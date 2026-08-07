//! Rules about ways a contract stops dead instead of reverting.

use syn::spanned::Spanned;
use syn::visit::Visit;

use super::{contract_impls, entrypoints, position, Ctx, Rule};
use crate::finding::{Finding, Severity};

/// A panic reachable from a caller.
///
/// On Stylus a panic is a WASM trap. It does not revert with a reason the
/// caller can read, and it consumes the gas the caller sent. The same code in
/// a test is fine, which is why test items are never looked at.
pub struct UnwrapInEntrypoint;

impl Rule for UnwrapInEntrypoint {
    fn id(&self) -> &'static str {
        "unwrap-in-entrypoint"
    }

    fn description(&self) -> &'static str {
        "a panic reachable from a caller, which traps instead of reverting"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, file: &syn::File, ctx: &Ctx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for item in contract_impls(file) {
            for function in entrypoints(item) {
                let mut seek = Panics {
                    ctx,
                    findings: &mut findings,
                    function: function.sig.ident.to_string(),
                    parameters: parameter_names(function),
                };
                seek.visit_block(&function.block);
            }
        }
        findings
    }
}

/// Whether the operation being unwrapped is one a caller can actually make fail.
///
/// A lookup fails when the key is not there, arithmetic fails when it overflows,
/// and a call fails when the callee reverts. All three are decided at run time
/// by whoever called. A conversion between types the contract already fixed,
/// like four bytes into `[u8; 4]`, either always works or never does, and
/// reporting it buries the three that matter.
fn can_actually_fail(expr: &syn::Expr, contract: &crate::model::Contract) -> bool {
    if crate::rules::external_call(expr, contract).is_some() {
        return true;
    }
    let syn::Expr::MethodCall(call) = expr else {
        return false;
    };
    let name = call.method.to_string();
    matches!(
        name.as_str(),
        "get" | "getter" | "setter" | "get_mut" | "pop"
    ) || name.starts_with("checked_")
}

/// The names a caller supplies, which is what makes a panic reachable.
fn parameter_names(function: &syn::ImplItemFn) -> Vec<String> {
    function
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(typed) => match &*typed.pat {
                syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

struct Panics<'a, 'c> {
    ctx: &'a Ctx<'c>,
    findings: &'a mut Vec<Finding>,
    function: String,
    parameters: Vec<String>,
}

impl Panics<'_, '_> {
    /// Whether anything a caller controls feeds this expression.
    ///
    /// `I256::try_from(20003000).unwrap()` cannot fail: the input is written in
    /// the source and either always fits or never does, and it would be caught
    /// the first time anyone ran it. `self.arr.get(index).unwrap()` is a
    /// different thing entirely, because the index arrives from outside.
    /// Reporting both is how a checker teaches people to stop reading it.
    fn caller_can_reach(&self, expr: &syn::Expr) -> bool {
        struct Seek<'a> {
            parameters: &'a [String],
            found: bool,
        }
        impl Visit<'_> for Seek<'_> {
            fn visit_expr_field(&mut self, field: &syn::ExprField) {
                if matches!(&*field.base, syn::Expr::Path(p) if p.path.is_ident("self")) {
                    self.found = true;
                }
                syn::visit::visit_expr_field(self, field);
            }
            fn visit_ident(&mut self, ident: &proc_macro2::Ident) {
                if self.parameters.iter().any(|p| ident == p.as_str()) {
                    self.found = true;
                }
            }
        }
        let mut seek = Seek {
            parameters: &self.parameters,
            found: false,
        };
        seek.visit_expr(expr);
        seek.found
    }
}

impl Panics<'_, '_> {
    fn report(&mut self, what: &str, span: proc_macro2::Span) {
        let (line, column) = position(span);
        self.findings.push(Finding::new(
            "unwrap-in-entrypoint",
            Severity::High,
            self.ctx.file,
            line,
            column,
            format!("`{what}` in `{}`", self.function),
            "return an Err with a reason instead. A panic becomes a WASM trap: the caller gets no \
             reason back and loses the gas it sent.",
        ));
    }
}

impl Visit<'_> for Panics<'_, '_> {
    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        let name = call.method.to_string();
        if (name == "unwrap" || name == "expect")
            && can_actually_fail(&call.receiver, self.ctx.contract)
            && self.caller_can_reach(&call.receiver)
        {
            self.report(&format!("{name}()"), call.span());
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &syn::Macro) {
        if let Some(name) = mac.path.segments.last().map(|s| s.ident.to_string()) {
            if matches!(
                name.as_str(),
                "panic" | "unreachable" | "todo" | "unimplemented"
            ) {
                self.report(&format!("{name}!"), mac.span());
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{contract_of, parse};
    use std::path::Path;

    fn run(source: &str) -> Vec<Finding> {
        let file = parse(source);
        let contract = contract_of(source);
        let ctx = Ctx {
            file: Path::new("contract.rs"),
            contract: &contract,
        };
        UnwrapInEntrypoint.check(&file, &ctx)
    }

    #[test]
    fn flags_an_unwrap_a_caller_can_reach() {
        let findings = run("#[public]
             impl A { pub fn go(&mut self, key: U256) { let x = self.book.get(key).unwrap(); } }");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("unwrap()"));
        assert!(findings[0].message.contains("go"));
    }

    #[test]
    fn flags_the_panicking_macros_too() {
        let findings = run("#[public]
             impl A { pub fn go(&mut self) { if bad { panic!(\"no\"); } todo!() } }");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn says_nothing_about_test_code() {
        let findings = run("#[cfg(test)]
             mod tests {
                #[public]
                impl A { pub fn go(&mut self, k: U256) { self.book.get(k).unwrap(); } }
             }");
        assert!(findings.is_empty(), "tests panic on purpose");
    }

    #[test]
    fn a_private_helper_traps_just_the_same() {
        // This test used to assert the opposite. Running the checker over a real
        // contract settled it: the part that moves money lives in a private
        // helper called from an entrypoint, and a panic there traps exactly as
        // hard as one written in the public function.
        let findings =
            run("impl A { fn helper(&self, key: U256) { self.book.get(key).unwrap(); } }");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("helper"));
    }

    #[test]
    fn flags_the_panic_wherever_the_contract_wrote_it() {
        let findings = run(
            "#[public]
             impl A { pub fn go(&mut self) -> Result<(), Vec<u8>> { self.settle() } }
             impl A { fn settle(&mut self) -> Result<(), Vec<u8>> { self.book.get(k).expect(\"no\"); Ok(()) } }",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("settle"));
    }
}

#[cfg(test)]
mod reachability_tests {
    use super::*;
    use crate::rules::{contract_of, parse};
    use std::path::Path;

    fn run(source: &str) -> Vec<Finding> {
        let file = parse(source);
        let contract = contract_of(source);
        let ctx = Ctx {
            file: Path::new("contract.rs"),
            contract: &contract,
        };
        UnwrapInEntrypoint.check(&file, &ctx)
    }

    /// Straight out of the SDK's own arrays example, and a real bug: an index
    /// past the end traps instead of reverting.
    #[test]
    fn flags_an_unwrap_on_something_the_caller_supplied() {
        let findings = run(
            "#[public]
             impl A { pub fn get_element(&self, index: U256) -> U256 { self.arr.get(index).unwrap() } }",
        );
        assert_eq!(findings.len(), 1);
    }

    /// Also from the SDK examples, and not a bug: the input is a literal, so it
    /// either always fits or fails the first time anybody runs it.
    #[test]
    fn says_nothing_about_an_unwrap_no_caller_can_influence() {
        let findings = run("#[public]
             impl A { pub fn demo(&self) { let a = I256::try_from(20003000).unwrap(); } }");
        assert!(findings.is_empty());
    }

    #[test]
    fn a_constant_parsed_at_startup_is_not_a_caller_problem() {
        let findings = run(
            "#[public]
             impl A { pub fn demo(&self) { let o = Address::parse_checksummed(OWNER, None).expect(\"bad\"); } }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn an_unconditional_panic_is_reported_whatever_feeds_it() {
        let findings = run("#[public]\n impl A { pub fn go(&mut self) { todo!() } }");
        assert_eq!(findings.len(), 1, "this one traps every single time");
    }
}

#[cfg(test)]
mod fallibility_tests {
    use super::*;
    use crate::rules::{contract_of, parse};
    use std::path::Path;

    fn run(source: &str) -> Vec<Finding> {
        let file = parse(source);
        let contract = contract_of(source);
        let ctx = Ctx {
            file: Path::new("contract.rs"),
            contract: &contract,
        };
        UnwrapInEntrypoint.check(&file, &ctx)
    }

    /// From the SDK's erc721 example. Four bytes always fit in four bytes, and
    /// saying otherwise buries the lookups that really can fail.
    #[test]
    fn a_conversion_between_fixed_sizes_is_not_a_risk() {
        let findings = run("#[public]
             impl A {
                pub fn supports(&self, interface: FixedBytes<4>) -> bool {
                    let a: [u8; 4] = interface.as_slice().try_into().unwrap();
                    true
                }
             }");
        assert!(findings.is_empty());
    }

    #[test]
    fn arithmetic_that_can_overflow_still_counts() {
        let findings = run(
            "#[public]
             impl A { pub fn take(&mut self, amount: U256) { let left = self.total.get().checked_sub(amount).unwrap(); } }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_lookup_with_a_key_from_outside_still_counts() {
        let findings = run("#[public]
             impl A { pub fn at(&self, index: U256) -> U256 { self.arr.get(index).unwrap() } }");
        assert_eq!(findings.len(), 1);
    }
}
