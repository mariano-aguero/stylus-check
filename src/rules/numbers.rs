//! Rules about numbers that quietly stop being the number you meant.

use syn::spanned::Spanned;
use syn::visit::Visit;

use super::{contract_impls, functions_in, position, Ctx, Rule};
use crate::finding::{Finding, Severity};
use crate::model::Contract;

/// A conversion from a wide storage value into a narrow one.
///
/// This is the rule that most needs to know types, and the one that shows why
/// reading `sol_storage!` was worth it. `self.last_refill.get().to::<u64>()` is
/// exact when the field is a `uint64` and lossy when it is a `uint256`, and the
/// only difference is a declaration the contract already made.
pub struct LossyIntegerConversion;

impl Rule for LossyIntegerConversion {
    fn id(&self) -> &'static str {
        "lossy-integer-conversion"
    }

    fn description(&self) -> &'static str {
        "a storage value narrowed into a type too small to hold it"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, file: &syn::File, ctx: &Ctx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for item in contract_impls(file) {
            for function in functions_in(item) {
                let mut seek = Narrowing {
                    ctx,
                    findings: &mut findings,
                };
                seek.visit_block(&function.block);
            }
        }
        findings
    }
}

struct Narrowing<'a, 'c> {
    ctx: &'a Ctx<'c>,
    findings: &'a mut Vec<Finding>,
}

impl Visit<'_> for Narrowing<'_, '_> {
    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        let method = call.method.to_string();
        let silent = match method.as_str() {
            // alloy's `to` panics when the value does not fit, which on Stylus
            // is a trap rather than a revert.
            "to" => false,
            // `wrapping_to` truncates and says nothing, which is worse: the
            // contract carries on with a number that is not the one it read.
            "wrapping_to" => true,
            _ => {
                syn::visit::visit_expr_method_call(self, call);
                return;
            }
        };

        if let (Some(target), Some(source)) = (
            turbofish_bits(&call.turbofish),
            read_field_bits(&call.receiver, self.ctx.contract),
        ) {
            if source.1 > target {
                let (line, column) = position(call.span());
                let (field, bits) = source;
                self.findings.push(Finding::new(
                    "lossy-integer-conversion",
                    if silent { Severity::High } else { Severity::Medium },
                    self.ctx.file,
                    line,
                    column,
                    format!(
                        "`{field}` is declared uint{bits} and is being narrowed to u{target} by `{method}`"
                    ),
                    if silent {
                        "the extra bits are dropped without a word, so the contract carries on with \
                         a different number. Keep the value wide, or refuse the operation when it \
                         does not fit."
                    } else {
                        "this panics when the value does not fit, and on Stylus a panic is a trap \
                         rather than a revert. Check the range and return an Err instead."
                    },
                ));
            }
        }

        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_cast(&mut self, cast: &syn::ExprCast) {
        if let (Some(target), Some((field, bits))) = (
            type_bits(&cast.ty),
            read_field_bits(&cast.expr, self.ctx.contract),
        ) {
            if bits > target {
                let (line, column) = position(cast.span());
                self.findings.push(Finding::new(
                    "lossy-integer-conversion",
                    Severity::High,
                    self.ctx.file,
                    line,
                    column,
                    format!("`{field}` is declared uint{bits} and is being cast to u{target}"),
                    "an `as` cast keeps the low bits and discards the rest without a word. Keep the \
                     value wide, or refuse the operation when it does not fit.",
                ));
            }
        }
        syn::visit::visit_expr_cast(self, cast);
    }
}

/// The width named in a `::<u64>()` turbofish.
fn turbofish_bits(turbofish: &Option<syn::AngleBracketedGenericArguments>) -> Option<u32> {
    let args = turbofish.as_ref()?;
    args.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => type_bits(ty),
        _ => None,
    })
}

/// The width of a primitive integer type, `u64` giving 64.
fn type_bits(ty: &syn::Type) -> Option<u32> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let name = path.path.segments.last()?.ident.to_string();
    let digits = name.strip_prefix('u').or_else(|| name.strip_prefix('i'))?;
    match digits {
        "size" => None, // platform dependent, and never what a contract means
        _ => digits.parse().ok(),
    }
}

/// If an expression reads a declared storage field, its name and declared width.
///
/// Only a direct read counts. Once a value has been through arithmetic the
/// declaration no longer bounds it, and reporting on it would be a guess.
fn read_field_bits(expr: &syn::Expr, contract: &Contract) -> Option<(String, u32)> {
    let syn::Expr::MethodCall(call) = expr else {
        return None;
    };
    if call.method != "get" {
        return None;
    }
    let syn::Expr::Field(field) = &*call.receiver else {
        return None;
    };
    if !matches!(&*field.base, syn::Expr::Path(p) if p.path.is_ident("self")) {
        return None;
    }
    let syn::Member::Named(name) = &field.member else {
        return None;
    };
    let declared = contract.field(&name.to_string())?;
    Some((declared.name.clone(), declared.int_bits()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{contract_of, parse};
    use std::path::Path;

    const PRELUDE: &str = r#"
        sol_storage! {
            #[entrypoint]
            pub struct A { uint256 budget; uint64 last_refill; address owner; }
        }
    "#;

    fn run(body: &str) -> Vec<Finding> {
        let source =
            format!("{PRELUDE}\n#[public]\nimpl A {{ pub fn go(&mut self) {{ {body} }} }}");
        let file = parse(&source);
        let contract = contract_of(&source);
        let ctx = Ctx {
            file: Path::new("contract.rs"),
            contract: &contract,
        };
        LossyIntegerConversion.check(&file, &ctx)
    }

    #[test]
    fn flags_a_wide_field_squeezed_into_a_narrow_type() {
        let findings = run("let n = self.budget.get().to::<u64>();");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("budget"));
        assert!(findings[0].message.contains("uint256"));
    }

    #[test]
    fn says_nothing_when_the_declaration_says_it_fits() {
        let findings = run("let n = self.last_refill.get().to::<u64>();");
        assert!(
            findings.is_empty(),
            "a uint64 field into a u64 loses nothing, and complaining here is how a checker gets uninstalled"
        );
    }

    #[test]
    fn a_silent_truncation_outranks_one_that_panics() {
        let loud = run("let n = self.budget.get().to::<u64>();");
        let quiet = run("let n = self.budget.get().wrapping_to::<u64>();");
        assert_eq!(loud[0].severity, Severity::Medium);
        assert_eq!(quiet[0].severity, Severity::High);
    }

    #[test]
    fn flags_a_plain_cast_of_a_wide_field() {
        let findings = run("let n = self.budget.get() as u32;");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn says_nothing_about_a_value_it_cannot_bound() {
        let findings = run("let n = some_local.to::<u64>();");
        assert!(
            findings.is_empty(),
            "nothing declared its width, so there is nothing to claim"
        );
    }

    #[test]
    fn says_nothing_about_arithmetic_it_can_no_longer_bound() {
        let findings = run("let n = (self.budget.get() * factor).to::<u64>();");
        assert!(
            findings.is_empty(),
            "past the multiply the declaration no longer bounds it"
        );
    }
}
