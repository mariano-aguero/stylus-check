//! Rules about who may act, and about work that grows without a bound.

use syn::spanned::Spanned;
use syn::visit::Visit;

use super::{
    entrypoints, mutates_self, position, public_impls, storage_write, touched_fields, Ctx, Rule,
};
use crate::finding::{Finding, Severity};

/// A function that changes storage without asking who is calling.
///
/// This rule stays silent unless the contract itself shows it has a notion of
/// authority. A contract with no owner and no roles is either deliberately open
/// or is a different kind of mistake, and flagging every setter in it would be
/// noise rather than a finding.
pub struct MissingAccessControl;

impl Rule for MissingAccessControl {
    fn id(&self) -> &'static str {
        "missing-access-control"
    }

    fn description(&self) -> &'static str {
        "a public function changes storage without checking who called it"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, file: &syn::File, ctx: &Ctx) -> Vec<Finding> {
        if !ctx.contract.has_an_authority() {
            return Vec::new();
        }

        let authorities: Vec<String> = ctx
            .contract
            .storage
            .values()
            .filter(|f| f.looks_like_an_authority())
            .map(|f| f.name.clone())
            .collect();

        let mut findings = Vec::new();
        for item in public_impls(file) {
            for function in entrypoints(item) {
                if !mutates_self(function) {
                    continue;
                }
                let body = Body::of(&function.block, ctx);
                if body.writes.is_empty() {
                    continue;
                }
                if body.checks_authority(&authorities) {
                    continue;
                }

                let (line, column) = position(function.sig.ident.span());
                let name = function.sig.ident.to_string();
                findings.push(Finding::new(
                    "missing-access-control",
                    Severity::Medium,
                    ctx.file,
                    line,
                    column,
                    format!(
                        "`{name}` writes {} but never reads {}",
                        list(&body.writes),
                        list(&authorities)
                    ),
                    "anyone can call this. Compare the caller against the authority the contract \
                     already declares, or say in a comment that it is meant to be open.",
                ));
            }
        }
        findings
    }
}

/// What a function body does, as far as this rule needs to know.
struct Body {
    writes: Vec<String>,
    reads: Vec<String>,
    /// Calls to things named like a check, e.g. `only_owner()`.
    guards: bool,
    /// Any comparison against the caller, which is a check written inline.
    inspects_sender: bool,
}

impl Body {
    fn of(block: &syn::Block, ctx: &Ctx) -> Self {
        struct Seek<'a, 'c> {
            ctx: &'a Ctx<'c>,
            body: Body,
        }
        impl Visit<'_> for Seek<'_, '_> {
            fn visit_expr(&mut self, expr: &syn::Expr) {
                if let Some(field) = storage_write(expr, self.ctx.contract) {
                    if !self.body.writes.contains(&field.name) {
                        self.body.writes.push(field.name.clone());
                    }
                }
                for name in touched_fields(expr) {
                    if !self.body.reads.contains(&name) {
                        self.body.reads.push(name);
                    }
                }
                syn::visit::visit_expr(self, expr);
            }

            fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
                let name = call.method.to_string();
                if name == "msg_sender" || name == "sender" {
                    self.body.inspects_sender = true;
                }
                if is_guard_name(&name) {
                    self.body.guards = true;
                }
                syn::visit::visit_expr_method_call(self, call);
            }

            fn visit_expr_call(&mut self, call: &syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    if let Some(last) = path.path.segments.last() {
                        if is_guard_name(&last.ident.to_string()) {
                            self.body.guards = true;
                        }
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }
        }

        let mut seek = Seek {
            ctx,
            body: Body {
                writes: Vec::new(),
                reads: Vec::new(),
                guards: false,
                inspects_sender: false,
            },
        };
        seek.visit_block(block);
        seek.body
    }

    /// True when the function does something that could decide who may call it.
    ///
    /// Reading the authority field counts even without a visible comparison: a
    /// function that loads the owner is doing so for a reason, and guessing that
    /// the reason is wrong would report correct code.
    fn checks_authority(&self, authorities: &[String]) -> bool {
        self.guards || self.inspects_sender || authorities.iter().any(|a| self.reads.contains(a))
    }
}

fn is_guard_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("only_")
        || lower.starts_with("require_")
        || lower.starts_with("assert_")
        || lower.starts_with("ensure_")
        || lower.contains("authorize")
        || lower.contains("authorise")
}

fn list(names: &[String]) -> String {
    match names {
        [] => "nothing".to_string(),
        [one] => format!("`{one}`"),
        [first, rest @ ..] => {
            let mut out = format!("`{first}`");
            for name in rest {
                out.push_str(&format!(", `{name}`"));
            }
            out
        }
    }
}

/// A loop whose length is decided by a collection callers can grow.
pub struct UnboundedStorageLoop;

impl Rule for UnboundedStorageLoop {
    fn id(&self) -> &'static str {
        "unbounded-storage-loop"
    }

    fn description(&self) -> &'static str {
        "a loop over storage that callers can make long enough to run out of gas"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn check(&self, file: &syn::File, ctx: &Ctx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for item in public_impls(file) {
            for function in entrypoints(item) {
                let mut seek = Loops {
                    ctx,
                    findings: &mut findings,
                };
                seek.visit_block(&function.block);
            }
        }
        findings
    }
}

struct Loops<'a, 'c> {
    ctx: &'a Ctx<'c>,
    findings: &'a mut Vec<Finding>,
}

impl Visit<'_> for Loops<'_, '_> {
    fn visit_expr_for_loop(&mut self, loop_expr: &syn::ExprForLoop) {
        let dynamic: Vec<String> = touched_fields(&loop_expr.expr)
            .into_iter()
            .filter(|name| {
                self.ctx
                    .contract
                    .field(name)
                    .is_some_and(crate::model::StorageField::is_dynamic)
            })
            .collect();

        if let Some(field) = dynamic.first() {
            let (line, column) = position(loop_expr.span());
            self.findings.push(Finding::new(
                "unbounded-storage-loop",
                Severity::Medium,
                self.ctx.file,
                line,
                column,
                format!("this loop is as long as `{field}`, which callers can grow"),
                "once it is long enough the call runs out of gas, and whatever it protects is stuck \
                 for everyone. Page through it, or let each caller settle their own entry.",
            ));
        }

        syn::visit::visit_expr_for_loop(self, loop_expr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{contract_of, parse};
    use std::path::Path;

    fn run(rule: &dyn Rule, source: &str) -> Vec<Finding> {
        let file = parse(source);
        let contract = contract_of(source);
        let ctx = Ctx {
            file: Path::new("contract.rs"),
            contract: &contract,
        };
        rule.check(&file, &ctx)
    }

    const OWNED: &str = r#"
        sol_storage! {
            #[entrypoint]
            pub struct A { address owner; uint256 budget; mapping(address => bool) allowed; }
        }
    "#;

    const OPEN: &str = r#"
        sol_storage! {
            #[entrypoint]
            pub struct A { uint256 counter; }
        }
    "#;

    #[test]
    fn flags_a_setter_anyone_can_call() {
        let findings = run(
            &MissingAccessControl,
            &format!(
                "{OWNED}
                 #[public]
                 impl A {{ pub fn set_budget(&mut self, v: U256) {{ self.budget.set(v); }} }}"
            ),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("set_budget"));
    }

    #[test]
    fn says_nothing_when_the_function_consults_the_owner() {
        let findings = run(
            &MissingAccessControl,
            &format!(
                "{OWNED}
                 #[public]
                 impl A {{
                     pub fn set_budget(&mut self, v: U256) -> Result<(), Vec<u8>> {{
                         if self.vm().msg_sender() != self.owner.get() {{ return Err(vec![]); }}
                         self.budget.set(v);
                         Ok(())
                     }}
                 }}"
            ),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn says_nothing_when_a_named_guard_does_the_checking() {
        let findings = run(
            &MissingAccessControl,
            &format!(
                "{OWNED}
                 #[public]
                 impl A {{
                     pub fn set_budget(&mut self, v: U256) -> Result<(), Vec<u8>> {{
                         self.only_owner()?;
                         self.budget.set(v);
                         Ok(())
                     }}
                 }}"
            ),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn stays_quiet_on_a_contract_with_no_notion_of_authority() {
        let findings = run(
            &MissingAccessControl,
            &format!(
                "{OPEN}
                 #[public]
                 impl A {{ pub fn bump(&mut self) {{ self.counter.set(v); }} }}"
            ),
        );
        assert!(
            findings.is_empty(),
            "nothing here says anyone is privileged, so there is no rule to break"
        );
    }

    #[test]
    fn a_reader_is_not_a_writer() {
        let findings = run(
            &MissingAccessControl,
            &format!(
                "{OWNED}
                 #[public]
                 impl A {{ pub fn budget(&self) -> U256 {{ self.budget.get() }} }}"
            ),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_a_loop_over_something_callers_can_grow() {
        let findings = run(
            &UnboundedStorageLoop,
            &format!(
                "{OWNED}
                 #[public]
                 impl A {{
                     pub fn sweep(&mut self) {{ for who in self.allowed.iter() {{ pay(who); }} }}
                 }}"
            ),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("allowed"));
    }

    #[test]
    fn says_nothing_about_a_loop_with_a_fixed_bound() {
        let findings = run(
            &UnboundedStorageLoop,
            &format!(
                "{OWNED}
                 #[public]
                 impl A {{ pub fn sweep(&mut self) {{ for i in 0..8 {{ step(i); }} }} }}"
            ),
        );
        assert!(findings.is_empty());
    }
}
