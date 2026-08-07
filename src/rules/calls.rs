//! Rules about calls that leave the contract.

use syn::spanned::Spanned;
use syn::visit::Visit;

use super::{contract_impls, entrypoints, external_call, position, storage_write, Ctx, Rule};
use crate::finding::{Finding, Severity};

/// A cross contract call whose answer nobody looked at.
pub struct UncheckedCallResult;

impl Rule for UncheckedCallResult {
    fn id(&self) -> &'static str {
        "unchecked-call-result"
    }

    fn description(&self) -> &'static str {
        "a call to another contract whose return value is thrown away"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, file: &syn::File, ctx: &Ctx) -> Vec<Finding> {
        let mut findings = Vec::new();

        for item in contract_impls(file) {
            for function in entrypoints(item) {
                let mut seek = DroppedResults {
                    ctx,
                    findings: &mut findings,
                };
                seek.visit_block(&function.block);
            }
        }

        findings
    }
}

struct DroppedResults<'a, 'c> {
    ctx: &'a Ctx<'c>,
    findings: &'a mut Vec<Finding>,
}

impl Visit<'_> for DroppedResults<'_, '_> {
    fn visit_stmt(&mut self, stmt: &syn::Stmt) {
        // `token.transfer(..)?;` as a statement: the error is handled, the
        // answer is not. That is the shape that loses money, because plenty of
        // tokens report failure by returning false rather than by reverting.
        if let syn::Stmt::Expr(expr, Some(_semicolon)) = stmt {
            let inner = match expr {
                syn::Expr::Try(t) => &*t.expr,
                other => other,
            };
            if let Some(call) = external_call(inner, self.ctx.contract) {
                if call.returns == Some(true) {
                    let (line, column) = position(call.span);
                    self.findings.push(Finding::new(
                        "unchecked-call-result",
                        Severity::High,
                        self.ctx.file,
                        line,
                        column,
                        format!(
                            "the result of `{}` is discarded, and the interface says it returns one",
                            call.name
                        ),
                        "bind the result and act on it. A token that reports failure by returning \
                         false rather than reverting will otherwise look like it paid.",
                    ));
                }
            }
        }
        syn::visit::visit_stmt(self, stmt);
    }
}

/// Storage written after the contract has already called out.
pub struct StateWriteAfterCall;

impl Rule for StateWriteAfterCall {
    fn id(&self) -> &'static str {
        "state-write-after-call"
    }

    fn description(&self) -> &'static str {
        "storage changed after an external call, against checks effects interactions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn check(&self, file: &syn::File, ctx: &Ctx) -> Vec<Finding> {
        let mut findings = Vec::new();
        for item in contract_impls(file) {
            for function in entrypoints(item) {
                let mut seek = Ordering {
                    ctx,
                    findings: &mut findings,
                };
                seek.visit_block(&function.block);
            }
        }
        findings
    }
}

struct Ordering<'a, 'c> {
    ctx: &'a Ctx<'c>,
    findings: &'a mut Vec<Finding>,
}

impl Visit<'_> for Ordering<'_, '_> {
    fn visit_block(&mut self, block: &syn::Block) {
        let mut called_out = false;

        for stmt in &block.stmts {
            if !called_out {
                called_out = contains_reentrant_call(stmt, self.ctx);
                // A statement that both calls out and writes is reported by the
                // next statement that writes, not by itself: the write inside
                // it happens before the call returns.
                continue;
            }

            for write in writes_in(stmt, self.ctx) {
                // Releasing a hand rolled lock after the call is the correct
                // place for it, and is the one write that has to come last.
                if write.is_guard {
                    continue;
                }
                let (line, column) = position(write.span);
                self.findings.push(Finding::new(
                    "state-write-after-call",
                    Severity::High,
                    self.ctx.file,
                    line,
                    column,
                    format!(
                        "`{}` is written after this function has already called another contract",
                        write.field
                    ),
                    "move the write above the call. The storage cache is flushed for you, but the \
                     callee can still call back in and will see state that has not been updated yet.",
                ));
            }
        }

        syn::visit::visit_block(self, block);
    }
}

/// A storage write, reduced to what the rule needs so no borrow outlives the
/// visit that found it.
struct Write {
    field: String,
    is_guard: bool,
    span: proc_macro2::Span,
}

/// True when a statement makes a call that could come back into this contract.
///
/// A static call is deliberately not one. It cannot write state and cannot make
/// a state changing call, so nothing after it is out of order because of it, and
/// treating it as an interaction reports correct code. Reading a token balance
/// before deciding what to do is the ordinary shape of a payment and must stay
/// quiet.
fn contains_reentrant_call(stmt: &syn::Stmt, ctx: &Ctx) -> bool {
    struct Seek<'a, 'c> {
        ctx: &'a Ctx<'c>,
        found: bool,
    }
    impl Visit<'_> for Seek<'_, '_> {
        fn visit_expr(&mut self, expr: &syn::Expr) {
            if external_call(expr, self.ctx.contract).is_some_and(|call| call.reenters) {
                self.found = true;
            }
            syn::visit::visit_expr(self, expr);
        }
    }
    let mut seek = Seek { ctx, found: false };
    seek.visit_stmt(stmt);
    seek.found
}

fn writes_in(stmt: &syn::Stmt, ctx: &Ctx) -> Vec<Write> {
    struct Seek<'a, 'c> {
        ctx: &'a Ctx<'c>,
        writes: Vec<Write>,
    }
    impl Visit<'_> for Seek<'_, '_> {
        fn visit_expr(&mut self, expr: &syn::Expr) {
            if let Some(field) = storage_write(expr, self.ctx.contract) {
                self.writes.push(Write {
                    field: field.name.clone(),
                    is_guard: field.looks_like_a_guard(),
                    span: expr.span(),
                });
            }
            syn::visit::visit_expr(self, expr);
        }
    }
    let mut seek = Seek {
        ctx,
        writes: Vec::new(),
    };
    seek.visit_stmt(stmt);
    seek.writes
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

    const PRELUDE: &str = r#"
        sol_interface! {
            interface IErc20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function poke(address to) external;
            }
        }
        sol_storage! {
            #[entrypoint]
            pub struct A { address owner; uint256 available; bool entered; }
        }
    "#;

    #[test]
    fn flags_a_transfer_whose_answer_is_thrown_away() {
        let findings = run(
            &UncheckedCallResult,
            &format!(
                "{PRELUDE}
                #[public]
                impl A {{
                    pub fn pay(&mut self) -> Result<(), Vec<u8>> {{
                        token.transfer(&vm, ctx, to, amount)?;
                        Ok(())
                    }}
                }}"
            ),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "unchecked-call-result");
    }

    #[test]
    fn says_nothing_when_the_answer_is_used() {
        let findings = run(
            &UncheckedCallResult,
            &format!(
                "{PRELUDE}
                #[public]
                impl A {{
                    pub fn pay(&mut self) -> Result<(), Vec<u8>> {{
                        let moved = token.transfer(&vm, ctx, to, amount)?;
                        if !moved {{ return Err(b\"TRANSFER_FAILED\".to_vec()); }}
                        Ok(())
                    }}
                }}"
            ),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn says_nothing_when_there_was_no_answer_to_use() {
        let findings = run(
            &UncheckedCallResult,
            &format!(
                "{PRELUDE}
                #[public]
                impl A {{
                    pub fn nudge(&mut self) -> Result<(), Vec<u8>> {{
                        token.poke(&vm, ctx, to)?;
                        Ok(())
                    }}
                }}"
            ),
        );
        assert!(findings.is_empty(), "a void call has no result to discard");
    }

    #[test]
    fn flags_storage_written_after_the_contract_called_out() {
        let findings = run(
            &StateWriteAfterCall,
            &format!(
                "{PRELUDE}
                #[public]
                impl A {{
                    pub fn pay(&mut self) -> Result<(), Vec<u8>> {{
                        let moved = token.transfer(&vm, ctx, to, amount)?;
                        self.available.set(remaining);
                        Ok(())
                    }}
                }}"
            ),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("available"));
    }

    #[test]
    fn says_nothing_when_the_write_comes_first() {
        let findings = run(
            &StateWriteAfterCall,
            &format!(
                "{PRELUDE}
                #[public]
                impl A {{
                    pub fn pay(&mut self) -> Result<(), Vec<u8>> {{
                        self.available.set(remaining);
                        let moved = token.transfer(&vm, ctx, to, amount)?;
                        Ok(())
                    }}
                }}"
            ),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn releasing_a_lock_after_the_call_is_where_it_belongs() {
        let findings = run(
            &StateWriteAfterCall,
            &format!(
                "{PRELUDE}
                #[public]
                impl A {{
                    pub fn pay(&mut self) -> Result<(), Vec<u8>> {{
                        self.entered.set(true);
                        self.available.set(remaining);
                        let moved = token.transfer(&vm, ctx, to, amount)?;
                        self.entered.set(false);
                        Ok(())
                    }}
                }}"
            ),
        );
        assert!(
            findings.is_empty(),
            "a guard has to be released after the call, that is the whole point of it"
        );
    }
}

#[cfg(test)]
mod static_call_tests {
    use super::*;
    use crate::rules::{contract_of, parse};
    use std::path::Path;

    const PRELUDE: &str = r#"
        sol_interface! {
            interface IErc20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function balanceOf(address who) external view returns (uint256);
            }
        }
        sol_storage! {
            #[entrypoint]
            pub struct A { uint256 available; }
        }
    "#;

    fn findings(body: &str) -> Vec<Finding> {
        let source =
            format!("{PRELUDE}\n#[public]\nimpl A {{ pub fn go(&mut self) {{ {body} }} }}");
        let file = parse(&source);
        let contract = contract_of(&source);
        let ctx = Ctx {
            file: Path::new("contract.rs"),
            contract: &contract,
        };
        StateWriteAfterCall.check(&file, &ctx)
    }

    /// Found by running the checker over a real contract, which read a balance
    /// and then recorded what it was about to spend. That is correct code and
    /// the rule was calling it a reentrancy bug.
    #[test]
    fn reading_a_balance_before_writing_is_not_an_ordering_mistake() {
        let out = findings(
            "let balance = token.balance_of(self.vm(), Call::new(), this)?;
             self.available.set(remaining);",
        );
        assert!(
            out.is_empty(),
            "a staticcall cannot come back in, so nothing is out of order"
        );
    }

    #[test]
    fn a_mutating_call_still_puts_what_follows_out_of_order() {
        let out = findings(
            "let moved = token.transfer(&vm, Call::new_mutating(self), to, amount)?;
             self.available.set(remaining);",
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn how_the_call_is_spelled_beats_what_the_interface_said() {
        // The interface calls this one mutating, but the call site asked for a
        // static context, and the call site is what the chain acts on.
        let out = findings(
            "let ok = token.transfer(self.vm(), Call::new(), to, amount)?;
             self.available.set(remaining);",
        );
        assert!(out.is_empty());
    }
}
