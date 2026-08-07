//! The rules, and the small amount of shared reading they all depend on.
//!
//! Every rule here is a syntactic pattern. None of them knows a type that the
//! contract did not declare, so each is written to stay silent when it cannot
//! tell rather than to guess. A checker that cries wolf gets uninstalled, and
//! then it catches nothing at all.

use std::path::Path;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::finding::{Finding, Severity};
use crate::model::Contract;

pub mod access;
pub mod calls;
pub mod numbers;
pub mod traps;

/// What a rule is given to work with.
pub struct Ctx<'a> {
    pub file: &'a Path,
    pub contract: &'a Contract,
}

/// A rule reads a parsed file and says what it noticed.
pub trait Rule {
    /// Stable identifier used by config files and by the SARIF output.
    fn id(&self) -> &'static str;
    /// What the rule is for, one line, shown by `--explain`.
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn check(&self, file: &syn::File, ctx: &Ctx) -> Vec<Finding>;
}

/// Every rule, in the order their findings tend to matter.
#[must_use]
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(traps::UnwrapInEntrypoint),
        Box::new(calls::UncheckedCallResult),
        Box::new(calls::StateWriteAfterCall),
        Box::new(numbers::LossyIntegerConversion),
        Box::new(access::MissingAccessControl),
        Box::new(access::UnboundedStorageLoop),
    ]
}

/// One based line and column, so a finding matches what an editor shows.
#[must_use]
pub fn position(span: Span) -> (usize, usize) {
    let start = span.start();
    (start.line, start.column + 1)
}

/// The `#[public]` impl blocks, which is where callers get in.
///
/// Use this only for rules that are about the public surface itself, such as
/// who is allowed to call something. For anything about what the code does,
/// use [`contract_impls`]: real contracts keep the part that moves money in a
/// private helper, and a rule that only reads the public block will sit there
/// looking like it ran.
#[must_use]
pub fn public_impls(file: &syn::File) -> Vec<&syn::ItemImpl> {
    collect_impls(file, true)
}

/// Every impl block in the contract, public or not, minus test code.
///
/// A panic in a private helper still traps, and a write after a call is still
/// out of order no matter which function it is written in.
#[must_use]
pub fn contract_impls(file: &syn::File) -> Vec<&syn::ItemImpl> {
    collect_impls(file, false)
}

fn collect_impls(file: &syn::File, only_public: bool) -> Vec<&syn::ItemImpl> {
    let mut collector = Impls {
        found: Vec::new(),
        only_public,
    };
    collector.visit_file(file);
    collector.found
}

struct Impls<'ast> {
    found: Vec<&'ast syn::ItemImpl>,
    only_public: bool,
}

impl<'ast> Visit<'ast> for Impls<'ast> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        // Test code traps and panics on purpose, and reporting it is the
        // fastest way to teach somebody to ignore the whole tool.
        if is_test_only(&module.attrs) || module.ident == "tests" {
            return;
        }
        syn::visit::visit_item_mod(self, module);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if is_test_only(&item.attrs) {
            return;
        }
        if !self.only_public || has_attribute(&item.attrs, "public") {
            self.found.push(item);
        }
        syn::visit::visit_item_impl(self, item);
    }
}

/// The functions a `#[public]` impl exposes.
#[must_use]
pub fn entrypoints(item: &syn::ItemImpl) -> Vec<&syn::ImplItemFn> {
    item.items
        .iter()
        .filter_map(|member| match member {
            syn::ImplItem::Fn(f) if !is_test_only(&f.attrs) => Some(f),
            _ => None,
        })
        .collect()
}

/// True when a function takes `&mut self`, and so can change storage.
#[must_use]
pub fn mutates_self(function: &syn::ImplItemFn) -> bool {
    matches!(
        function.sig.inputs.first(),
        Some(syn::FnArg::Receiver(syn::Receiver {
            mutability: Some(_),
            reference: Some(_),
            ..
        }))
    )
}

#[must_use]
pub fn has_attribute(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs
        .iter()
        .any(|a| a.path().segments.last().is_some_and(|s| s.ident == name))
}

#[must_use]
pub fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        let path = a.path();
        if path.segments.last().is_some_and(|s| s.ident == "test") {
            return true;
        }
        if path.segments.last().is_none_or(|s| s.ident != "cfg") {
            return false;
        }
        a.meta
            .require_list()
            .map(|list| list.tokens.to_string().contains("test"))
            .unwrap_or(false)
    })
}

/// A call that leaves this contract.
pub struct ExternalCall {
    pub span: Span,
    /// The method as written, for the message.
    pub name: String,
    /// Whether the callee hands anything back, when the interface said so.
    pub returns: Option<bool>,
    /// Whether this call can come back into us before it returns.
    ///
    /// A static call cannot: it may not write state and may not make a
    /// state changing call, so nothing it does can reenter. Ordering rules only
    /// have something to say about calls that can.
    pub reenters: bool,
}

/// Recognises a call to another contract.
///
/// Two signals, either of which is conclusive in stylus-sdk code: the method is
/// one a `sol_interface!` declared, or the call carries a `Call` context, which
/// is how the SDK spells "this leaves the contract". Raw calls are named
/// outright.
#[must_use]
pub fn external_call(expr: &syn::Expr, contract: &Contract) -> Option<ExternalCall> {
    match expr {
        syn::Expr::MethodCall(call) => {
            let context = call.args.iter().find_map(call_context);
            let name = call.method.to_string();
            if let Some(method) = contract.external_method(&name) {
                // How the call was spelled at the call site wins over what the
                // interface said, because that is what actually decides.
                let reenters = context.unwrap_or(method.mutates);
                return Some(ExternalCall {
                    span: call.span(),
                    name,
                    returns: Some(method.returns),
                    reenters,
                });
            }
            if let Some(reenters) = context {
                return Some(ExternalCall {
                    span: call.span(),
                    name,
                    returns: None,
                    reenters,
                });
            }
            None
        }
        syn::Expr::Call(call) => {
            let name = path_tail(&call.func)?;
            let reenters = match name.as_str() {
                "static_call" => false,
                "call" | "delegate_call" | "transfer_eth" | "raw_call" => true,
                _ => return None,
            };
            Some(ExternalCall {
                span: call.span(),
                name,
                returns: None,
                reenters,
            })
        }
        _ => None,
    }
}

/// Reads a `Call::new()` style context, saying whether it can reenter.
///
/// `Call::new()` is a static call and `Call::new_mutating(self)` is not, which
/// is the SDK spelling out at the call site whether the callee is allowed to
/// come back in.
fn call_context(expr: &syn::Expr) -> Option<bool> {
    struct Seek {
        mutating: Option<bool>,
    }
    impl Visit<'_> for Seek {
        fn visit_path(&mut self, path: &syn::Path) {
            let is_call_type = path
                .segments
                .first()
                .is_some_and(|s| s.ident == "Call" || s.ident == "RawCall");
            if is_call_type {
                let constructor = path.segments.last().map(|s| s.ident.to_string());
                let mutating = constructor
                    .as_deref()
                    .is_some_and(|c| c.contains("mutating"));
                // Any mutating context in the expression settles it.
                self.mutating = Some(self.mutating.unwrap_or(false) || mutating);
            }
            syn::visit::visit_path(self, path);
        }
    }
    let mut seek = Seek { mutating: None };
    seek.visit_expr(expr);
    seek.mutating
}

fn path_tail(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// The storage field an expression writes to, if it writes to one.
///
/// Covers the whole family the SDK offers: `set`, `setter(..).set(..)`, `push`,
/// `insert`, `erase`. The field name comes from the innermost `self.<field>`,
/// so a chain through a mapping still reports the mapping.
#[must_use]
pub fn storage_write<'a>(
    expr: &syn::Expr,
    contract: &'a Contract,
) -> Option<&'a crate::model::StorageField> {
    let syn::Expr::MethodCall(call) = expr else {
        return None;
    };
    let method = call.method.to_string();
    if !matches!(
        method.as_str(),
        "set" | "push" | "insert" | "erase" | "clear" | "set_word" | "replace" | "grow" | "shrink"
    ) {
        return None;
    }
    let field = self_field(&call.receiver)?;
    contract.field(&field)
}

/// Walks back through a method chain to the `self.<field>` it started from.
fn self_field(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Field(field) => {
            if !matches!(&*field.base, syn::Expr::Path(p) if p.path.is_ident("self")) {
                return None;
            }
            match &field.member {
                syn::Member::Named(name) => Some(name.to_string()),
                syn::Member::Unnamed(_) => None,
            }
        }
        syn::Expr::MethodCall(call) => self_field(&call.receiver),
        syn::Expr::Index(index) => self_field(&index.expr),
        _ => None,
    }
}

/// Every `self.<field>` an expression reads or writes.
#[must_use]
pub fn touched_fields(expr: &syn::Expr) -> Vec<String> {
    struct Seek {
        names: Vec<String>,
    }
    impl Visit<'_> for Seek {
        fn visit_expr_field(&mut self, field: &syn::ExprField) {
            if matches!(&*field.base, syn::Expr::Path(p) if p.path.is_ident("self")) {
                if let syn::Member::Named(name) = &field.member {
                    self.names.push(name.to_string());
                }
            }
            syn::visit::visit_expr_field(self, field);
        }
    }
    let mut seek = Seek { names: Vec::new() };
    seek.visit_expr(expr);
    seek.names
}

#[cfg(test)]
pub(crate) fn parse(source: &str) -> syn::File {
    syn::parse_file(source).expect("test fixture should parse")
}

#[cfg(test)]
pub(crate) fn contract_of(source: &str) -> Contract {
    let file = parse(source);
    let mut contract = Contract::default();
    contract.absorb(&file);
    contract
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"
        sol_interface! {
            interface IErc20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function ping(address to) external;
            }
        }
        sol_storage! {
            #[entrypoint]
            pub struct A { address owner; uint256 budget; bool entered; }
        }
        #[public]
        impl A {
            pub fn go(&mut self) {}
            pub fn look(&self) {}
        }
        #[cfg(test)]
        mod tests {
            #[public]
            impl B { pub fn hidden(&mut self) {} }
        }
    "#;

    #[test]
    fn finds_the_public_surface_and_ignores_tests() {
        let file = parse(SOURCE);
        let impls = public_impls(&file);
        assert_eq!(
            impls.len(),
            1,
            "the impl behind cfg(test) is not the contract"
        );
        let names: Vec<_> = entrypoints(impls[0])
            .iter()
            .map(|f| f.sig.ident.to_string())
            .collect();
        assert_eq!(names, vec!["go", "look"]);
    }

    #[test]
    fn knows_which_entrypoints_can_change_storage() {
        let file = parse(SOURCE);
        let impls = public_impls(&file);
        let fns = entrypoints(impls[0]);
        assert!(mutates_self(fns[0]));
        assert!(!mutates_self(fns[1]));
    }

    #[test]
    fn recognises_a_call_that_leaves_the_contract() {
        let contract = contract_of(SOURCE);
        let declared: syn::Expr = syn::parse_quote!(token.transfer(&vm, ctx, to, amount));
        let contextual: syn::Expr =
            syn::parse_quote!(other.whatever(self.vm(), Call::new_mutating(self), x));
        let raw: syn::Expr = syn::parse_quote!(static_call(vm, ctx, addr, data));
        let local: syn::Expr = syn::parse_quote!(self.settle(recipient, amount));

        assert!(external_call(&declared, &contract).is_some());
        assert!(external_call(&contextual, &contract).is_some());
        assert!(external_call(&raw, &contract).is_some());
        assert!(
            external_call(&local, &contract).is_none(),
            "calling our own method is not leaving the contract"
        );
    }

    #[test]
    fn knows_whether_the_callee_returns_anything() {
        let contract = contract_of(SOURCE);
        let with: syn::Expr = syn::parse_quote!(token.transfer(&vm, ctx, to, amount));
        let without: syn::Expr = syn::parse_quote!(token.ping(&vm, ctx, to));
        assert_eq!(external_call(&with, &contract).unwrap().returns, Some(true));
        assert_eq!(
            external_call(&without, &contract).unwrap().returns,
            Some(false)
        );
    }

    #[test]
    fn recognises_the_ways_storage_gets_written() {
        let contract = contract_of(SOURCE);
        let direct: syn::Expr = syn::parse_quote!(self.owner.set(next));
        let through_map: syn::Expr = syn::parse_quote!(self.budget.setter(key).set(value));
        let read: syn::Expr = syn::parse_quote!(self.owner.get());
        let unrelated: syn::Expr = syn::parse_quote!(local.set(value));

        assert_eq!(
            storage_write(&direct, &contract).map(|f| f.name.as_str()),
            Some("owner")
        );
        assert_eq!(
            storage_write(&through_map, &contract).map(|f| f.name.as_str()),
            Some("budget")
        );
        assert!(storage_write(&read, &contract).is_none());
        assert!(
            storage_write(&unrelated, &contract).is_none(),
            "a local variable is not storage"
        );
    }
}
