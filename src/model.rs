//! What the checker knows about a contract before any rule runs.
//!
//! There is no type inference here and there never will be, but a Stylus
//! contract declares more about itself than plain Rust does. `sol_storage!`
//! names every storage field and its exact Solidity type, and `sol_interface!`
//! names every function that reaches another contract. Reading those two macros
//! buys most of what a rule would otherwise need a type checker for, which is
//! the difference between a rule that stays quiet on correct code and one that
//! guesses.

use std::collections::BTreeMap;

use syn::visit::Visit;

/// A storage field as `sol_storage!` declared it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageField {
    pub name: String,
    /// The Solidity type verbatim, e.g. `uint256`, `mapping(address => bool)`.
    pub sol_type: String,
}

impl StorageField {
    /// Width in bits for `uintN` and `intN`, otherwise nothing.
    #[must_use]
    pub fn int_bits(&self) -> Option<u32> {
        let ty = self.sol_type.trim();
        let digits = ty.strip_prefix("uint").or_else(|| ty.strip_prefix("int"))?;
        if digits.is_empty() {
            return Some(256); // bare `uint` and `int` are 256 in Solidity
        }
        digits.parse().ok()
    }

    /// True for a collection whose size the contract does not control.
    #[must_use]
    pub fn is_dynamic(&self) -> bool {
        let ty = self.sol_type.trim();
        ty.starts_with("mapping") || ty.ends_with("[]") || ty == "bytes" || ty == "string"
    }

    /// True when the name reads like a lock a human added by hand.
    #[must_use]
    pub fn looks_like_a_guard(&self) -> bool {
        if self.sol_type.trim() != "bool" {
            return false;
        }
        let name = self.name.to_ascii_lowercase();
        ["entered", "locked", "lock", "guard", "reentran", "busy"]
            .iter()
            .any(|needle| name.contains(needle))
    }

    /// True when the name reads like whoever is allowed to change things.
    #[must_use]
    pub fn looks_like_an_authority(&self) -> bool {
        let ty = self.sol_type.trim();
        if ty != "address" && !ty.starts_with("mapping") {
            return false;
        }
        let name = self.name.to_ascii_lowercase();
        [
            "owner",
            "admin",
            "governor",
            "authority",
            "operator",
            "manager",
            "role",
        ]
        .iter()
        .any(|needle| name.contains(needle))
    }
}

/// A function on another contract, as `sol_interface!` declared it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalMethod {
    /// The Solidity name and the Rust one the SDK generates, when they differ.
    pub names: Vec<String>,
    /// Whether it returns anything. A call whose result is dropped only matters
    /// when there was a result to drop, and plenty of tokens report failure by
    /// returning false rather than by reverting.
    pub returns: bool,
    /// Whether the callee may change state, and so may call back into us.
    /// A `view` or `pure` function is reached by a static call, which cannot
    /// reenter, so ordering rules have nothing to say about it.
    pub mutates: bool,
}

/// Everything the two macros told us about one crate.
#[derive(Debug, Default)]
pub struct Contract {
    /// Storage fields by name.
    pub storage: BTreeMap<String, StorageField>,
    /// Functions that reach another contract.
    pub external_methods: Vec<ExternalMethod>,
}

impl Contract {
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&StorageField> {
        self.storage.get(name)
    }

    /// Looks up a method call name against the declared interfaces.
    #[must_use]
    pub fn external_method(&self, name: &str) -> Option<&ExternalMethod> {
        self.external_methods
            .iter()
            .find(|m| m.names.iter().any(|n| n == name))
    }

    /// True when this contract declares something that decides who may act.
    #[must_use]
    pub fn has_an_authority(&self) -> bool {
        self.storage
            .values()
            .any(StorageField::looks_like_an_authority)
    }

    /// Learns from every file in the crate, since the macros need not share one.
    pub fn absorb(&mut self, file: &syn::File) {
        let mut visitor = MacroReader { contract: self };
        visitor.visit_file(file);
    }
}

struct MacroReader<'a> {
    contract: &'a mut Contract,
}

impl Visit<'_> for MacroReader<'_> {
    fn visit_macro(&mut self, mac: &syn::Macro) {
        let Some(name) = mac.path.segments.last().map(|s| s.ident.to_string()) else {
            return;
        };
        let body = mac.tokens.to_string();
        match name.as_str() {
            "sol_storage" => {
                for field in parse_storage(&body) {
                    self.contract.storage.insert(field.name.clone(), field);
                }
            }
            "sol_interface" => {
                for method in parse_interface_methods(&body) {
                    if !self.contract.external_methods.contains(&method) {
                        self.contract.external_methods.push(method);
                    }
                }
            }
            // A contract can also be called through a plain trait object in
            // tests; nothing to learn from those.
            _ => {}
        }
    }
}

/// Pulls `type name;` pairs out of a `sol_storage!` body.
///
/// The body is Solidity, not Rust, so it arrives as an opaque token stream and
/// is read as text. Declarations are simple enough that this holds up: split on
/// semicolons, and in each declaration the last word is the name and the rest
/// is the type.
#[must_use]
pub fn parse_storage(body: &str) -> Vec<StorageField> {
    let mut fields = Vec::new();

    // Attributes come off first, before anything is split. A documented field
    // arrives as `# [doc = r" ..."] address owner`, and the doc text can hold
    // semicolons and braces of its own, so splitting before stripping loses
    // every field that somebody bothered to explain.
    let body = strip_attributes(body);

    // Everything between the outermost braces of each struct, so that struct
    // names and attributes do not look like declarations.
    for chunk in body.split(';') {
        let decl = chunk
            .rsplit('{')
            .next()
            .unwrap_or(chunk)
            .replace('}', " ")
            .trim()
            .to_string();
        if decl.is_empty() {
            continue;
        }
        // Attributes and struct headers are not fields.
        if decl.contains("struct")
            || decl.starts_with('#')
            || decl.contains("=>") && !decl.contains(')')
        {
            continue;
        }
        let Some((ty, name)) = split_declaration(&decl) else {
            continue;
        };
        if !is_identifier(&name) {
            continue;
        }
        fields.push(StorageField {
            name,
            sol_type: normalise_type(&ty),
        });
    }

    fields
}

/// Removes `#[..]` attribute groups, brackets balanced, contents and all.
#[must_use]
pub fn strip_attributes(body: &str) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut out = String::with_capacity(body.len());
    let mut at = 0;

    while at < chars.len() {
        if chars[at] == '#' {
            // Skip whitespace between the hash and its bracket, which the token
            // stream inserts.
            let mut probe = at + 1;
            while probe < chars.len() && chars[probe].is_whitespace() {
                probe += 1;
            }
            if probe < chars.len() && chars[probe] == '[' {
                let mut depth = 0usize;
                while probe < chars.len() {
                    match chars[probe] {
                        '[' => depth += 1,
                        ']' => {
                            depth -= 1;
                            if depth == 0 {
                                probe += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    probe += 1;
                }
                at = probe;
                out.push(' ');
                continue;
            }
        }
        out.push(chars[at]);
        at += 1;
    }

    out
}

/// Splits `mapping(address => bool) allowed` into its type and its name.
fn split_declaration(decl: &str) -> Option<(String, String)> {
    let trimmed = decl.trim();
    let (ty, name) = trimmed.rsplit_once(char::is_whitespace)?;
    let name = name.trim();
    let ty = ty.trim();
    if ty.is_empty() || name.is_empty() {
        return None;
    }
    Some((ty.to_string(), name.to_string()))
}

/// Token streams stringify with spaces around punctuation; put them back.
fn normalise_type(ty: &str) -> String {
    ty.replace(" (", "(")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" [", "[")
        .replace("[ ", "[")
        .replace(" ]", "]")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && text.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Pulls function names out of a `sol_interface!` body, in both spellings.
///
/// Every one of these is a call that leaves this contract, which is the single
/// most useful fact a rule can have: it is what makes checks-effects-interactions
/// checkable without knowing any types.
#[must_use]
pub fn parse_interface_methods(body: &str) -> Vec<ExternalMethod> {
    let mut methods = Vec::new();
    let mut rest = body;
    while let Some(at) = rest.find("function ") {
        rest = &rest[at + "function ".len()..];
        let name: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        // Everything up to the semicolon is this declaration, and `returns`
        // only appears in it when the function hands something back.
        let declaration = rest.split(';').next().unwrap_or(rest);
        let returns = declaration.contains("returns");
        let mutates = !declaration.contains("view") && !declaration.contains("pure");

        let snake = to_snake_case(&name);
        let mut names = vec![name];
        if snake != names[0] {
            names.push(snake);
        }
        methods.push(ExternalMethod {
            names,
            returns,
            mutates,
        });
    }
    methods
}

/// The spelling the SDK generates for a Solidity function name.
///
/// `balanceOf` becomes `balance_of` and `verifyEd25519` becomes
/// `verify_ed_25519`, digits splitting from letters the same way the macro does.
#[must_use]
pub fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    let mut previous: Option<char> = None;
    for ch in name.chars() {
        if ch.is_uppercase() {
            if previous.is_some_and(|p| p != '_') {
                out.push('_');
            }
            out.extend(ch.to_lowercase());
        } else if ch.is_ascii_digit() && previous.is_some_and(char::is_alphabetic) {
            out.push('_');
            out.push(ch);
        } else {
            out.push(ch);
        }
        previous = Some(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage_of(body: &str) -> Vec<StorageField> {
        parse_storage(body)
    }

    #[test]
    fn reads_the_fields_a_contract_declares() {
        let fields = storage_of(
            "#[entrypoint] pub struct Account { address owner ; uint256 budget ; bool entered ; }",
        );
        let names: Vec<_> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["owner", "budget", "entered"]);
        assert_eq!(fields[1].sol_type, "uint256");
    }

    #[test]
    fn reads_a_mapping_without_mistaking_the_arrow_for_a_field() {
        let fields = storage_of("pub struct A { mapping ( address => bool ) allowed ; }");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "allowed");
        assert!(fields[0].is_dynamic());
    }

    #[test]
    fn knows_how_wide_a_number_is() {
        let u256 = StorageField {
            name: "a".into(),
            sol_type: "uint256".into(),
        };
        let u64f = StorageField {
            name: "b".into(),
            sol_type: "uint64".into(),
        };
        let addr = StorageField {
            name: "c".into(),
            sol_type: "address".into(),
        };
        assert_eq!(u256.int_bits(), Some(256));
        assert_eq!(u64f.int_bits(), Some(64));
        assert_eq!(addr.int_bits(), None);
    }

    #[test]
    fn recognises_a_hand_rolled_lock_and_an_authority() {
        let guard = StorageField {
            name: "entered".into(),
            sol_type: "bool".into(),
        };
        let owner = StorageField {
            name: "owner".into(),
            sol_type: "address".into(),
        };
        let budget = StorageField {
            name: "budget".into(),
            sol_type: "uint256".into(),
        };
        assert!(guard.looks_like_a_guard());
        assert!(owner.looks_like_an_authority());
        assert!(!budget.looks_like_a_guard());
        assert!(!budget.looks_like_an_authority());
    }

    #[test]
    fn a_bool_named_like_a_flag_is_not_a_lock() {
        let flag = StorageField {
            name: "paused".into(),
            sol_type: "bool".into(),
        };
        assert!(!flag.looks_like_a_guard());
    }

    #[test]
    fn reads_the_functions_an_interface_declares() {
        let methods = parse_interface_methods(
            "interface IErc20 { function transfer (address to , uint256 amount) external returns (bool) ; \
             function balanceOf (address who) external view returns (uint256) ; }",
        );
        let names: Vec<&str> = methods
            .iter()
            .flat_map(|m| m.names.iter().map(String::as_str))
            .collect();
        assert!(names.contains(&"transfer"));
        assert!(names.contains(&"balance_of"));
        assert!(names.contains(&"balanceOf"));
        assert!(methods.iter().all(|m| m.returns));
    }

    #[test]
    fn spells_names_the_way_the_macro_does() {
        assert_eq!(to_snake_case("transfer"), "transfer");
        assert_eq!(to_snake_case("balanceOf"), "balance_of");
        assert_eq!(to_snake_case("verifyEd25519"), "verify_ed_25519");
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;

    #[test]
    fn knows_which_calls_hand_something_back() {
        let methods = parse_interface_methods(
            "interface I { function ping () external ; \
             function balanceOf (address a) external view returns (uint256) ; }",
        );
        let ping = methods.iter().find(|m| m.names[0] == "ping").unwrap();
        let balance = methods.iter().find(|m| m.names[0] == "balanceOf").unwrap();
        assert!(!ping.returns, "a void call has no result to drop");
        assert!(balance.returns);
    }
}

#[cfg(test)]
mod documented_storage_tests {
    use super::*;

    /// The real contract this checker was built against documents every field.
    /// Before this was handled the storage model came back empty, and every
    /// rule that depends on it went quiet while looking like it had run.
    #[test]
    fn a_documented_field_is_still_a_field() {
        let body = r###"
            #[entrypoint]
            pub struct Account {
                # [doc = r" Sets policy and rotates the agent; never spends."] address owner ;
                # [doc = r" Spendable per window."] uint256 budget ;
                # [doc = r" Recipients { allowed } without a mandate."] mapping (address => bool) allowed ;
            }
        "###;
        let fields = parse_storage(body);
        let names: Vec<_> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["owner", "budget", "allowed"]);
        assert_eq!(fields[1].sol_type, "uint256");
    }

    #[test]
    fn attribute_text_never_leaks_into_a_field() {
        let stripped = strip_attributes("# [doc = r\" a; b { c }\"] address owner ;");
        assert!(!stripped.contains("doc"));
        assert!(stripped.contains("address owner"));
    }
}

#[cfg(test)]
mod mutability_tests {
    use super::*;

    /// Reading this off the interface is what keeps the ordering rule quiet on
    /// correct code: a static call cannot call back, so a write after one is
    /// not out of order.
    #[test]
    fn a_view_function_is_reached_by_a_call_that_cannot_reenter() {
        let methods = parse_interface_methods(
            "interface I { function transfer (address to, uint256 v) external returns (bool) ; \
             function balanceOf (address a) external view returns (uint256) ; }",
        );
        let transfer = methods.iter().find(|m| m.names[0] == "transfer").unwrap();
        let balance = methods.iter().find(|m| m.names[0] == "balanceOf").unwrap();
        assert!(transfer.mutates);
        assert!(
            !balance.mutates,
            "a view call is a staticcall and cannot come back in"
        );
    }
}
