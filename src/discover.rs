//! Finding the code to check, and refusing politely when there is none.

use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Why a path cannot be checked. Each of these is a message to a person, so
/// each says what was looked for and where.
#[derive(Debug)]
pub enum NotStylus {
    /// The path does not exist.
    Missing(PathBuf),
    /// A Rust crate, but nothing in it depends on the stylus-sdk.
    NoSdkDependency(PathBuf),
    /// No Rust source at all under the path.
    NoRustSource(PathBuf),
}

impl std::fmt::Display for NotStylus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotStylus::Missing(p) => write!(f, "there is nothing at {}", p.display()),
            NotStylus::NoSdkDependency(p) => write!(
                f,
                "no crate under {} depends on stylus-sdk, so there are no Stylus contracts here.\n\
                 This checker only understands stylus-sdk code; for plain Rust use clippy, and for \
                 Solidity use slither.",
                p.display()
            ),
            NotStylus::NoRustSource(p) => {
                write!(f, "no Rust source files under {}", p.display())
            }
        }
    }
}

impl std::error::Error for NotStylus {}

/// The Rust files to check, once the path has been confirmed to hold Stylus code.
#[derive(Debug)]
pub struct Sources {
    pub files: Vec<PathBuf>,
    /// Manifests that pulled in the stylus-sdk, for reporting.
    pub manifests: Vec<PathBuf>,
}

/// Collects the Rust sources under `root`, provided this really is Stylus code.
///
/// The dependency check exists so that pointing the tool at an unrelated Rust
/// project fails with a sentence rather than with a page of findings from rules
/// that were never meant to apply to it.
///
/// # Errors
/// Returns [`NotStylus`] when the path is missing, holds no Rust, or holds Rust
/// that never depends on the stylus-sdk.
pub fn collect(root: &Path) -> Result<Sources, NotStylus> {
    if !root.exists() {
        return Err(NotStylus::Missing(root.to_path_buf()));
    }

    let mut files = Vec::new();
    let mut manifests = Vec::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_ignored_dir(e.path()))
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.file_name().is_some_and(|n| n == "Cargo.toml") {
            if let Ok(text) = fs::read_to_string(path) {
                if declares_stylus_sdk(&text) {
                    manifests.push(path.to_path_buf());
                }
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path.to_path_buf());
        }
    }

    // A single file is a legitimate target, and it has no manifest of its own.
    // Fall back to the source itself saying it is Stylus.
    if manifests.is_empty() {
        let looks_like_stylus = files.iter().any(|f| {
            fs::read_to_string(f)
                .ok()
                .and_then(|text| syn::parse_file(&text).ok())
                .is_some_and(|file| declares_a_contract(&file))
        });
        if !looks_like_stylus {
            return Err(if files.is_empty() {
                NotStylus::NoRustSource(root.to_path_buf())
            } else {
                NotStylus::NoSdkDependency(root.to_path_buf())
            });
        }
    }

    if files.is_empty() {
        return Err(NotStylus::NoRustSource(root.to_path_buf()));
    }

    files.sort();
    manifests.sort();
    Ok(Sources { files, manifests })
}

/// Directories whose contents are never the user's own contract code.
fn is_ignored_dir(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        matches!(
            name.to_string_lossy().as_ref(),
            "target" | ".git" | "node_modules" | ".cargo" | "vendor"
        )
    })
}

/// True when a manifest depends on the stylus-sdk, however it is spelled.
///
/// Deliberately textual. Reading the manifest properly would mean modelling
/// workspace inheritance, path dependencies and renamed crates, and getting
/// the answer wrong in either direction only changes whether we agree to look.
fn declares_stylus_sdk(manifest: &str) -> bool {
    manifest
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .any(|line| line.starts_with("stylus-sdk") || line.starts_with("stylus_sdk"))
}

/// True when a parsed file actually declares a Stylus contract.
///
/// Looking for these words in the text would be simpler and wrong: this
/// checker's own source is full of them, and it happily accepted itself as a
/// contract to check. The macro has to be invoked, not merely mentioned.
fn declares_a_contract(file: &syn::File) -> bool {
    use syn::visit::Visit;

    struct Seek {
        found: bool,
    }
    impl Visit<'_> for Seek {
        fn visit_macro(&mut self, mac: &syn::Macro) {
            if mac
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "sol_storage" || s.ident == "sol_interface")
            {
                self.found = true;
            }
            syn::visit::visit_macro(self, mac);
        }
        fn visit_item_impl(&mut self, item: &syn::ItemImpl) {
            if item.attrs.iter().any(|a| {
                a.path()
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "public")
            }) {
                self.found = true;
            }
            syn::visit::visit_item_impl(self, item);
        }
    }

    let mut seek = Seek { found: false };
    seek.visit_file(file);
    seek.found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_naming_the_sdk_counts_however_it_is_written() {
        assert!(declares_stylus_sdk("stylus-sdk = \"0.10\""));
        assert!(declares_stylus_sdk("  stylus-sdk = { version = \"0.10\" }"));
        assert!(declares_stylus_sdk("stylus_sdk = \"0.10\""));
    }

    #[test]
    fn a_commented_out_dependency_does_not_count() {
        assert!(!declares_stylus_sdk("# stylus-sdk = \"0.10\""));
    }

    #[test]
    fn an_unrelated_manifest_does_not_count() {
        assert!(!declares_stylus_sdk("serde = \"1\"\ntokio = \"1\""));
        // Naming the checker itself is not the same as depending on the SDK.
        assert!(!declares_stylus_sdk("stylus-check = \"0.1\""));
    }

    #[test]
    fn build_output_is_never_checked() {
        assert!(is_ignored_dir(Path::new("/x/target")));
        assert!(is_ignored_dir(Path::new("/x/node_modules")));
        assert!(!is_ignored_dir(Path::new("/x/src")));
    }

    #[test]
    fn a_missing_path_says_so() {
        let err = collect(Path::new("/nonexistent/place")).unwrap_err();
        assert!(matches!(err, NotStylus::Missing(_)));
    }
}

#[cfg(test)]
mod contract_detection_tests {
    use super::*;

    /// This checker's own source quotes `sol_storage!` and `#[public]` in
    /// strings and comments all over. Matching on text meant it accepted itself
    /// as a contract and then reported findings in its own rule definitions.
    #[test]
    fn merely_naming_the_macros_is_not_declaring_a_contract() {
        let file = syn::parse_file(
            r##"
            const EXAMPLE: &str = "sol_storage! { pub struct A { address owner; } }";
            /// Recognises a `#[public]` impl block.
            fn describe() -> &'static str { "#[public]" }
            "##,
        )
        .unwrap();
        assert!(!declares_a_contract(&file));
    }

    #[test]
    fn invoking_the_macro_is() {
        let file = syn::parse_file("sol_storage! { pub struct A { address owner; } }").unwrap();
        assert!(declares_a_contract(&file));
    }

    #[test]
    fn so_is_a_public_impl() {
        let file = syn::parse_file("#[public] impl A { pub fn go(&mut self) {} }").unwrap();
        assert!(declares_a_contract(&file));
    }
}
