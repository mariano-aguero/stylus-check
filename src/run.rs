//! Putting it together: read a path, learn the contract, run the rules.

use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::discover::{self, NotStylus};
use crate::finding::{Finding, Report, Severity, SkippedFile};
use crate::model::Contract;
use crate::rules::{self, Ctx};

/// The rule ids, including the ones that read manifests rather than syntax.
#[must_use]
pub fn rule_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = rules::all().iter().map(|r| r.id()).collect();
    ids.push(DEPRECATED_GUARD);
    ids.sort_unstable();
    ids
}

const DEPRECATED_GUARD: &str = "deprecated-reentrancy-guard";

/// Checks everything under `root`.
///
/// The contract is learned from every file first and the rules run afterwards,
/// because `sol_storage!` and `sol_interface!` need not live in the file that
/// uses them, and a rule that has not read them yet would guess.
///
/// # Errors
/// Returns [`NotStylus`] when the path holds no Stylus code to check.
pub fn check(root: &Path, config: &Config) -> Result<Report, NotStylus> {
    let sources = discover::collect(root)?;
    let mut report = Report::default();

    // One model per crate, not one per run. A repository can hold many
    // contracts, and merging their storage produces a model that belongs to
    // none of them: a rule then reports a function for not reading an owner
    // field that lives in somebody else's contract.
    let mut parsed: Vec<(std::path::PathBuf, String, syn::File, std::path::PathBuf)> = Vec::new();
    let mut contracts: std::collections::BTreeMap<std::path::PathBuf, Contract> =
        std::collections::BTreeMap::new();

    for path in &sources.files {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => {
                report.skipped.push(SkippedFile {
                    file: path.clone(),
                    reason: err.to_string(),
                });
                continue;
            }
        };
        match syn::parse_file(&text) {
            Ok(file) => {
                let crate_root = crate_root_of(path, &sources.manifests);
                contracts
                    .entry(crate_root.clone())
                    .or_default()
                    .absorb(&file);
                parsed.push((path.clone(), text, file, crate_root));
            }
            Err(err) => {
                // One unparseable file must not stop the rest. Half a report
                // beats no report, as long as the gap is stated.
                report.skipped.push(SkippedFile {
                    file: path.clone(),
                    reason: err.to_string(),
                });
            }
        }
    }

    let fallback = Contract::default();
    for (path, text, file, crate_root) in &parsed {
        let contract = contracts.get(crate_root).unwrap_or(&fallback);
        let ctx = Ctx {
            file: path,
            contract,
        };
        for rule in rules::all() {
            if config.is_disabled(rule.id()) {
                continue;
            }
            for mut finding in rule.check(file, &ctx) {
                if let Some(severity) = config.severity_for(rule.id()) {
                    finding.severity = severity;
                }
                report.findings.push(finding);
            }
        }
        if !config.is_disabled(DEPRECATED_GUARD) {
            report
                .findings
                .extend(deprecated_guard_in_source(path, text, config));
        }
    }
    report.files_checked = parsed.len();

    if !config.is_disabled(DEPRECATED_GUARD) {
        for manifest in &sources.manifests {
            if let Ok(text) = fs::read_to_string(manifest) {
                report
                    .findings
                    .extend(deprecated_guard_in_manifest(manifest, &text, config));
            }
        }
    }

    report.sort();
    Ok(report)
}

/// The crate a file belongs to: the closest manifest above it.
///
/// Everything under one manifest shares a contract model, and nothing crosses
/// between them.
fn crate_root_of(file: &Path, manifests: &[std::path::PathBuf]) -> std::path::PathBuf {
    manifests
        .iter()
        .filter_map(|manifest| manifest.parent())
        .filter(|root| file.starts_with(root))
        .max_by_key(|root| root.components().count())
        .map_or_else(|| std::path::PathBuf::from(""), Path::to_path_buf)
}

fn severity_of(config: &Config, default: Severity) -> Severity {
    config.severity_for(DEPRECATED_GUARD).unwrap_or(default)
}

/// The SDK's own reentrancy guard, which it deprecated in 0.10.5.
///
/// Worth saying because the advice most people carry over from Solidity is to
/// add a guard, and here that means adopting an API on its way out. The high
/// level call functions flush the storage cache themselves now. That is not the
/// same as being safe from reentrancy, which is what the checks effects
/// interactions rule is for.
fn deprecated_guard_in_source(path: &Path, text: &str, config: &Config) -> Vec<Finding> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            // A rule that reads text has to ignore text that is not code, or it
            // reports the comment explaining why the guard was removed.
            !trimmed.starts_with("//") && !trimmed.starts_with("*") && line.contains("deny_reentrant")
        })
        .map(|(index, line)| {
            Finding::new(
                DEPRECATED_GUARD,
                severity_of(config, Severity::Medium),
                path,
                index + 1,
                line.find("deny_reentrant").unwrap_or(0) + 1,
                "`deny_reentrant` was deprecated in stylus-sdk 0.10.5",
                "drop it. The high level call functions flush the storage cache themselves, which \
                 is what this guard was for. Reentrancy itself is still yours to handle, by writing \
                 state before you call out.",
            )
        })
        .collect()
}

fn deprecated_guard_in_manifest(path: &Path, text: &str, config: &Config) -> Vec<Finding> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim();
            // The line has to name the SDK. Matching any line with a feature
            // called `reentrant` reported unrelated crates that happen to have
            // one, which is a finding about somebody else's dependency.
            !trimmed.starts_with('#')
                && trimmed.contains("\"reentrant\"")
                && (trimmed.contains("stylus-sdk") || trimmed.contains("stylus_sdk"))
        })
        .map(|(index, _)| {
            Finding::new(
                DEPRECATED_GUARD,
                severity_of(config, Severity::Medium),
                path,
                index + 1,
                1,
                "the stylus-sdk `reentrant` feature was deprecated in 0.10.5",
                "drop the feature. It blocks legitimate reentrant calls and the cache flushing it \
                 existed for now happens on every high level call.",
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("stylus-check-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, text: &str) {
        fs::write(dir.join(rel), text).unwrap();
    }

    #[test]
    fn refuses_a_project_that_is_not_stylus() {
        let dir = temp("plain");
        write(
            &dir,
            "Cargo.toml",
            "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\n",
        );
        write(
            &dir,
            "src/lib.rs",
            "pub fn add(a: u8, b: u8) -> u8 { a + b }",
        );

        let err = check(&dir, &Config::default()).unwrap_err();
        assert!(matches!(err, NotStylus::NoSdkDependency(_)));
    }

    #[test]
    fn a_file_that_does_not_parse_is_reported_and_the_rest_still_run() {
        let dir = temp("broken");
        write(
            &dir,
            "Cargo.toml",
            "[dependencies]\nstylus-sdk = \"0.10\"\n",
        );
        write(&dir, "src/broken.rs", "pub fn oops( {");
        write(
            &dir,
            "src/lib.rs",
            "sol_storage! { pub struct A { address owner; uint256 v; } }\n\
             #[public]\n impl A { pub fn go(&mut self, k: U256) { self.book.get(k).unwrap(); } }",
        );

        let report = check(&dir, &Config::default()).unwrap();
        assert_eq!(report.skipped.len(), 1, "the broken file is named");
        assert!(report.skipped[0].file.ends_with("broken.rs"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "unwrap-in-entrypoint"),
            "the good file is still checked"
        );
    }

    #[test]
    fn learns_the_contract_from_a_file_other_than_the_one_it_checks() {
        let dir = temp("split");
        write(
            &dir,
            "Cargo.toml",
            "[dependencies]\nstylus-sdk = \"0.10\"\n",
        );
        write(
            &dir,
            "src/storage.rs",
            "sol_storage! { pub struct A { uint64 last_refill; uint256 budget; } }",
        );
        write(
            &dir,
            "src/logic.rs",
            "#[public]\n impl A {\n pub fn go(&mut self) { let a = self.last_refill.get().to::<u64>(); let b = self.budget.get().to::<u64>(); }\n }",
        );

        let report = check(&dir, &Config::default()).unwrap();
        let lossy: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule == "lossy-integer-conversion")
            .collect();
        assert_eq!(lossy.len(), 1, "only the uint256 one is lossy");
        assert!(lossy[0].message.contains("budget"));
    }

    #[test]
    fn a_disabled_rule_says_nothing() {
        let dir = temp("disabled");
        write(
            &dir,
            "Cargo.toml",
            "[dependencies]\nstylus-sdk = \"0.10\"\n",
        );
        write(
            &dir,
            "src/lib.rs",
            "#[public]\n impl A { pub fn go(&mut self, k: U256) { self.book.get(k).unwrap(); } }",
        );
        let config = Config {
            disable: vec!["unwrap-in-entrypoint".into()],
            ..Config::default()
        };
        let report = check(&dir, &config).unwrap();
        assert!(report.findings.is_empty());
    }

    #[test]
    fn flags_the_deprecated_guard_wherever_it_appears() {
        let dir = temp("guard");
        write(
            &dir,
            "Cargo.toml",
            "[dependencies]\nstylus-sdk = { version = \"0.10\", features = [\"reentrant\"] }\n",
        );
        write(
            &dir,
            "src/lib.rs",
            "#[entrypoint]\n#[deny_reentrant]\npub struct A;",
        );

        let report = check(&dir, &Config::default()).unwrap();
        let guards: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule == "deprecated-reentrancy-guard")
            .collect();
        assert_eq!(guards.len(), 2, "the manifest and the source both say it");
    }
}

#[cfg(test)]
mod crate_scope_tests {
    use super::*;

    /// Found by running the checker over the stylus-sdk examples, where one
    /// contract was reported for not consulting an owner that belonged to a
    /// different example entirely.
    #[test]
    fn one_contract_never_borrows_another_contract_storage() {
        let dir = std::env::temp_dir().join(format!("stylus-check-scope-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for name in ["owned", "open"] {
            fs::create_dir_all(dir.join(name).join("src")).unwrap();
            fs::write(
                dir.join(name).join("Cargo.toml"),
                "[dependencies]\nstylus-sdk = \"0.10\"\n",
            )
            .unwrap();
        }
        fs::write(
            dir.join("owned/src/lib.rs"),
            "sol_storage! { pub struct A { address owner; uint256 v; } }",
        )
        .unwrap();
        fs::write(
            dir.join("open/src/lib.rs"),
            "sol_storage! { pub struct B { uint256 counter; } }\n\
             #[public]\n impl B { pub fn bump(&mut self) { self.counter.set(v); } }",
        )
        .unwrap();

        let report = check(&dir, &Config::default()).unwrap();
        assert!(
            !report.findings.iter().any(|f| f.rule == "missing-access-control"),
            "the open contract has no authority of its own, and the neighbour's is not its business"
        );
    }
}

#[cfg(test)]
mod manifest_rule_tests {
    use super::*;

    fn findings_for(manifest: &str) -> Vec<Finding> {
        deprecated_guard_in_manifest(Path::new("Cargo.toml"), manifest, &Config::default())
    }

    #[test]
    fn flags_the_feature_on_the_sdk() {
        let found = findings_for("stylus-sdk = { version = \"0.10\", features = [\"reentrant\"] }");
        assert_eq!(found.len(), 1);
    }

    /// A crate that happens to have a feature by the same name is not the SDK,
    /// and a finding about somebody else's dependency is just noise.
    #[test]
    fn says_nothing_about_another_crate_with_a_feature_of_the_same_name() {
        let found = findings_for("other-crate = { version = \"1\", features = [\"reentrant\"] }");
        assert!(found.is_empty());
    }

    #[test]
    fn a_commented_line_is_not_a_dependency() {
        let found =
            findings_for("# stylus-sdk = { version = \"0.10\", features = [\"reentrant\"] }");
        assert!(found.is_empty());
    }
}
