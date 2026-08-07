//! `stylus-check.toml`, for when a rule is wrong about your contract.
//!
//! Every rule here is a heuristic, so every rule is sometimes wrong. The way
//! that gets handled decides whether the tool survives contact with a real
//! codebase: either you can turn one rule down in one project, or you turn the
//! whole checker off. This is the first of those.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::finding::Severity;

/// What a project asked for.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Rules to switch off entirely, by id.
    #[serde(default)]
    pub disable: Vec<String>,
    /// Severity overrides, by rule id, e.g. `state-write-after-call = "low"`.
    #[serde(default)]
    pub severity: BTreeMap<String, String>,
}

/// Why a config file could not be used. Always names the file and the problem,
/// because a config that is silently ignored is worse than one that is missing.
#[derive(Debug)]
pub enum ConfigError {
    Unreadable(String),
    Malformed(String),
    UnknownRule {
        rule: String,
        known: Vec<&'static str>,
    },
    UnknownSeverity {
        rule: String,
        value: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Unreadable(why) => write!(f, "could not read stylus-check.toml: {why}"),
            ConfigError::Malformed(why) => write!(f, "stylus-check.toml is not valid: {why}"),
            ConfigError::UnknownRule { rule, known } => write!(
                f,
                "stylus-check.toml mentions the rule `{rule}`, which does not exist. \
                 The rules are: {}",
                known.join(", ")
            ),
            ConfigError::UnknownSeverity { rule, value } => write!(
                f,
                "stylus-check.toml sets `{rule}` to severity `{value}`, which is not one of \
                 low, medium or high"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Looks for `stylus-check.toml` at `start` and in every directory above it.
///
/// Stops at a repository boundary so a stray file in a home directory cannot
/// quietly change what somebody's project reports.
#[must_use]
fn find_upward(start: &Path) -> Option<std::path::PathBuf> {
    let mut current = if start.is_dir() {
        Some(start)
    } else {
        start.parent()
    };

    while let Some(directory) = current {
        let candidate = directory.join("stylus-check.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if directory.join(".git").exists() {
            return None;
        }
        current = directory.parent();
    }
    None
}

impl Config {
    /// Reads `stylus-check.toml`, searching upward from the path being checked.
    ///
    /// Upward, not just in place, because people point this at a subdirectory:
    /// `stylus-check ./src` is the first example in the README, and the config
    /// belongs at the project root above it. Looking only where the tool was
    /// aimed meant the file was there, was valid, and did nothing.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the file exists but cannot be used.
    pub fn load(root: &Path, known_rules: &[&'static str]) -> Result<Self, ConfigError> {
        let Some(path) = find_upward(root) else {
            return Ok(Self::default());
        };
        let text =
            std::fs::read_to_string(&path).map_err(|e| ConfigError::Unreadable(e.to_string()))?;
        let config: Config =
            toml::from_str(&text).map_err(|e| ConfigError::Malformed(e.to_string()))?;
        config.validate(known_rules)?;
        Ok(config)
    }

    /// Rejects a config that names a rule that does not exist.
    ///
    /// A typo would otherwise disable nothing and say nothing, leaving somebody
    /// believing they had silenced a rule that is still running.
    fn validate(&self, known: &[&'static str]) -> Result<(), ConfigError> {
        for rule in self.disable.iter().chain(self.severity.keys()) {
            if !known.contains(&rule.as_str()) {
                return Err(ConfigError::UnknownRule {
                    rule: rule.clone(),
                    known: known.to_vec(),
                });
            }
        }
        for (rule, value) in &self.severity {
            if Severity::parse(value).is_none() {
                return Err(ConfigError::UnknownSeverity {
                    rule: rule.clone(),
                    value: value.clone(),
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn is_disabled(&self, rule: &str) -> bool {
        self.disable.iter().any(|r| r == rule)
    }

    /// The severity a project wants for a rule, if it asked for a different one.
    #[must_use]
    pub fn severity_for(&self, rule: &str) -> Option<Severity> {
        self.severity.get(rule).and_then(|v| Severity::parse(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: &[&str] = &["unwrap-in-entrypoint", "state-write-after-call"];

    fn parse(text: &str) -> Result<Config, ConfigError> {
        let config: Config =
            toml::from_str(text).map_err(|e| ConfigError::Malformed(e.to_string()))?;
        config.validate(KNOWN)?;
        Ok(config)
    }

    #[test]
    fn a_project_can_switch_a_rule_off() {
        let config = parse("disable = [\"unwrap-in-entrypoint\"]").unwrap();
        assert!(config.is_disabled("unwrap-in-entrypoint"));
        assert!(!config.is_disabled("state-write-after-call"));
    }

    #[test]
    fn a_project_can_rank_a_rule_differently() {
        let config = parse("[severity]\nstate-write-after-call = \"low\"").unwrap();
        assert_eq!(
            config.severity_for("state-write-after-call"),
            Some(Severity::Low)
        );
        assert_eq!(config.severity_for("unwrap-in-entrypoint"), None);
    }

    #[test]
    fn a_typo_is_refused_rather_than_ignored() {
        let err = parse("disable = [\"unwrap-in-entrypoints\"]").unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownRule { .. }),
            "silently ignoring this would leave somebody thinking a rule was off"
        );
    }

    #[test]
    fn a_severity_that_is_not_one_is_refused() {
        let err = parse("[severity]\nunwrap-in-entrypoint = \"critical\"").unwrap_err();
        assert!(matches!(err, ConfigError::UnknownSeverity { .. }));
    }

    #[test]
    fn a_stray_key_is_refused_so_it_cannot_look_like_it_worked() {
        assert!(parse("disabled = [\"unwrap-in-entrypoint\"]").is_err());
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("stylus-check-config-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        dir
    }

    /// `stylus-check ./src` is the README's own first example, and the config
    /// belongs at the project root above it. Looking only where the tool was
    /// aimed left the file sitting there doing nothing.
    #[test]
    fn a_config_at_the_project_root_applies_to_a_subdirectory() {
        let dir = scratch("upward");
        fs::write(
            dir.join("stylus-check.toml"),
            "disable = [\"unwrap-in-entrypoint\"]",
        )
        .unwrap();

        let config = Config::load(&dir.join("src"), &["unwrap-in-entrypoint"]).unwrap();
        assert!(config.is_disabled("unwrap-in-entrypoint"));
    }

    #[test]
    fn it_is_found_from_a_single_file_too() {
        let dir = scratch("file");
        fs::write(
            dir.join("stylus-check.toml"),
            "disable = [\"unwrap-in-entrypoint\"]",
        )
        .unwrap();
        let file = dir.join("src/lib.rs");
        fs::write(&file, "").unwrap();

        let config = Config::load(&file, &["unwrap-in-entrypoint"]).unwrap();
        assert!(config.is_disabled("unwrap-in-entrypoint"));
    }

    #[test]
    fn the_search_stops_at_the_repository_it_is_checking() {
        let dir = scratch("boundary");
        // A file above the repository must not reach into it.
        fs::write(
            dir.join("stylus-check.toml"),
            "disable = [\"unwrap-in-entrypoint\"]",
        )
        .unwrap();
        let repo = dir.join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("src")).unwrap();

        let config = Config::load(&repo.join("src"), &["unwrap-in-entrypoint"]).unwrap();
        assert!(!config.is_disabled("unwrap-in-entrypoint"));
    }

    #[test]
    fn no_config_anywhere_is_not_an_error() {
        let dir = scratch("none");
        fs::create_dir_all(dir.join("repo/.git")).unwrap();
        let config = Config::load(&dir.join("repo"), &["unwrap-in-entrypoint"]).unwrap();
        assert!(!config.is_disabled("unwrap-in-entrypoint"));
    }
}
