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

impl Config {
    /// Reads `stylus-check.toml` from a directory, if there is one.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the file exists but cannot be used.
    pub fn load(root: &Path, known_rules: &[&'static str]) -> Result<Self, ConfigError> {
        let path = if root.is_dir() {
            root.join("stylus-check.toml")
        } else {
            root.parent().unwrap_or(root).join("stylus-check.toml")
        };
        if !path.exists() {
            return Ok(Self::default());
        }
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
