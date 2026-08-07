//! Turning a report into something a person or a machine reads.

use serde::Serialize;

use crate::finding::{Report, Severity};

/// How to print a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// For a person at a terminal.
    Text,
    /// For anything that wants to read it back.
    Json,
    /// For code scanning, which annotates pull requests from it.
    Sarif,
}

impl Format {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text" => Some(Format::Text),
            "json" => Some(Format::Json),
            "sarif" => Some(Format::Sarif),
            _ => None,
        }
    }
}

/// A line of plain text per finding, worst first, with a closing count.
///
/// The last line says out loud that this is a heuristic tool. A clean run means
/// these rules found nothing, and somebody will otherwise read it as a contract
/// being safe, which is not something any linter can tell them.
#[must_use]
pub fn text(report: &Report, threshold: Severity) -> String {
    let mut out = String::new();

    for skipped in &report.skipped {
        out.push_str(&format!(
            "skipped {}: {}\n",
            skipped.file.display(),
            skipped
                .reason
                .lines()
                .next()
                .unwrap_or("could not be parsed")
        ));
    }
    if !report.skipped.is_empty() {
        out.push('\n');
    }

    for finding in &report.findings {
        out.push_str(&format!(
            "{}:{}:{} {} [{}]\n  {}\n  {}\n\n",
            finding.file.display(),
            finding.line,
            finding.column,
            finding.severity.as_str(),
            finding.rule,
            finding.message,
            finding.suggestion,
        ));
    }

    let counted = report.at_or_above(threshold).count();
    let files = report.files_checked;
    out.push_str(&format!(
        "{} finding{} at or above {} across {} file{}.\n",
        counted,
        if counted == 1 { "" } else { "s" },
        threshold.as_str(),
        files,
        if files == 1 { "" } else { "s" },
    ));
    out.push_str(
        "These are heuristics, not an audit. A quiet run means these rules found nothing to say.\n",
    );
    out
}

/// The whole report as JSON, for anything that wants to read it back.
///
/// # Errors
/// Returns an error only if the report cannot be serialised, which would be a bug.
pub fn json(report: &Report) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Makes a path relative to `base`, which is what SARIF consumers need.
///
/// Code scanning resolves every location against the repository root. An
/// absolute path from whichever machine ran the checker resolves to nothing, so
/// the annotation lands nowhere and the run looks clean.
#[must_use]
pub fn relative_to(path: &std::path::Path, base: &std::path::Path) -> String {
    let stripped = path.strip_prefix(base).unwrap_or(path);
    let text = stripped.to_string_lossy().replace('\\', "/");
    text.strip_prefix("./").unwrap_or(&text).to_string()
}

/// SARIF 2.1.0, which is what code scanning ingests to annotate a pull request.
///
/// Locations are written relative to `base`, which should be the repository
/// root, because that is what the annotations are resolved against.
///
/// # Errors
/// Returns an error only if the report cannot be serialised, which would be a bug.
pub fn sarif(
    report: &Report,
    rules: &[(&str, &str)],
    base: &std::path::Path,
) -> Result<String, serde_json::Error> {
    #[derive(Serialize)]
    struct Sarif<'a> {
        #[serde(rename = "$schema")]
        schema: &'a str,
        version: &'a str,
        runs: Vec<Run<'a>>,
    }
    #[derive(Serialize)]
    struct Run<'a> {
        tool: Tool<'a>,
        results: Vec<SarifResult<'a>>,
    }
    #[derive(Serialize)]
    struct Tool<'a> {
        driver: Driver<'a>,
    }
    #[derive(Serialize)]
    struct Driver<'a> {
        name: &'a str,
        version: &'a str,
        #[serde(rename = "informationUri")]
        information_uri: &'a str,
        rules: Vec<SarifRule<'a>>,
    }
    #[derive(Serialize)]
    struct SarifRule<'a> {
        id: &'a str,
        #[serde(rename = "shortDescription")]
        short_description: Text<'a>,
    }
    #[derive(Serialize)]
    struct SarifResult<'a> {
        #[serde(rename = "ruleId")]
        rule_id: &'a str,
        level: &'a str,
        message: Owned,
        locations: Vec<Location>,
    }
    #[derive(Serialize)]
    struct Text<'a> {
        text: &'a str,
    }
    #[derive(Serialize)]
    struct Owned {
        text: String,
    }
    #[derive(Serialize)]
    struct Location {
        #[serde(rename = "physicalLocation")]
        physical_location: Physical,
    }
    #[derive(Serialize)]
    struct Physical {
        #[serde(rename = "artifactLocation")]
        artifact_location: Artifact,
        region: Region,
    }
    #[derive(Serialize)]
    struct Artifact {
        uri: String,
    }
    #[derive(Serialize)]
    struct Region {
        #[serde(rename = "startLine")]
        start_line: usize,
        #[serde(rename = "startColumn")]
        start_column: usize,
    }

    let document = Sarif {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "stylus-check",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/mariano-aguero/stylus-check",
                    rules: rules
                        .iter()
                        .map(|(id, description)| SarifRule {
                            id,
                            short_description: Text { text: description },
                        })
                        .collect(),
                },
            },
            results: report
                .findings
                .iter()
                .map(|f| SarifResult {
                    rule_id: f.rule,
                    level: match f.severity {
                        Severity::High => "error",
                        Severity::Medium => "warning",
                        Severity::Low => "note",
                    },
                    message: Owned {
                        text: format!("{} {}", f.message, f.suggestion),
                    },
                    locations: vec![Location {
                        physical_location: Physical {
                            artifact_location: Artifact {
                                uri: relative_to(&f.file, base),
                            },
                            region: Region {
                                start_line: f.line,
                                start_column: f.column,
                            },
                        },
                    }],
                })
                .collect(),
        }],
    };

    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;
    use std::path::Path;

    fn report() -> Report {
        let mut report = Report {
            files_checked: 2,
            ..Default::default()
        };
        report.findings.push(Finding::new(
            "unwrap-in-entrypoint",
            Severity::High,
            Path::new("src/lib.rs"),
            12,
            9,
            "`unwrap()` is reachable",
            "return an Err instead",
        ));
        report
    }

    #[test]
    fn text_names_the_place_the_rule_and_the_fix() {
        let out = text(&report(), Severity::Low);
        assert!(out.contains("src/lib.rs:12:9"));
        assert!(out.contains("[unwrap-in-entrypoint]"));
        assert!(out.contains("return an Err instead"));
    }

    #[test]
    fn text_never_lets_a_quiet_run_read_as_a_clean_bill_of_health() {
        let out = text(&Report::default(), Severity::Low);
        assert!(out.contains("heuristics, not an audit"));
    }

    #[test]
    fn text_counts_only_what_the_threshold_admits() {
        let out = text(&report(), Severity::High);
        assert!(out.contains("1 finding at or above high"));
        let quiet = text(&report(), Severity::Low);
        assert!(quiet.contains("1 finding at or above low"));
    }

    #[test]
    fn json_round_trips() {
        let out = json(&report()).unwrap();
        let back: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(back["findings"][0]["rule"], "unwrap-in-entrypoint");
        assert_eq!(back["findings"][0]["severity"], "high");
        assert_eq!(back["findings"][0]["line"], 12);
    }

    #[test]
    fn sarif_says_what_code_scanning_needs() {
        let out = sarif(
            &report(),
            &[("unwrap-in-entrypoint", "a panic reachable from a caller")],
            Path::new(""),
        )
        .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(doc["version"], "2.1.0");
        let result = &doc["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "unwrap-in-entrypoint");
        assert_eq!(
            result["level"], "error",
            "high severity has to block a merge"
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
        assert_eq!(
            doc["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "unwrap-in-entrypoint"
        );
    }

    #[test]
    fn a_format_is_only_one_of_the_three() {
        assert_eq!(Format::parse("SARIF"), Some(Format::Sarif));
        assert_eq!(Format::parse("xml"), None);
    }
}

#[cfg(test)]
mod sarif_location_tests {
    use super::*;
    use crate::finding::Finding;
    use std::path::{Path, PathBuf};

    fn report_at(file: &str) -> Report {
        let mut report = Report::default();
        report.findings.push(Finding::new(
            "unwrap-in-entrypoint",
            Severity::High,
            Path::new(file),
            3,
            1,
            "m",
            "s",
        ));
        report
    }

    fn uri(report: &Report, base: &Path) -> String {
        let out = sarif(report, &[("unwrap-in-entrypoint", "d")], base).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Code scanning resolves locations against the repository root. An absolute
    /// path from the machine that ran the checker resolves to nothing, and the
    /// annotation lands nowhere while the run still looks like it worked.
    #[test]
    fn a_location_is_written_relative_to_the_checkout() {
        let base = PathBuf::from("/home/runner/work/repo/repo");
        let report = report_at("/home/runner/work/repo/repo/contracts/src/lib.rs");
        assert_eq!(uri(&report, &base), "contracts/src/lib.rs");
    }

    #[test]
    fn a_leading_dot_slash_is_not_part_of_the_path() {
        let report = report_at("./src/lib.rs");
        assert_eq!(uri(&report, Path::new("")), "src/lib.rs");
    }

    #[test]
    fn a_path_outside_the_base_is_left_alone_rather_than_mangled() {
        let report = report_at("/elsewhere/src/lib.rs");
        assert_eq!(
            uri(&report, Path::new("/home/runner/work")),
            "/elsewhere/src/lib.rs"
        );
    }
}
