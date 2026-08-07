//! What the checker reports, and how badly it wants your attention.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// How much a finding should worry you.
///
/// The scale is about consequence, not confidence. A rule only reports at all
/// when it is fairly sure, so a low severity finding is a real observation
/// about code that probably still works, not a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, unlikely to cost money on its own.
    Low,
    /// Can cost money given the wrong caller or the wrong token.
    Medium,
    /// Can lose funds or brick the contract.
    High,
}

impl Severity {
    /// The name used on the command line and in config files.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    /// Parses a severity written by a human, in any case.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            _ => None,
        }
    }
}

/// A single thing worth looking at, always tied to a place in a file.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. `unwrap-in-entrypoint`. Config files key on it.
    pub rule: &'static str,
    pub severity: Severity,
    pub file: PathBuf,
    /// One based, so it matches what an editor shows.
    pub line: usize,
    /// One based.
    pub column: usize,
    /// What is wrong, in one sentence, naming the specific code.
    pub message: String,
    /// What to do instead. Never a rewrite, only a direction.
    pub suggestion: String,
}

impl Finding {
    pub fn new(
        rule: &'static str,
        severity: Severity,
        file: &Path,
        line: usize,
        column: usize,
        message: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            severity,
            file: file.to_path_buf(),
            line,
            column,
            message: message.into(),
            suggestion: suggestion.into(),
        }
    }
}

/// A file that could not be parsed, kept so the run can report it and move on.
///
/// One bad file must never stop the others from being checked: a checker that
/// gives up on the first syntax error is a checker nobody runs mid refactor.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedFile {
    pub file: PathBuf,
    pub reason: String,
}

/// Everything one run produced.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedFile>,
    /// How many files were parsed and checked.
    pub files_checked: usize,
}

impl Report {
    /// The findings at or above a threshold, which is what decides the exit code.
    pub fn at_or_above(&self, threshold: Severity) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(move |f| f.severity >= threshold)
    }

    /// Sorts by severity first, then by position, so the worst is read first
    /// and two runs over unchanged code print the same thing.
    pub fn sort(&mut self) {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.column.cmp(&b.column))
                .then_with(|| a.rule.cmp(b.rule))
        });
        self.skipped.sort_by(|a, b| a.file.cmp(&b.file));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_by_consequence() {
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn severity_parses_what_a_human_would_write() {
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse(" med "), Some(Severity::Medium));
        assert_eq!(Severity::parse("critical"), None);
    }

    #[test]
    fn the_worst_finding_is_reported_first() {
        let file = Path::new("a.rs");
        let mut report = Report::default();
        report
            .findings
            .push(Finding::new("b", Severity::Low, file, 1, 1, "m", "s"));
        report
            .findings
            .push(Finding::new("a", Severity::High, file, 9, 1, "m", "s"));
        report.sort();
        assert_eq!(report.findings[0].rule, "a");
    }

    #[test]
    fn the_threshold_decides_what_counts() {
        let file = Path::new("a.rs");
        let mut report = Report::default();
        report
            .findings
            .push(Finding::new("b", Severity::Low, file, 1, 1, "m", "s"));
        report
            .findings
            .push(Finding::new("a", Severity::High, file, 9, 1, "m", "s"));
        assert_eq!(report.at_or_above(Severity::High).count(), 1);
        assert_eq!(report.at_or_above(Severity::Low).count(), 2);
    }
}
