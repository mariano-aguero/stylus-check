//! The command line.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use stylus_check::config::Config;
use stylus_check::finding::Severity;
use stylus_check::render::{self, Format};
use stylus_check::rules;
use stylus_check::run;

/// Exit codes, because a script will read them.
const FOUND_SOMETHING: u8 = 1;
const COULD_NOT_RUN: u8 = 2;

/// The one rule that reads text rather than syntax, so it is not in the registry.
const DEPRECATED_GUARD_DOC: (&str, &str, &str) = (
    "deprecated-reentrancy-guard",
    "medium",
    "the SDK guard that was deprecated in 0.10.5",
);

#[derive(Parser)]
#[command(
    name = "stylus-check",
    version,
    about = "Static security checks for Arbitrum Stylus contracts",
    long_about = "Reads stylus-sdk contract source and reports patterns that tend to cost money.\n\
                  These are heuristics, not an audit: a quiet run means these rules found nothing."
)]
struct Cli {
    /// Directory or file to check.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// How to print the findings.
    #[arg(long, default_value = "text")]
    format: String,

    /// The lowest severity that makes the run fail.
    #[arg(long, default_value = "medium")]
    fail_on: String,

    /// List the rules and what each one is for, then stop.
    #[arg(long)]
    explain: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.explain {
        for rule in rules::all() {
            println!(
                "{:<28} {:<7} {}",
                rule.id(),
                rule.severity().as_str(),
                rule.description()
            );
        }
        let (id, severity, description) = DEPRECATED_GUARD_DOC;
        println!("{id:<28} {severity:<7} {description}");
        return ExitCode::SUCCESS;
    }

    let Some(format) = Format::parse(&cli.format) else {
        eprintln!("unknown format `{}`. Pick text, json or sarif.", cli.format);
        return ExitCode::from(COULD_NOT_RUN);
    };
    let Some(threshold) = Severity::parse(&cli.fail_on) else {
        eprintln!(
            "unknown severity `{}`. Pick low, medium or high.",
            cli.fail_on
        );
        return ExitCode::from(COULD_NOT_RUN);
    };

    let known = run::rule_ids();
    let config = match Config::load(&cli.path, &known) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(COULD_NOT_RUN);
        }
    };

    let report = match run::check(&cli.path, &config) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(COULD_NOT_RUN);
        }
    };

    let descriptions: Vec<(&str, &str)> = rules::all()
        .iter()
        .map(|r| (r.id(), r.description()))
        .chain(std::iter::once((
            DEPRECATED_GUARD_DOC.0,
            DEPRECATED_GUARD_DOC.2,
        )))
        .collect();

    let rendered = match format {
        Format::Text => Ok(render::text(&report, threshold)),
        Format::Json => render::json(&report),
        // Relative to where the checker was run, which in CI is the checkout
        // root, so code scanning can resolve each location to a real file.
        Format::Sarif => {
            let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            render::sarif(&report, &descriptions, &base)
        }
    };
    match rendered {
        Ok(text) => print!("{text}"),
        Err(err) => {
            eprintln!("could not render the report: {err}");
            return ExitCode::from(COULD_NOT_RUN);
        }
    }

    if report.at_or_above(threshold).next().is_some() {
        ExitCode::from(FOUND_SOMETHING)
    } else {
        ExitCode::SUCCESS
    }
}
