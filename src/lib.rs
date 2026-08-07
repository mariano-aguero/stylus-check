//! Static security checks for Arbitrum Stylus contracts.
//!
//! This is a heuristic tool, not an audit. It reads source and recognises
//! patterns; it does not prove anything, and a clean run means only that these
//! particular rules found nothing to say.

#![forbid(unsafe_code)]

pub mod config;
pub mod discover;
pub mod finding;
pub mod model;
pub mod render;
pub mod rules;
pub mod run;
