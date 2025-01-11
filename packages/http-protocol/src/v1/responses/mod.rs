//! HTTP responses for the HTTP tracker.
//!
//! Refer to the generic [HTTP server documentation](crate::servers::http) for
//! more information about the HTTP tracker.
pub mod announce;
pub mod error;
pub mod scrape;

pub use announce::{Announce, Compact, Normal};
