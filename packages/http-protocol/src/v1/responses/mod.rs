//! HTTP responses for the HTTP tracker.
pub mod announce;
pub mod error;
pub mod scrape;

pub use announce::{Announce, Compact, Normal};
