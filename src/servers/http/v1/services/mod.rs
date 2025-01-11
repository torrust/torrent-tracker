//! Application services for the HTTP tracker.
//!
//! These modules contain logic that is specific for the HTTP tracker but it
//! does depend on the Axum web server. It could be reused for other web
//! servers.
//!
//! Refer to [`torrust_tracker`](crate) documentation.
pub mod announce;
pub mod scrape;
