#![allow(clippy::doc_markdown)]
//! Logging for the Integration Tests
//!
//! Tests should start their own logging.
//!
//! To find tests that do not start their own logging:
//!
//! ´´´ sh
//! awk 'BEGIN{RS=""; FS="\n"} /#\[tokio::test\]\s*async\s+fn\s+\w+\s*\(\s*\)\s*\{[^}]*\}/ && !/#\[tokio::test\]\s*async\s+fn\s+\w+\s*\(\s*\)\s*\{[^}]*INIT\.call_once/' $(find . -name "*.rs")
//! ´´´
//!

use std::sync::Once;

use tracing::level_filters::LevelFilter;

#[allow(dead_code)]
pub static INIT: Once = Once::new();

#[allow(dead_code)]
pub fn tracing_stderr_init(_filter: LevelFilter) {
    /*let builder = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_ansi(true)
        .with_writer(std::io::stderr);

    builder.pretty().with_file(true).init();*/

    tracing::info!("Logging initialized");
}
