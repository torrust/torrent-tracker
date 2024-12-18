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

use std::io;
use std::sync::{Arc, Mutex, Once};

use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

#[allow(dead_code)]
pub static INIT: Once = Once::new();

#[allow(dead_code)]
pub fn tracing_stderr_init(filter: LevelFilter) {
    let builder = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_ansi(true)
        .with_writer(std::io::stderr);

    builder.pretty().with_file(true).init();

    tracing::info!("Logging initialized");
}

#[allow(dead_code)]
pub fn tracing_init_with_capturer(filter: LevelFilter, log_capturer: Arc<Mutex<LogCapturer>>) {
    let writer = LogCapturerWrapper::new(log_capturer);

    let builder = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_ansi(true)
        .with_writer(writer);

    builder.pretty().with_file(true).init();

    tracing::info!("Logging initialized");
}

pub struct LogCapturerWrapper {
    inner: Arc<Mutex<LogCapturer>>,
}

impl LogCapturerWrapper {
    pub fn new(inner: Arc<Mutex<LogCapturer>>) -> Self {
        Self { inner }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapturerWrapper {
    type Writer = LogCapturerGuard;

    fn make_writer(&'a self) -> Self::Writer {
        LogCapturerGuard {
            inner: self.inner.clone(),
        }
    }
}

pub struct LogCapturerGuard {
    inner: Arc<Mutex<LogCapturer>>,
}

impl io::Write for LogCapturerGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut capturer = self.inner.lock().unwrap();
        capturer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut capturer = self.inner.lock().unwrap();
        capturer.flush()
    }
}

#[derive(Debug, Default)]
pub struct LogCapturer {
    output: String,
}

impl LogCapturer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, message: &str) -> bool {
        self.output.contains(message)
    }
}

impl io::Write for LogCapturer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let out_str = String::from_utf8_lossy(buf);

        // We print to stdout so that the output is visible in the terminal
        // when you run the tests with `cargo test -- --nocapture`.
        println!("{out_str}");

        self.output.push_str(&out_str);

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogCapturer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        Self::default()
    }
}
