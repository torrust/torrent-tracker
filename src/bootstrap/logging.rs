//! Setup for the application logging.
//!
//! It redirects the log info to the standard output with the log threshold
//! defined in the configuration.
//!
//! - `Off`
//! - `Error`
//! - `Warn`
//! - `Info`
//! - `Debug`
//! - `Trace`
//!
//! Refer to the [configuration crate documentation](https://docs.rs/torrust-tracker-configuration) to know how to change log settings.
use std::sync::Once;

use torrust_tracker_configuration::{Configuration, Threshold};
use tracing::level_filters::LevelFilter;

static INIT: Once = Once::new();

/// It redirects the log info to the standard output with the log threshold
/// defined in the configuration.
pub fn setup(cfg: &Configuration) {
    let tracing_level = map_to_tracing_level_filter(&cfg.logging.threshold);

    if tracing_level == LevelFilter::OFF {
        return;
    }

    INIT.call_once(|| {
        tracing_stdout_init(tracing_level, &TraceStyle::Default);
    });
}

fn map_to_tracing_level_filter(threshold: &Threshold) -> LevelFilter {
    match threshold {
        Threshold::Off => LevelFilter::OFF,
        Threshold::Error => LevelFilter::ERROR,
        Threshold::Warn => LevelFilter::WARN,
        Threshold::Info => LevelFilter::INFO,
        Threshold::Debug => LevelFilter::DEBUG,
        Threshold::Trace => LevelFilter::TRACE,
    }
}

fn tracing_stdout_init(filter: LevelFilter, style: &TraceStyle) {
    let builder = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_ansi(true)
        .with_test_writer();

    let () = match style {
        TraceStyle::Default => builder.init(),
        TraceStyle::Pretty(display_filename) => builder.pretty().with_file(*display_filename).init(),
        TraceStyle::Compact => builder.compact().init(),
        TraceStyle::Json => builder.json().init(),
    };

    tracing::info!("Logging initialized");
}

#[derive(Debug)]
pub enum TraceStyle {
    Default,
    Pretty(bool),
    Compact,
    Json,
}

impl std::fmt::Display for TraceStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let style = match self {
            TraceStyle::Default => "Default Style",
            TraceStyle::Pretty(path) => match path {
                true => "Pretty Style with File Paths",
                false => "Pretty Style without File Paths",
            },
            TraceStyle::Compact => "Compact Style",
            TraceStyle::Json => "Json Format",
        };

        f.write_str(style)
    }
}
