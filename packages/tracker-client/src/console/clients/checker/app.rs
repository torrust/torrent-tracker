//! Program to run checks against running trackers.
//!
//! Run providing a config file path:
//!
//! ```text
//! cargo run --bin tracker_checker -- --config-path "./share/default/config/tracker_checker.json"
//! TORRUST_CHECKER_CONFIG_PATH="./share/default/config/tracker_checker.json" cargo run --bin tracker_checker
//! ```
//!
//! Run providing the configuration:
//!
//! ```text
//! TORRUST_CHECKER_CONFIG=$(cat "./share/default/config/tracker_checker.json") cargo run --bin tracker_checker
//! ```
//!
//! Another real example to test the Torrust demo tracker:
//!
//! ```text
//! TORRUST_CHECKER_CONFIG='{
//!     "udp_trackers": ["144.126.245.19:6969"],
//!     "http_trackers": ["https://tracker.torrust-demo.com"],
//!     "health_checks": ["https://tracker.torrust-demo.com/api/health_check"]
//! }' cargo run --bin tracker_checker
//! ```
//!
//! The output should be something like the following:
//!
//! ```json
//! {
//!   "udp_trackers": [
//!     {
//!       "url": "144.126.245.19:6969",
//!       "status": {
//!         "code": "ok",
//!         "message": ""
//!       }
//!     }
//!   ],
//!   "http_trackers": [
//!     {
//!       "url": "https://tracker.torrust-demo.com/",
//!       "status": {
//!         "code": "ok",
//!         "message": ""
//!       }
//!     }
//!   ],
//!   "health_checks": [
//!     {
//!       "url": "https://tracker.torrust-demo.com/api/health_check",
//!       "status": {
//!         "code": "ok",
//!         "message": ""
//!       }
//!     }
//!   ]
//! }
//! ```
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::level_filters::LevelFilter;

use super::config::Configuration;
use super::console::Console;
use super::service::{CheckResult, Service};
use crate::console::clients::checker::config::parse_from_json;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the JSON configuration file.
    #[clap(short, long, env = "TORRUST_CHECKER_CONFIG_PATH")]
    config_path: Option<PathBuf>,

    /// Direct configuration content in JSON.
    #[clap(env = "TORRUST_CHECKER_CONFIG", hide_env_values = true)]
    config_content: Option<String>,
}

/// # Errors
///
/// Will return an error if the configuration was not provided.
pub async fn run() -> Result<Vec<CheckResult>> {
    tracing_stdout_init(LevelFilter::INFO);

    let args = Args::parse();

    let config = setup_config(args)?;

    let console_printer = Console {};

    let service = Service {
        config: Arc::new(config),
        console: console_printer,
    };

    service.run_checks().await.context("it should run the check tasks")
}

fn tracing_stdout_init(filter: LevelFilter) {
    tracing_subscriber::fmt().with_max_level(filter).init();
    tracing::debug!("Logging initialized");
}

fn setup_config(args: Args) -> Result<Configuration> {
    match (args.config_path, args.config_content) {
        (Some(config_path), _) => load_config_from_file(&config_path),
        (_, Some(config_content)) => parse_from_json(&config_content).context("invalid config format"),
        _ => Err(anyhow::anyhow!("no configuration provided")),
    }
}

fn load_config_from_file(path: &PathBuf) -> Result<Configuration> {
    let file_content = std::fs::read_to_string(path).with_context(|| format!("can't read config file {path:?}"))?;

    parse_from_json(&file_content).context("invalid config format")
}
