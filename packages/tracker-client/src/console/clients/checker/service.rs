use std::sync::Arc;

use futures::FutureExt as _;
use serde::Serialize;
use tokio::task::{JoinError, JoinSet};
use torrust_tracker_configuration::DEFAULT_TIMEOUT;

use super::checks::{health, http, udp};
use super::config::Configuration;
use super::console::Console;
use crate::console::clients::checker::printer::Printer;

pub struct Service {
    pub(crate) config: Arc<Configuration>,
    pub(crate) console: Console,
}

#[derive(Debug, Clone, Serialize)]
pub enum CheckResult {
    Udp(Result<udp::Checks, udp::Checks>),
    Http(Result<http::Checks, http::Checks>),
    Health(Result<health::Checks, health::Checks>),
}

impl Service {
    /// # Errors
    ///
    /// It will return an error if some of the tests panic or otherwise fail to run.
    /// On success it will return a vector of `Ok(())` of [`CheckResult`].
    ///
    /// # Panics
    ///
    /// It would panic if `serde_json` produces invalid json for the `to_string_pretty` function.
    pub async fn run_checks(self) -> Result<Vec<CheckResult>, JoinError> {
        tracing::info!("Running checks for trackers ...");

        let mut check_results = Vec::default();

        let mut checks = JoinSet::new();
        checks.spawn(
            udp::run(self.config.udp_trackers.clone(), DEFAULT_TIMEOUT).map(|mut f| f.drain(..).map(CheckResult::Udp).collect()),
        );
        checks.spawn(
            http::run(self.config.http_trackers.clone(), DEFAULT_TIMEOUT)
                .map(|mut f| f.drain(..).map(CheckResult::Http).collect()),
        );
        checks.spawn(
            health::run(self.config.health_checks.clone(), DEFAULT_TIMEOUT)
                .map(|mut f| f.drain(..).map(CheckResult::Health).collect()),
        );

        while let Some(results) = checks.join_next().await {
            check_results.append(&mut results?);
        }

        let json_output = serde_json::json!(check_results);
        self.console
            .println(&serde_json::to_string_pretty(&json_output).expect("it should consume valid json"));

        Ok(check_results)
    }
}
