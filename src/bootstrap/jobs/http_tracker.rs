//! HTTP tracker job starter.
//!
//! The function [`http_tracker::start_job`](crate::bootstrap::jobs::http_tracker::start_job) starts a new HTTP tracker server.
//!
//! > **NOTICE**: the application can launch more than one HTTP tracker on different ports.
//! > Refer to the [configuration documentation](https://docs.rs/torrust-tracker-configuration) for the configuration options.
//!
//! The [`http_tracker::start_job`](crate::bootstrap::jobs::http_tracker::start_job) function spawns a new asynchronous task,
//! that tasks is the "**launcher**". The "**launcher**" starts the actual server and sends a message back to the main application.
//!
//! The "**launcher**" is an intermediary thread that decouples the HTTP servers from the process that handles it. The HTTP could be used independently in the future.
//! In that case it would not need to notify a parent process.
use std::net::SocketAddr;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use tokio::task::JoinHandle;
use torrust_tracker_configuration::HttpTracker;
use tracing::instrument;

use super::make_rust_tls;
use crate::core::statistics::event::sender::Sender;
use crate::core::{self, statistics};
use crate::servers::http::server::{HttpServer, Launcher};
use crate::servers::http::Version;
use crate::servers::registar::ServiceRegistrationForm;

/// It starts a new HTTP server with the provided configuration and version.
///
/// Right now there is only one version but in the future we could support more than one HTTP tracker version at the same time.
/// This feature allows supporting breaking changes on `BitTorrent` BEPs.
///
/// # Panics
///
/// It would panic if the `config::HttpTracker` struct would contain inappropriate values.
///
#[instrument(skip(config, tracker, stats_event_sender, form))]
pub async fn start_job(
    config: &HttpTracker,
    tracker: Arc<core::Tracker>,
    stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    form: ServiceRegistrationForm,
    version: Version,
) -> Option<JoinHandle<()>> {
    let socket = config.bind_address;

    let tls = make_rust_tls(&config.tsl_config)
        .await
        .map(|tls| tls.expect("it should have a valid http tracker tls configuration"));

    match version {
        Version::V1 => Some(start_v1(socket, tls, tracker.clone(), stats_event_sender.clone(), form).await),
    }
}

#[allow(clippy::async_yields_async)]
#[instrument(skip(socket, tls, tracker, stats_event_sender, form))]
async fn start_v1(
    socket: SocketAddr,
    tls: Option<RustlsConfig>,
    tracker: Arc<core::Tracker>,
    stats_event_sender: Arc<Option<Box<dyn statistics::event::sender::Sender>>>,
    form: ServiceRegistrationForm,
) -> JoinHandle<()> {
    let server = HttpServer::new(Launcher::new(socket, tls))
        .start(tracker, stats_event_sender, form)
        .await
        .expect("it should be able to start to the http tracker");

    tokio::spawn(async move {
        assert!(
            !server.state.halt_task.is_closed(),
            "Halt channel for HTTP tracker should be open"
        );
        server
            .state
            .task
            .await
            .expect("it should be able to join to the http tracker task");
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrust_tracker_test_helpers::configuration::ephemeral_public;

    use crate::bootstrap::app::initialize_global_services;
    use crate::bootstrap::jobs::http_tracker::start_job;
    use crate::core::services::{initialize_database, initialize_whitelist, statistics, tracker_factory};
    use crate::servers::http::Version;
    use crate::servers::registar::Registar;

    #[tokio::test]
    async fn it_should_start_http_tracker() {
        let cfg = Arc::new(ephemeral_public());
        let http_tracker = cfg.http_trackers.clone().expect("missing HTTP tracker configuration");
        let config = &http_tracker[0];

        let (stats_event_sender, _stats_repository) = statistics::setup::factory(cfg.core.tracker_usage_statistics);
        let stats_event_sender = Arc::new(stats_event_sender);

        initialize_global_services(&cfg);

        let database = initialize_database(&cfg);
        let whitelist_manager = initialize_whitelist(database.clone());
        let tracker = Arc::new(tracker_factory(&cfg, &database, &whitelist_manager));

        let version = Version::V1;

        start_job(config, tracker, stats_event_sender, Registar::default().give_form(), version)
            .await
            .expect("it should be able to join to the http tracker start-job");
    }
}
