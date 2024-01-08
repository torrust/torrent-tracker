//! Tracker API job starter.
//!
//! The [`tracker_apis::start_job`](crate::bootstrap::jobs::tracker_apis::start_job)
//! function starts a the HTTP tracker REST API.
//!
//! > **NOTICE**: that even thought there is only one job the API has different
//! versions. API consumers can choose which version to use. The API version is
//! part of the URL, for example: `http://localhost:1212/api/v1/stats`.
//!
//! The [`tracker_apis::start_job`](crate::bootstrap::jobs::tracker_apis::start_job)  
//! function spawns a new asynchronous task, that tasks is the "**launcher**".
//! The "**launcher**" starts the actual server and sends a message back
//! to the main application. The main application waits until receives
//! the message [`ApiServerJobStarted`]
//! from the "**launcher**".
//!
//! The "**launcher**" is an intermediary thread that decouples the API server
//! from the process that handles it. The API could be used independently
//! in the future. In that case it would not need to notify a parent process.
//!
//! Refer to the [configuration documentation](https://docs.rs/torrust-tracker-configuration)
//! for the API configuration options.
use std::net::SocketAddr;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use log::info;
use tokio::task::JoinHandle;
use torrust_tracker_configuration::HttpApi;

use super::make_rust_tls;
use crate::core;
use crate::servers::apis::server::{ApiServer, Launcher};
use crate::servers::apis::Version;

/// This is the message that the "launcher" spawned task sends to the main
/// application process to notify the API server was successfully started.
///
/// > **NOTICE**: it does not mean the API server is ready to receive requests.
/// It only means the new server started. It might take some time to the server
/// to be ready to accept request.
#[derive(Debug)]
pub struct ApiServerJobStarted();

/// This function starts a new API server with the provided configuration.
///
/// The functions starts a new concurrent task that will run the API server.
/// This task will send a message to the main application process to notify
/// that the API server was successfully started.
///
/// # Panics
///
/// It would panic if unable to send the  `ApiServerJobStarted` notice.
///
///
pub async fn start_job(config: &HttpApi, tracker: Arc<core::Tracker>, version: Version) -> Option<JoinHandle<()>> {
    if config.enabled {
        let bind_to = config
            .bind_address
            .parse::<std::net::SocketAddr>()
            .expect("it should have a valid tracker api bind address");

        let tls = make_rust_tls(config.ssl_enabled, &config.ssl_cert_path, &config.ssl_key_path)
            .await
            .map(|tls| tls.expect("it should have a valid tracker api tls configuration"));

        match version {
            Version::V1 => Some(start_v1(bind_to, tls, tracker.clone()).await),
        }
    } else {
        info!("Note: Not loading Http Tracker Service, Not Enabled in Configuration.");
        None
    }
}

async fn start_v1(socket: SocketAddr, tls: Option<RustlsConfig>, tracker: Arc<core::Tracker>) -> JoinHandle<()> {
    let server = ApiServer::new(Launcher::new(socket, tls))
        .start(tracker)
        .await
        .expect("it should be able to start to the tracker api");

    tokio::spawn(async move {
        server.state.task.await.expect("failed to close service");
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrust_tracker_test_helpers::configuration::ephemeral_mode_public;

    use crate::bootstrap::app::initialize_with_configuration;
    use crate::bootstrap::jobs::tracker_apis::start_job;
    use crate::servers::apis::Version;

    #[tokio::test]
    async fn it_should_start_http_tracker() {
        let cfg = Arc::new(ephemeral_mode_public());
        let config = &cfg.http_api;
        let tracker = initialize_with_configuration(&cfg);
        let version = Version::V1;

        start_job(config, tracker, version)
            .await
            .expect("it should be able to join to the tracker api start-job");
    }
}
