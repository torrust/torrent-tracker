//! Tracker API job starter.
//!
//! The [`tracker_apis::start_job`](crate::bootstrap::jobs::tracker_apis::start_job)
//! function starts a the HTTP tracker REST API.
//!
//! > **NOTICE**: that even thought there is only one job the API has different
//! > versions. API consumers can choose which version to use. The API version is
//! > part of the URL, for example: `http://localhost:1212/api/v1/stats`.
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
use tokio::task::JoinHandle;
use torrust_tracker_configuration::AccessTokens;
use tracing::instrument;

use super::make_rust_tls;
use crate::container::HttpApiContainer;
use crate::servers::apis::server::{ApiServer, Launcher};
use crate::servers::apis::Version;
use crate::servers::registar::ServiceRegistrationForm;

/// This is the message that the "launcher" spawned task sends to the main
/// application process to notify the API server was successfully started.
///
/// > **NOTICE**: it does not mean the API server is ready to receive requests.
/// > It only means the new server started. It might take some time to the server
/// > to be ready to accept request.
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
#[instrument(skip(http_api_container, form))]
pub async fn start_job(
    http_api_container: Arc<HttpApiContainer>,
    form: ServiceRegistrationForm,
    version: Version,
) -> Option<JoinHandle<()>> {
    let bind_to = http_api_container.http_api_config.bind_address;

    let tls = make_rust_tls(&http_api_container.http_api_config.tsl_config)
        .await
        .map(|tls| tls.expect("it should have a valid tracker api tls configuration"));

    let access_tokens = Arc::new(http_api_container.http_api_config.access_tokens.clone());

    match version {
        Version::V1 => Some(start_v1(bind_to, tls, http_api_container, form, access_tokens).await),
    }
}

#[allow(clippy::async_yields_async)]
#[instrument(skip(socket, tls, http_api_container, form, access_tokens))]
async fn start_v1(
    socket: SocketAddr,
    tls: Option<RustlsConfig>,
    http_api_container: Arc<HttpApiContainer>,
    form: ServiceRegistrationForm,
    access_tokens: Arc<AccessTokens>,
) -> JoinHandle<()> {
    let server = ApiServer::new(Launcher::new(socket, tls))
        .start(http_api_container, form, access_tokens)
        .await
        .expect("it should be able to start to the tracker api");

    tokio::spawn(async move {
        assert!(!server.state.halt_task.is_closed(), "Halt channel should be open");
        server.state.task.await.expect("failed to close service");
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrust_tracker_test_helpers::configuration::ephemeral_public;

    use crate::bootstrap::app::{initialize_app_container, initialize_global_services};
    use crate::bootstrap::jobs::tracker_apis::start_job;
    use crate::container::HttpApiContainer;
    use crate::servers::apis::Version;
    use crate::servers::registar::Registar;

    #[tokio::test]
    async fn it_should_start_http_tracker() {
        let cfg = Arc::new(ephemeral_public());
        let http_api_config = Arc::new(cfg.http_api.clone().unwrap());

        initialize_global_services(&cfg);

        let app_container = Arc::new(initialize_app_container(&cfg));

        let http_api_container = Arc::new(HttpApiContainer::from_app_container(&http_api_config, &app_container));

        let version = Version::V1;

        start_job(http_api_container, Registar::default().give_form(), version)
            .await
            .expect("it should be able to join to the tracker api start-job");
    }
}
