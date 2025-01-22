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
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use torrust_tracker_configuration::{AccessTokens, HttpApi};
use tracing::instrument;

use super::make_rust_tls;
use crate::core::statistics::event::sender::Sender;
use crate::core::statistics::repository::Repository;
use crate::core::whitelist::manager::WhiteListManager;
use crate::core::{self};
use crate::servers::apis::server::{ApiServer, Launcher};
use crate::servers::apis::Version;
use crate::servers::registar::ServiceRegistrationForm;
use crate::servers::udp::server::banning::BanService;

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
#[allow(clippy::too_many_arguments)]
#[instrument(skip(config, tracker, whitelist_manager, ban_service, stats_event_sender, stats_repository, form))]
pub async fn start_job(
    config: &HttpApi,
    tracker: Arc<core::Tracker>,
    whitelist_manager: Arc<WhiteListManager>,
    ban_service: Arc<RwLock<BanService>>,
    stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    stats_repository: Arc<Repository>,
    form: ServiceRegistrationForm,
    version: Version,
) -> Option<JoinHandle<()>> {
    let bind_to = config.bind_address;

    let tls = make_rust_tls(&config.tsl_config)
        .await
        .map(|tls| tls.expect("it should have a valid tracker api tls configuration"));

    let access_tokens = Arc::new(config.access_tokens.clone());

    match version {
        Version::V1 => Some(
            start_v1(
                bind_to,
                tls,
                tracker.clone(),
                whitelist_manager.clone(),
                ban_service.clone(),
                stats_event_sender.clone(),
                stats_repository.clone(),
                form,
                access_tokens,
            )
            .await,
        ),
    }
}

#[allow(clippy::async_yields_async)]
#[allow(clippy::too_many_arguments)]
#[instrument(skip(
    socket,
    tls,
    tracker,
    whitelist_manager,
    ban_service,
    stats_event_sender,
    stats_repository,
    form,
    access_tokens
))]
async fn start_v1(
    socket: SocketAddr,
    tls: Option<RustlsConfig>,
    tracker: Arc<core::Tracker>,
    whitelist_manager: Arc<WhiteListManager>,
    ban_service: Arc<RwLock<BanService>>,
    stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    stats_repository: Arc<Repository>,
    form: ServiceRegistrationForm,
    access_tokens: Arc<AccessTokens>,
) -> JoinHandle<()> {
    let server = ApiServer::new(Launcher::new(socket, tls))
        .start(
            tracker,
            whitelist_manager,
            stats_event_sender,
            stats_repository,
            ban_service,
            form,
            access_tokens,
        )
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

    use tokio::sync::RwLock;
    use torrust_tracker_test_helpers::configuration::ephemeral_public;

    use crate::bootstrap::app::initialize_global_services;
    use crate::bootstrap::jobs::tracker_apis::start_job;
    use crate::core::authentication::handler::KeysHandler;
    use crate::core::authentication::key::repository::in_memory::InMemoryKeyRepository;
    use crate::core::authentication::key::repository::persisted::DatabaseKeyRepository;
    use crate::core::authentication::service;
    use crate::core::services::{initialize_database, initialize_tracker, initialize_whitelist_manager, statistics};
    use crate::core::whitelist::repository::in_memory::InMemoryWhitelist;
    use crate::core::{authentication, whitelist};
    use crate::servers::apis::Version;
    use crate::servers::registar::Registar;
    use crate::servers::udp::server::banning::BanService;
    use crate::servers::udp::server::launcher::MAX_CONNECTION_ID_ERRORS_PER_IP;

    #[tokio::test]
    async fn it_should_start_http_tracker() {
        let cfg = Arc::new(ephemeral_public());
        let config = &cfg.http_api.clone().unwrap();

        let ban_service = Arc::new(RwLock::new(BanService::new(MAX_CONNECTION_ID_ERRORS_PER_IP)));
        let (stats_event_sender, stats_repository) = statistics::setup::factory(cfg.core.tracker_usage_statistics);
        let stats_event_sender = Arc::new(stats_event_sender);
        let stats_repository = Arc::new(stats_repository);

        initialize_global_services(&cfg);

        let database = initialize_database(&cfg);
        let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
        let whitelist_authorization = Arc::new(whitelist::authorization::Authorization::new(
            &cfg.core,
            &in_memory_whitelist.clone(),
        ));
        let whitelist_manager = initialize_whitelist_manager(database.clone(), in_memory_whitelist.clone());
        let db_key_repository = Arc::new(DatabaseKeyRepository::new(&database));
        let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());
        let authentication_service = Arc::new(service::Service::new(&cfg.core, &in_memory_key_repository));
        let keys_handler = Arc::new(KeysHandler::new(
            &db_key_repository.clone(),
            &in_memory_key_repository.clone(),
        ));
        let authentication = Arc::new(authentication::Facade::new(&authentication_service, &keys_handler));

        let tracker = Arc::new(initialize_tracker(&cfg, &database, &whitelist_authorization, &authentication));

        let version = Version::V1;

        start_job(
            config,
            tracker,
            whitelist_manager,
            ban_service,
            stats_event_sender,
            stats_repository,
            Registar::default().give_form(),
            version,
        )
        .await
        .expect("it should be able to join to the tracker api start-job");
    }
}
