use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use futures::executor::block_on;
use torrust_tracker_configuration::{Configuration, HttpTracker};
use torrust_tracker_lib::bootstrap::app::{initialize_app_container, initialize_global_services};
use torrust_tracker_lib::bootstrap::jobs::make_rust_tls;
use torrust_tracker_lib::core::authentication::handler::KeysHandler;
use torrust_tracker_lib::core::authentication::service::AuthenticationService;
use torrust_tracker_lib::core::statistics::event::sender::Sender;
use torrust_tracker_lib::core::statistics::repository::Repository;
use torrust_tracker_lib::core::whitelist::manager::WhiteListManager;
use torrust_tracker_lib::core::{whitelist, Tracker};
use torrust_tracker_lib::servers::http::server::{HttpServer, Launcher, Running, Stopped};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_primitives::peer;

pub struct Environment<S> {
    pub config: Arc<HttpTracker>,
    pub tracker: Arc<Tracker>,
    pub keys_handler: Arc<KeysHandler>,
    pub authentication_service: Arc<AuthenticationService>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
    pub whitelist_authorization: Arc<whitelist::authorization::Authorization>,
    pub whitelist_manager: Arc<WhiteListManager>,
    pub registar: Registar,
    pub server: HttpServer<S>,
}

impl<S> Environment<S> {
    /// Add a torrent to the tracker
    pub fn add_torrent_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let _ = self.tracker.upsert_peer_and_get_stats(info_hash, peer);
    }
}

impl Environment<Stopped> {
    #[allow(dead_code)]
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        initialize_global_services(configuration);

        let app_container = initialize_app_container(configuration);

        let http_tracker = configuration
            .http_trackers
            .clone()
            .expect("missing HTTP tracker configuration");

        let config = Arc::new(http_tracker[0].clone());

        let bind_to = config.bind_address;

        let tls = block_on(make_rust_tls(&config.tsl_config)).map(|tls| tls.expect("tls config failed"));

        let server = HttpServer::new(Launcher::new(bind_to, tls));

        Self {
            config,
            tracker: app_container.tracker.clone(),
            keys_handler: app_container.keys_handler.clone(),
            authentication_service: app_container.authentication_service.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            stats_repository: app_container.stats_repository.clone(),
            whitelist_authorization: app_container.whitelist_authorization.clone(),
            whitelist_manager: app_container.whitelist_manager.clone(),
            registar: Registar::default(),
            server,
        }
    }

    #[allow(dead_code)]
    pub async fn start(self) -> Environment<Running> {
        Environment {
            config: self.config,
            tracker: self.tracker.clone(),
            keys_handler: self.keys_handler.clone(),
            authentication_service: self.authentication_service.clone(),
            whitelist_authorization: self.whitelist_authorization.clone(),
            stats_event_sender: self.stats_event_sender.clone(),
            stats_repository: self.stats_repository.clone(),
            whitelist_manager: self.whitelist_manager.clone(),
            registar: self.registar.clone(),
            server: self
                .server
                .start(
                    self.tracker,
                    self.authentication_service,
                    self.whitelist_authorization,
                    self.stats_event_sender,
                    self.registar.give_form(),
                )
                .await
                .unwrap(),
        }
    }
}

impl Environment<Running> {
    pub async fn new(configuration: &Arc<Configuration>) -> Self {
        Environment::<Stopped>::new(configuration).start().await
    }

    pub async fn stop(self) -> Environment<Stopped> {
        Environment {
            config: self.config,
            tracker: self.tracker,
            keys_handler: self.keys_handler,
            authentication_service: self.authentication_service,
            whitelist_authorization: self.whitelist_authorization,
            stats_event_sender: self.stats_event_sender,
            stats_repository: self.stats_repository,
            whitelist_manager: self.whitelist_manager,
            registar: Registar::default(),

            server: self.server.stop().await.unwrap(),
        }
    }

    pub fn bind_address(&self) -> &std::net::SocketAddr {
        &self.server.state.binding
    }
}
