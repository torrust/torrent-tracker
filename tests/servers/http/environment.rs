use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use futures::executor::block_on;
use torrust_tracker_configuration::{Configuration, Core, HttpTracker};
use torrust_tracker_lib::bootstrap::app::{initialize_app_container, initialize_global_services};
use torrust_tracker_lib::bootstrap::jobs::make_rust_tls;
use torrust_tracker_lib::core::announce_handler::AnnounceHandler;
use torrust_tracker_lib::core::authentication::handler::KeysHandler;
use torrust_tracker_lib::core::authentication::service::AuthenticationService;
use torrust_tracker_lib::core::databases::Database;
use torrust_tracker_lib::core::scrape_handler::ScrapeHandler;
use torrust_tracker_lib::core::statistics::event::sender::Sender;
use torrust_tracker_lib::core::statistics::repository::Repository;
use torrust_tracker_lib::core::torrent::repository::in_memory::InMemoryTorrentRepository;
use torrust_tracker_lib::core::whitelist;
use torrust_tracker_lib::core::whitelist::manager::WhitelistManager;
use torrust_tracker_lib::servers::http::server::{HttpServer, Launcher, Running, Stopped};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_primitives::peer;

pub struct Environment<S> {
    pub core_config: Arc<Core>,
    pub http_tracker_config: Arc<HttpTracker>,
    pub database: Arc<Box<dyn Database>>,
    pub announce_handler: Arc<AnnounceHandler>,
    pub scrape_handler: Arc<ScrapeHandler>,
    pub in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,
    pub keys_handler: Arc<KeysHandler>,
    pub authentication_service: Arc<AuthenticationService>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
    pub whitelist_authorization: Arc<whitelist::authorization::WhitelistAuthorization>,
    pub whitelist_manager: Arc<WhitelistManager>,
    pub registar: Registar,
    pub server: HttpServer<S>,
}

impl<S> Environment<S> {
    /// Add a torrent to the tracker
    pub fn add_torrent_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        let () = self.in_memory_torrent_repository.upsert_peer(info_hash, peer);
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
            http_tracker_config: config,
            core_config: Arc::new(configuration.core.clone()),
            database: app_container.database.clone(),
            announce_handler: app_container.announce_handler.clone(),
            scrape_handler: app_container.scrape_handler.clone(),
            in_memory_torrent_repository: app_container.in_memory_torrent_repository.clone(),
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
            http_tracker_config: self.http_tracker_config,
            core_config: self.core_config.clone(),
            database: self.database.clone(),
            announce_handler: self.announce_handler.clone(),
            scrape_handler: self.scrape_handler.clone(),
            in_memory_torrent_repository: self.in_memory_torrent_repository.clone(),
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
                    self.core_config,
                    self.announce_handler,
                    self.scrape_handler,
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
            http_tracker_config: self.http_tracker_config,
            core_config: self.core_config,
            database: self.database,
            announce_handler: self.announce_handler,
            scrape_handler: self.scrape_handler,
            in_memory_torrent_repository: self.in_memory_torrent_repository,
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
