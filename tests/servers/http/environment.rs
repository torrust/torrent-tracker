use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use bittorrent_tracker_core::authentication::handler::KeysHandler;
use bittorrent_tracker_core::databases::Database;
use bittorrent_tracker_core::torrent::repository::in_memory::InMemoryTorrentRepository;
use bittorrent_tracker_core::whitelist::manager::WhitelistManager;
use futures::executor::block_on;
use packages::statistics::repository::Repository;
use torrust_tracker_configuration::Configuration;
use torrust_tracker_lib::bootstrap::app::{initialize_app_container, initialize_global_services};
use torrust_tracker_lib::bootstrap::jobs::make_rust_tls;
use torrust_tracker_lib::container::HttpTrackerContainer;
use torrust_tracker_lib::packages;
use torrust_tracker_lib::servers::http::server::{HttpServer, Launcher, Running, Stopped};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_primitives::peer;

pub struct Environment<S> {
    pub http_tracker_container: Arc<HttpTrackerContainer>,

    pub database: Arc<Box<dyn Database>>,
    pub in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,
    pub keys_handler: Arc<KeysHandler>,
    pub stats_repository: Arc<Repository>,
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
        let http_tracker_config = Arc::new(http_tracker[0].clone());

        let bind_to = http_tracker_config.bind_address;

        let tls = block_on(make_rust_tls(&http_tracker_config.tsl_config)).map(|tls| tls.expect("tls config failed"));

        let server = HttpServer::new(Launcher::new(bind_to, tls));

        let http_tracker_container = Arc::new(HttpTrackerContainer {
            core_config: app_container.core_config.clone(),
            http_tracker_config: http_tracker_config.clone(),
            announce_handler: app_container.announce_handler.clone(),
            scrape_handler: app_container.scrape_handler.clone(),
            whitelist_authorization: app_container.whitelist_authorization.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            authentication_service: app_container.authentication_service.clone(),
        });

        Self {
            http_tracker_container,

            database: app_container.database.clone(),
            in_memory_torrent_repository: app_container.in_memory_torrent_repository.clone(),
            keys_handler: app_container.keys_handler.clone(),
            stats_repository: app_container.stats_repository.clone(),
            whitelist_manager: app_container.whitelist_manager.clone(),

            registar: Registar::default(),
            server,
        }
    }

    #[allow(dead_code)]
    pub async fn start(self) -> Environment<Running> {
        Environment {
            http_tracker_container: self.http_tracker_container.clone(),

            database: self.database.clone(),
            in_memory_torrent_repository: self.in_memory_torrent_repository.clone(),
            keys_handler: self.keys_handler.clone(),
            stats_repository: self.stats_repository.clone(),
            whitelist_manager: self.whitelist_manager.clone(),

            registar: self.registar.clone(),
            server: self
                .server
                .start(self.http_tracker_container, self.registar.give_form())
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
            http_tracker_container: self.http_tracker_container,

            database: self.database,
            in_memory_torrent_repository: self.in_memory_torrent_repository,
            keys_handler: self.keys_handler,
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
