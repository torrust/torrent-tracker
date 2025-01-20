use std::net::SocketAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use futures::executor::block_on;
use tokio::sync::RwLock;
use torrust_tracker_api_client::connection_info::{ConnectionInfo, Origin};
use torrust_tracker_configuration::{Configuration, HttpApi};
use torrust_tracker_lib::bootstrap::app::{initialize_app_container, initialize_global_services};
use torrust_tracker_lib::bootstrap::jobs::make_rust_tls;
use torrust_tracker_lib::core::statistics::event::sender::Sender;
use torrust_tracker_lib::core::statistics::repository::Repository;
use torrust_tracker_lib::core::whitelist::manager::WhiteListManager;
use torrust_tracker_lib::core::Tracker;
use torrust_tracker_lib::servers::apis::server::{ApiServer, Launcher, Running, Stopped};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_lib::servers::udp::server::banning::BanService;
use torrust_tracker_primitives::peer;

pub struct Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    pub config: Arc<HttpApi>,
    pub tracker: Arc<Tracker>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
    pub whitelist_manager: Arc<WhiteListManager>,
    pub ban_service: Arc<RwLock<BanService>>,
    pub registar: Registar,
    pub server: ApiServer<S>,
}

impl<S> Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    /// Add a torrent to the tracker
    pub fn add_torrent_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        self.tracker.upsert_peer_and_get_stats(info_hash, peer);
    }
}

impl Environment<Stopped> {
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        initialize_global_services(configuration);

        let app_container = initialize_app_container(configuration);

        let config = Arc::new(configuration.http_api.clone().expect("missing API configuration"));

        let bind_to = config.bind_address;

        let tls = block_on(make_rust_tls(&config.tsl_config)).map(|tls| tls.expect("tls config failed"));

        let server = ApiServer::new(Launcher::new(bind_to, tls));

        Self {
            config,
            tracker: app_container.tracker.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            stats_repository: app_container.stats_repository.clone(),
            whitelist_manager: app_container.whitelist_manager.clone(),
            ban_service: app_container.ban_service.clone(),
            registar: Registar::default(),
            server,
        }
    }

    pub async fn start(self) -> Environment<Running> {
        let access_tokens = Arc::new(self.config.access_tokens.clone());

        Environment {
            config: self.config,
            tracker: self.tracker.clone(),
            stats_event_sender: self.stats_event_sender.clone(),
            stats_repository: self.stats_repository.clone(),
            whitelist_manager: self.whitelist_manager.clone(),
            ban_service: self.ban_service.clone(),
            registar: self.registar.clone(),
            server: self
                .server
                .start(
                    self.tracker,
                    self.stats_event_sender,
                    self.stats_repository,
                    self.ban_service,
                    self.registar.give_form(),
                    access_tokens,
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
            stats_event_sender: self.stats_event_sender,
            stats_repository: self.stats_repository,
            whitelist_manager: self.whitelist_manager,
            ban_service: self.ban_service,
            registar: Registar::default(),
            server: self.server.stop().await.unwrap(),
        }
    }

    pub fn get_connection_info(&self) -> ConnectionInfo {
        let origin = Origin::new(&format!("http://{}/", self.server.state.local_addr)).unwrap(); // DevSkim: ignore DS137138

        ConnectionInfo {
            origin,
            api_token: self.config.access_tokens.get("admin").cloned(),
        }
    }

    pub fn bind_address(&self) -> SocketAddr {
        self.server.state.local_addr
    }
}
