use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use futures::executor::block_on;
use torrust_tracker_configuration::{Configuration, HttpTracker};
use torrust_tracker_lib::bootstrap::app::initialize_with_configuration;
use torrust_tracker_lib::bootstrap::jobs::make_rust_tls;
use torrust_tracker_lib::core::whitelist::WhiteListManager;
use torrust_tracker_lib::core::Tracker;
use torrust_tracker_lib::servers::http::server::{HttpServer, Launcher, Running, Stopped};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_primitives::peer;

pub struct Environment<S> {
    pub config: Arc<HttpTracker>,
    pub tracker: Arc<Tracker>,
    pub whitelist_manager: Arc<WhiteListManager>,
    pub registar: Registar,
    pub server: HttpServer<S>,
}

impl<S> Environment<S> {
    /// Add a torrent to the tracker
    pub fn add_torrent_peer(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        self.tracker.upsert_peer_and_get_stats(info_hash, peer);
    }
}

impl Environment<Stopped> {
    #[allow(dead_code)]
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        let tracker = initialize_with_configuration(configuration);

        let whitelist_manager = tracker.whitelist_manager.clone();

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
            tracker,
            whitelist_manager,
            registar: Registar::default(),
            server,
        }
    }

    #[allow(dead_code)]
    pub async fn start(self) -> Environment<Running> {
        Environment {
            config: self.config,
            tracker: self.tracker.clone(),
            whitelist_manager: self.whitelist_manager.clone(),
            registar: self.registar.clone(),
            server: self.server.start(self.tracker, self.registar.give_form()).await.unwrap(),
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
            whitelist_manager: self.whitelist_manager,
            registar: Registar::default(),

            server: self.server.stop().await.unwrap(),
        }
    }

    pub fn bind_address(&self) -> &std::net::SocketAddr {
        &self.server.state.binding
    }
}
