use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use futures::executor::block_on;
use torrust_tracker_configuration::{Configuration, HttpTracker};
use torrust_tracker_lib::bootstrap::app::initialize_globals_and_tracker;
use torrust_tracker_lib::bootstrap::jobs::make_rust_tls;
use torrust_tracker_lib::core::services::statistics;
use torrust_tracker_lib::core::statistics::event::sender::Sender;
use torrust_tracker_lib::core::statistics::repository::Repository;
use torrust_tracker_lib::core::whitelist::WhiteListManager;
use torrust_tracker_lib::core::Tracker;
use torrust_tracker_lib::servers::http::server::{HttpServer, Launcher, Running, Stopped};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_primitives::peer;

pub struct Environment<S> {
    pub config: Arc<HttpTracker>,
    pub tracker: Arc<Tracker>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
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
        let (stats_event_sender, stats_repository) = statistics::setup::factory(configuration.core.tracker_usage_statistics);
        let stats_event_sender = Arc::new(stats_event_sender);
        let stats_repository = Arc::new(stats_repository);

        let tracker = initialize_globals_and_tracker(configuration);

        // todo: instantiate outside of `initialize_globals_and_tracker`
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
            stats_event_sender,
            stats_repository,
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
            stats_event_sender: self.stats_event_sender.clone(),
            stats_repository: self.stats_repository.clone(),
            whitelist_manager: self.whitelist_manager.clone(),
            registar: self.registar.clone(),
            server: self
                .server
                .start(self.tracker, self.stats_event_sender, self.registar.give_form())
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
            registar: Registar::default(),

            server: self.server.stop().await.unwrap(),
        }
    }

    pub fn bind_address(&self) -> &std::net::SocketAddr {
        &self.server.state.binding
    }
}
