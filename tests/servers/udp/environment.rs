use std::net::SocketAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use tokio::sync::RwLock;
use torrust_tracker_configuration::{Configuration, UdpTracker, DEFAULT_TIMEOUT};
use torrust_tracker_lib::bootstrap::app::{initialize_app_container, initialize_global_services};
use torrust_tracker_lib::core::statistics::event::sender::Sender;
use torrust_tracker_lib::core::statistics::repository::Repository;
use torrust_tracker_lib::core::{whitelist, Tracker};
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_lib::servers::udp::server::banning::BanService;
use torrust_tracker_lib::servers::udp::server::spawner::Spawner;
use torrust_tracker_lib::servers::udp::server::states::{Running, Stopped};
use torrust_tracker_lib::servers::udp::server::Server;
use torrust_tracker_primitives::peer;

pub struct Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    pub config: Arc<UdpTracker>,
    pub tracker: Arc<Tracker>,
    pub whitelist_authorization: Arc<whitelist::authorization::Authorization>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
    pub ban_service: Arc<RwLock<BanService>>,
    pub registar: Registar,
    pub server: Server<S>,
}

impl<S> Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    /// Add a torrent to the tracker
    #[allow(dead_code)]
    pub fn add_torrent(&self, info_hash: &InfoHash, peer: &peer::Peer) {
        self.tracker.upsert_peer_and_get_stats(info_hash, peer);
    }
}

impl Environment<Stopped> {
    #[allow(dead_code)]
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        initialize_global_services(configuration);

        let app_container = initialize_app_container(configuration);

        let udp_tracker = configuration.udp_trackers.clone().expect("missing UDP tracker configuration");

        let config = Arc::new(udp_tracker[0].clone());

        let bind_to = config.bind_address;

        let server = Server::new(Spawner::new(bind_to));

        Self {
            config,
            tracker: app_container.tracker.clone(),
            whitelist_authorization: app_container.whitelist_authorization.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            stats_repository: app_container.stats_repository.clone(),
            ban_service: app_container.ban_service.clone(),
            registar: Registar::default(),
            server,
        }
    }

    #[allow(dead_code)]
    pub async fn start(self) -> Environment<Running> {
        let cookie_lifetime = self.config.cookie_lifetime;
        Environment {
            config: self.config,
            tracker: self.tracker.clone(),
            whitelist_authorization: self.whitelist_authorization.clone(),
            stats_event_sender: self.stats_event_sender.clone(),
            stats_repository: self.stats_repository.clone(),
            ban_service: self.ban_service.clone(),
            registar: self.registar.clone(),
            server: self
                .server
                .start(
                    self.tracker,
                    self.whitelist_authorization,
                    self.stats_event_sender,
                    self.ban_service,
                    self.registar.give_form(),
                    cookie_lifetime,
                )
                .await
                .unwrap(),
        }
    }
}

impl Environment<Running> {
    pub async fn new(configuration: &Arc<Configuration>) -> Self {
        tokio::time::timeout(DEFAULT_TIMEOUT, Environment::<Stopped>::new(configuration).start())
            .await
            .expect("it should create an environment within the timeout")
    }

    #[allow(dead_code)]
    pub async fn stop(self) -> Environment<Stopped> {
        let stopped = tokio::time::timeout(DEFAULT_TIMEOUT, self.server.stop())
            .await
            .expect("it should stop the environment within the timeout");

        Environment {
            config: self.config,
            tracker: self.tracker,
            whitelist_authorization: self.whitelist_authorization,
            stats_event_sender: self.stats_event_sender,
            stats_repository: self.stats_repository,
            ban_service: self.ban_service,
            registar: Registar::default(),
            server: stopped.expect("it stop the udp tracker service"),
        }
    }

    pub fn bind_address(&self) -> SocketAddr {
        self.server.state.local_addr
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::sleep;
    use torrust_tracker_test_helpers::configuration;

    use crate::common::logging;
    use crate::servers::udp::Started;

    #[tokio::test]
    async fn it_should_make_and_stop_udp_server() {
        logging::setup();

        let env = Started::new(&configuration::ephemeral().into()).await;
        sleep(Duration::from_secs(1)).await;
        env.stop().await;
        sleep(Duration::from_secs(1)).await;
    }
}
