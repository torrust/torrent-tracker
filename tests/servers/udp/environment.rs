use std::net::SocketAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use bittorrent_tracker_core::databases::Database;
use bittorrent_tracker_core::torrent::repository::in_memory::InMemoryTorrentRepository;
use packages::statistics::repository::Repository;
use torrust_tracker_configuration::{Configuration, DEFAULT_TIMEOUT};
use torrust_tracker_lib::bootstrap::app::{initialize_app_container, initialize_global_services};
use torrust_tracker_lib::container::UdpTrackerContainer;
use torrust_tracker_lib::packages;
use torrust_tracker_lib::servers::registar::Registar;
use torrust_tracker_lib::servers::udp::server::spawner::Spawner;
use torrust_tracker_lib::servers::udp::server::states::{Running, Stopped};
use torrust_tracker_lib::servers::udp::server::Server;
use torrust_tracker_primitives::peer;

pub struct Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    pub udp_tracker_container: Arc<UdpTrackerContainer>,

    pub database: Arc<Box<dyn Database>>,
    pub in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,
    pub stats_repository: Arc<Repository>,

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
        let () = self.in_memory_torrent_repository.upsert_peer(info_hash, peer);
    }
}

impl Environment<Stopped> {
    #[allow(dead_code)]
    pub fn new(configuration: &Arc<Configuration>) -> Self {
        initialize_global_services(configuration);

        let app_container = initialize_app_container(configuration);

        let udp_tracker_configurations = configuration.udp_trackers.clone().expect("missing UDP tracker configuration");

        let udp_tracker_config = Arc::new(udp_tracker_configurations[0].clone());

        let bind_to = udp_tracker_config.bind_address;

        let server = Server::new(Spawner::new(bind_to));

        let udp_tracker_container = Arc::new(UdpTrackerContainer {
            udp_tracker_config: udp_tracker_config.clone(),
            core_config: app_container.core_config.clone(),
            announce_handler: app_container.announce_handler.clone(),
            scrape_handler: app_container.scrape_handler.clone(),
            whitelist_authorization: app_container.whitelist_authorization.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            ban_service: app_container.ban_service.clone(),
        });

        Self {
            udp_tracker_container,

            database: app_container.database.clone(),
            in_memory_torrent_repository: app_container.in_memory_torrent_repository.clone(),
            stats_repository: app_container.stats_repository.clone(),

            registar: Registar::default(),
            server,
        }
    }

    #[allow(dead_code)]
    pub async fn start(self) -> Environment<Running> {
        let cookie_lifetime = self.udp_tracker_container.udp_tracker_config.cookie_lifetime;

        Environment {
            udp_tracker_container: self.udp_tracker_container.clone(),

            database: self.database.clone(),
            in_memory_torrent_repository: self.in_memory_torrent_repository.clone(),
            stats_repository: self.stats_repository.clone(),

            registar: self.registar.clone(),
            server: self
                .server
                .start(self.udp_tracker_container, self.registar.give_form(), cookie_lifetime)
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
            udp_tracker_container: self.udp_tracker_container,

            database: self.database,
            in_memory_torrent_repository: self.in_memory_torrent_repository,
            stats_repository: self.stats_repository,

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
