use std::net::SocketAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker::bootstrap::app::initialize_with_configuration;
use torrust_tracker::core::Tracker;
use torrust_tracker::servers::registar::Registar;
use torrust_tracker::servers::udp::server::spawner::Spawner;
use torrust_tracker::servers::udp::server::states::{Running, Stopped};
use torrust_tracker::servers::udp::server::Server;
use torrust_tracker_configuration::{Configuration, UdpTracker, DEFAULT_TIMEOUT};
use torrust_tracker_primitives::peer;

pub struct Environment<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    pub config: Arc<UdpTracker>,
    pub tracker: Arc<Tracker>,
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
        let tracker = initialize_with_configuration(configuration);

        let udp_tracker = configuration.udp_trackers.clone().expect("missing UDP tracker configuration");

        let config = Arc::new(udp_tracker[0].clone());

        let bind_to = config.bind_address;

        let server = Server::new(Spawner::new(bind_to));

        Self {
            config,
            tracker,
            registar: Registar::default(),
            server,
        }
    }

    #[allow(dead_code)]
    pub async fn start(self) -> Environment<Running> {
        Environment {
            config: self.config,
            tracker: self.tracker.clone(),
            registar: self.registar.clone(),
            server: self.server.start(self.tracker, self.registar.give_form()).await.unwrap(),
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
    use tracing::level_filters::LevelFilter;

    use crate::common::logging::{tracing_stderr_init, INIT};
    use crate::servers::udp::Started;

    #[tokio::test]
    async fn it_should_make_and_stop_udp_server() {
        INIT.call_once(|| {
            tracing_stderr_init(LevelFilter::ERROR);
        });

        let env = Started::new(&configuration::ephemeral().into()).await;
        sleep(Duration::from_secs(1)).await;
        env.stop().await;
        sleep(Duration::from_secs(1)).await;
    }
}
