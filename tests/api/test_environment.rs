use core::panic;
use std::sync::Arc;

use torrust_tracker::apis::server::{ApiServer, RunningApiServer, StoppedApiServer};
use torrust_tracker::protocol::info_hash::InfoHash;
use torrust_tracker::tracker::peer::Peer;
use torrust_tracker::tracker::statistics::Keeper;
use torrust_tracker::tracker::Tracker;
use torrust_tracker::{ephemeral_instance_keys, logging, static_time};
use torrust_tracker_configuration::Configuration;
use torrust_tracker_test_helpers::configuration::ephemeral;

use super::connection_info::ConnectionInfo;

#[allow(clippy::module_name_repetitions, dead_code)]
pub type StoppedTestEnvironment = TestEnvironment<Stopped>;
#[allow(clippy::module_name_repetitions)]
pub type RunningTestEnvironment = TestEnvironment<Running>;

pub struct TestEnvironment<S> {
    pub tracker: Arc<Tracker>,
    pub state: S,
}

#[allow(dead_code)]
pub struct Stopped {
    api_server: StoppedApiServer,
}

pub struct Running {
    api_server: RunningApiServer,
}

impl<S> TestEnvironment<S> {
    /// Add a torrent to the tracker
    pub async fn add_torrent_peer(&self, info_hash: &InfoHash, peer: &Peer) {
        self.tracker.update_torrent_with_peer_and_get_stats(info_hash, peer).await;
    }
}

impl TestEnvironment<Stopped> {
    #[allow(dead_code)]
    pub fn new_stopped() -> Self {
        let api_server = api_server();

        Self {
            tracker: api_server.tracker.clone(),
            state: Stopped { api_server },
        }
    }

    #[allow(dead_code)]
    pub fn start(self) -> TestEnvironment<Running> {
        TestEnvironment {
            tracker: self.tracker,
            state: Running {
                api_server: self.state.api_server.start().unwrap(),
            },
        }
    }
}

impl TestEnvironment<Running> {
    pub fn new_running() -> Self {
        let api_server = running_api_server();

        Self {
            tracker: api_server.tracker.clone(),
            state: Running { api_server },
        }
    }

    pub async fn stop(self) -> TestEnvironment<Stopped> {
        TestEnvironment {
            tracker: self.tracker,
            state: Stopped {
                api_server: self.state.api_server.stop().await.unwrap(),
            },
        }
    }

    pub fn get_connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            bind_address: self.state.api_server.state.bind_address.to_string(),
            api_token: self.state.api_server.cfg.access_tokens.get("admin").cloned(),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub fn running_test_environment() -> RunningTestEnvironment {
    TestEnvironment::new_running()
}

pub fn tracker_configuration() -> Arc<Configuration> {
    Arc::new(ephemeral())
}

// TODO: Move to test-helpers crate once `Tracker` is isolated.
pub fn tracker_instance(configuration: &Arc<Configuration>) -> Arc<Tracker> {
    // Set the time of Torrust app starting
    lazy_static::initialize(&static_time::TIME_AT_APP_START);

    // Initialize the Ephemeral Instance Random Seed
    lazy_static::initialize(&ephemeral_instance_keys::RANDOM_SEED);

    // Initialize stats tracker
    let (stats_event_sender, stats_repository) = Keeper::new_active_instance();

    // Initialize Torrust tracker
    let tracker = match Tracker::new(configuration, Some(stats_event_sender), stats_repository) {
        Ok(tracker) => Arc::new(tracker),
        Err(error) => {
            panic!("{}", error)
        }
    };

    // Initialize logging
    logging::setup(configuration);

    tracker
}

pub fn api_server() -> StoppedApiServer {
    let config = tracker_configuration();

    let tracker = tracker_instance(&config);

    ApiServer::new(config.http_api.clone(), tracker)
}

pub fn running_api_server() -> RunningApiServer {
    api_server().start().unwrap()
}
