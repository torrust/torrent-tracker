//! Module to handle the UDP server instances.
use std::fmt::Debug;

use derive_more::derive::Display;
use thiserror::Error;

use super::RawRequest;

pub mod banning;
pub mod bound_socket;
pub mod launcher;
pub mod processor;
pub mod receiver;
pub mod request_buffer;
pub mod spawner;
pub mod states;

/// Error that can occur when starting or stopping the UDP server.
///
/// Some errors triggered while starting the server are:
///
/// - The server cannot bind to the given address.
/// - It cannot get the bound address.
///
/// Some errors triggered while stopping the server are:
///
/// - The [`Server`] cannot send the shutdown signal to the spawned UDP service thread.
#[derive(Debug, Error)]
pub enum UdpError {
    #[error("Any error to do with the socket")]
    FailedToBindSocket(std::io::Error),

    #[error("Any error to do with starting or stopping the sever")]
    FailedToStartOrStopServer(String),
}

/// A UDP server.
///
/// It's an state machine. Configurations cannot be changed. This struct
/// represents concrete configuration and state. It allows to start and stop the
/// server but always keeping the same configuration.
///
/// > **NOTICE**: if the configurations changes after running the server it will
/// > reset to the initial value after stopping the server. This struct is not
/// > intended to persist configurations between runs.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Display)]
pub struct Server<S>
where
    S: std::fmt::Debug + std::fmt::Display,
{
    /// The state of the server: `running` or `stopped`.
    pub state: S,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::RwLock;
    use torrust_tracker_test_helpers::configuration::ephemeral_public;

    use super::spawner::Spawner;
    use super::Server;
    use crate::bootstrap::app::initialize_global_services;
    use crate::core::services::{initialize_database, initialize_tracker, initialize_whitelist, statistics};
    use crate::servers::registar::Registar;
    use crate::servers::udp::server::banning::BanService;
    use crate::servers::udp::server::launcher::MAX_CONNECTION_ID_ERRORS_PER_IP;

    #[tokio::test]
    async fn it_should_be_able_to_start_and_stop() {
        let cfg = Arc::new(ephemeral_public());

        let (stats_event_sender, _stats_repository) = statistics::setup::factory(cfg.core.tracker_usage_statistics);
        let stats_event_sender = Arc::new(stats_event_sender);
        let ban_service = Arc::new(RwLock::new(BanService::new(MAX_CONNECTION_ID_ERRORS_PER_IP)));

        initialize_global_services(&cfg);

        let database = initialize_database(&cfg);
        let whitelist_manager = initialize_whitelist(database.clone());
        let tracker = Arc::new(initialize_tracker(&cfg, &database, &whitelist_manager));

        let udp_trackers = cfg.udp_trackers.clone().expect("missing UDP trackers configuration");
        let config = &udp_trackers[0];
        let bind_to = config.bind_address;
        let register = &Registar::default();

        let stopped = Server::new(Spawner::new(bind_to));

        let started = stopped
            .start(
                tracker,
                stats_event_sender,
                ban_service,
                register.give_form(),
                config.cookie_lifetime,
            )
            .await
            .expect("it should start the server");

        let stopped = started.stop().await.expect("it should stop the server");

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(stopped.state.spawner.bind_to, bind_to);
    }

    #[tokio::test]
    async fn it_should_be_able_to_start_and_stop_with_wait() {
        let cfg = Arc::new(ephemeral_public());

        let (stats_event_sender, _stats_repository) = statistics::setup::factory(cfg.core.tracker_usage_statistics);
        let stats_event_sender = Arc::new(stats_event_sender);
        let ban_service = Arc::new(RwLock::new(BanService::new(MAX_CONNECTION_ID_ERRORS_PER_IP)));

        initialize_global_services(&cfg);

        let database = initialize_database(&cfg);
        let whitelist_manager = initialize_whitelist(database.clone());
        let tracker = Arc::new(initialize_tracker(&cfg, &database, &whitelist_manager));

        let config = &cfg.udp_trackers.as_ref().unwrap().first().unwrap();
        let bind_to = config.bind_address;
        let register = &Registar::default();

        let stopped = Server::new(Spawner::new(bind_to));

        let started = stopped
            .start(
                tracker,
                stats_event_sender,
                ban_service,
                register.give_form(),
                config.cookie_lifetime,
            )
            .await
            .expect("it should start the server");

        tokio::time::sleep(Duration::from_secs(1)).await;

        let stopped = started.stop().await.expect("it should stop the server");

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(stopped.state.spawner.bind_to, bind_to);
    }
}

/// Todo: submit test to tokio documentation.
#[cfg(test)]
mod test_tokio {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::Barrier;
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn test_barrier_with_aborted_tasks() {
        // Create a barrier that requires 10 tasks to proceed.
        let barrier = Arc::new(Barrier::new(10));
        let mut tasks = JoinSet::default();
        let mut handles = Vec::default();

        // Set Barrier to 9/10.
        for _ in 0..9 {
            let c = barrier.clone();
            handles.push(tasks.spawn(async move {
                c.wait().await;
            }));
        }

        // Abort two tasks: Barrier: 7/10.
        for _ in 0..2 {
            if let Some(handle) = handles.pop() {
                handle.abort();
            }
        }

        // Spawn a single task: Barrier 8/10.
        let c = barrier.clone();
        handles.push(tasks.spawn(async move {
            c.wait().await;
        }));

        // give a chance fro the barrier to release.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // assert that the barrier isn't removed, i.e. 8, not 10.
        for h in &handles {
            assert!(!h.is_finished());
        }

        // Spawn two more tasks to trigger the barrier release: Barrier 10/10.
        for _ in 0..2 {
            let c = barrier.clone();
            handles.push(tasks.spawn(async move {
                c.wait().await;
            }));
        }

        // give a chance fro the barrier to release.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // assert that the barrier has been triggered
        for h in &handles {
            assert!(h.is_finished());
        }

        tasks.shutdown().await;
    }
}
