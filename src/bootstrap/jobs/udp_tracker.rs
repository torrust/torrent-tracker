//! UDP tracker job starter.
//!
//! The [`udp_tracker::start_job`](crate::bootstrap::jobs::udp_tracker::start_job)
//! function starts a new UDP tracker server.
//!
//! > **NOTICE**: that the application can launch more than one UDP tracker
//! > on different ports. Refer to the [configuration documentation](https://docs.rs/torrust-tracker-configuration)
//! > for the configuration options.
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::instrument;

use crate::container::UdpTrackerContainer;
use crate::servers::registar::ServiceRegistrationForm;
use crate::servers::udp::server::spawner::Spawner;
use crate::servers::udp::server::Server;
use crate::servers::udp::UDP_TRACKER_LOG_TARGET;

/// It starts a new UDP server with the provided configuration.
///
/// It spawns a new asynchronous task for the new UDP server.
///
/// # Panics
///
/// It will panic if the API binding address is not a valid socket.
/// It will panic if it is unable to start the UDP service.
/// It will panic if the task did not finish successfully.
#[must_use]
#[allow(clippy::async_yields_async)]
#[instrument(skip(udp_tracker_container, form))]
pub async fn start_job(udp_tracker_container: Arc<UdpTrackerContainer>, form: ServiceRegistrationForm) -> JoinHandle<()> {
    let bind_to = udp_tracker_container.udp_tracker_config.bind_address;
    let cookie_lifetime = udp_tracker_container.udp_tracker_config.cookie_lifetime;

    let server = Server::new(Spawner::new(bind_to))
        .start(udp_tracker_container, form, cookie_lifetime)
        .await
        .expect("it should be able to start the udp tracker");

    tokio::spawn(async move {
        tracing::debug!(target: UDP_TRACKER_LOG_TARGET, "Wait for launcher (UDP service) to finish ...");
        tracing::debug!(target: UDP_TRACKER_LOG_TARGET, "Is halt channel closed before waiting?: {}", server.state.halt_task.is_closed());

        assert!(
            !server.state.halt_task.is_closed(),
            "Halt channel for UDP tracker should be open"
        );

        server
            .state
            .task
            .await
            .expect("it should be able to join to the udp tracker task");

        tracing::debug!(target: UDP_TRACKER_LOG_TARGET, "Is halt channel closed after finishing the server?: {}", server.state.halt_task.is_closed());
    })
}
