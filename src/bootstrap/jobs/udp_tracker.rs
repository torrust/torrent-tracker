//! UDP tracker job starter.
//!
//! The [`udp_tracker::start_job`](crate::bootstrap::jobs::udp_tracker::start_job)
//! function starts a new UDP tracker server.
//!
//! > **NOTICE**: that the application can launch more than one UDP tracker
//! > on different ports. Refer to the [configuration documentation](https://docs.rs/torrust-tracker-configuration)
//! > for the configuration options.
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use torrust_tracker_configuration::UdpTracker;
use tracing::instrument;

use crate::core::announce_handler::AnnounceHandler;
use crate::core::scrape_handler::ScrapeHandler;
use crate::core::statistics::event::sender::Sender;
use crate::core::{self, whitelist};
use crate::servers::registar::ServiceRegistrationForm;
use crate::servers::udp::server::banning::BanService;
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
#[allow(clippy::too_many_arguments)]
#[allow(clippy::async_yields_async)]
#[instrument(skip(
    config,
    tracker,
    announce_handler,
    scrape_handler,
    whitelist_authorization,
    stats_event_sender,
    ban_service,
    form
))]
pub async fn start_job(
    config: &UdpTracker,
    tracker: Arc<core::Tracker>,
    announce_handler: Arc<AnnounceHandler>,
    scrape_handler: Arc<ScrapeHandler>,
    whitelist_authorization: Arc<whitelist::authorization::Authorization>,
    stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    ban_service: Arc<RwLock<BanService>>,
    form: ServiceRegistrationForm,
) -> JoinHandle<()> {
    let bind_to = config.bind_address;
    let cookie_lifetime = config.cookie_lifetime;

    let server = Server::new(Spawner::new(bind_to))
        .start(
            tracker,
            announce_handler,
            scrape_handler,
            whitelist_authorization,
            stats_event_sender,
            ban_service,
            form,
            cookie_lifetime,
        )
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
