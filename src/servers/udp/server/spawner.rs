//! A thin wrapper for tokio spawn to launch the UDP server launcher as a new task.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use derive_more::derive::Display;
use derive_more::Constructor;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use torrust_tracker_configuration::Core;

use super::banning::BanService;
use super::launcher::Launcher;
use crate::bootstrap::jobs::Started;
use crate::core::announce_handler::AnnounceHandler;
use crate::core::scrape_handler::ScrapeHandler;
use crate::core::statistics::event::sender::Sender;
use crate::core::{whitelist, Tracker};
use crate::servers::signals::Halted;

#[derive(Constructor, Copy, Clone, Debug, Display)]
#[display("(with socket): {bind_to}")]
pub struct Spawner {
    pub bind_to: SocketAddr,
}

impl Spawner {
    /// It spawns a new task to run the UDP server instance.
    ///
    /// # Panics
    ///
    /// It would panic if unable to resolve the `local_addr` from the supplied ´socket´.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_launcher(
        &self,
        core_config: Arc<Core>,
        tracker: Arc<Tracker>,
        announce_handler: Arc<AnnounceHandler>,
        scrape_handler: Arc<ScrapeHandler>,
        whitelist_authorization: Arc<whitelist::authorization::Authorization>,
        opt_stats_event_sender: Arc<Option<Box<dyn Sender>>>,
        ban_service: Arc<RwLock<BanService>>,
        cookie_lifetime: Duration,
        tx_start: oneshot::Sender<Started>,
        rx_halt: oneshot::Receiver<Halted>,
    ) -> JoinHandle<Spawner> {
        let spawner = Self::new(self.bind_to);

        tokio::spawn(async move {
            Launcher::run_with_graceful_shutdown(
                core_config,
                tracker,
                announce_handler,
                scrape_handler,
                whitelist_authorization,
                opt_stats_event_sender,
                ban_service,
                spawner.bind_to,
                cookie_lifetime,
                tx_start,
                rx_halt,
            )
            .await;
            spawner
        })
    }
}
