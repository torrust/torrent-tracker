//! Job that runs a task on intervals to clean up torrents.
//!
//! It removes inactive peers and (optionally) peerless torrents.
//!
//! **Inactive peers** are peers that have not been updated for more than `max_peer_timeout` seconds.
//! `max_peer_timeout` is a customizable core tracker option.
//!
//! If the core tracker configuration option `remove_peerless_torrents` is true, the cleanup job will also
//! remove **peerless torrents** which are torrents with an empty peer list.
//!
//! Refer to [`torrust-tracker-configuration documentation`](https://docs.rs/torrust-tracker-configuration) for more info about those options.

use std::sync::Arc;

use bittorrent_tracker_core::torrent::manager::TorrentsManager;
use chrono::Utc;
use tokio::task::JoinHandle;
use torrust_tracker_configuration::Core;
use tracing::instrument;

/// It starts a jobs for cleaning up the torrent data in the tracker.
///
/// The cleaning task is executed on an `inactive_peer_cleanup_interval`.
///
/// Refer to [`torrust-tracker-configuration documentation`](https://docs.rs/torrust-tracker-configuration) for more info about that option.
#[must_use]
#[instrument(skip(config, torrents_manager))]
pub fn start_job(config: &Core, torrents_manager: &Arc<TorrentsManager>) -> JoinHandle<()> {
    let weak_torrents_manager = std::sync::Arc::downgrade(torrents_manager);
    let interval = config.inactive_peer_cleanup_interval;

    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(interval);
        let mut interval = tokio::time::interval(interval);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Stopping torrent cleanup job..");
                    break;
                }
                _ = interval.tick() => {
                    if let Some(torrents_manager) = weak_torrents_manager.upgrade() {
                        let start_time = Utc::now().time();
                        tracing::info!("Cleaning up torrents..");
                        torrents_manager.cleanup_torrents();
                        tracing::info!("Cleaned up torrents in: {}ms", (Utc::now().time() - start_time).num_milliseconds());
                    } else {
                        break;
                    }
                }
            }
        }
    })
}
