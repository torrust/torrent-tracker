use std::sync::Arc;
use std::time::Duration;

use torrust_tracker_clock::clock::Time;
use torrust_tracker_configuration::Core;

use super::repository::in_memory::InMemoryTorrentRepository;
use super::repository::persisted::DatabasePersistentTorrentRepository;
use crate::core::databases;
use crate::CurrentClock;

pub struct TorrentsManager {
    /// The tracker configuration.
    config: Core,

    /// The in-memory torrents repository.
    in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,

    /// The persistent torrents repository.
    db_torrent_repository: Arc<DatabasePersistentTorrentRepository>,
}

impl TorrentsManager {
    #[must_use]
    pub fn new(
        config: &Core,
        in_memory_torrent_repository: &Arc<InMemoryTorrentRepository>,
        db_torrent_repository: &Arc<DatabasePersistentTorrentRepository>,
    ) -> Self {
        Self {
            config: config.clone(),
            in_memory_torrent_repository: in_memory_torrent_repository.clone(),
            db_torrent_repository: db_torrent_repository.clone(),
        }
    }

    /// It loads the torrents from database into memory. It only loads the
    /// torrent entry list with the number of seeders for each torrent. Peers
    /// data is not persisted.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list of `persistent_torrents` from the database.
    pub fn load_torrents_from_database(&self) -> Result<(), databases::error::Error> {
        let persistent_torrents = self.db_torrent_repository.load_all()?;

        self.in_memory_torrent_repository.import_persistent(&persistent_torrents);

        Ok(())
    }

    /// Remove inactive peers and (optionally) peerless torrents.
    pub fn cleanup_torrents(&self) {
        let current_cutoff = CurrentClock::now_sub(&Duration::from_secs(u64::from(self.config.tracker_policy.max_peer_timeout)))
            .unwrap_or_default();

        self.in_memory_torrent_repository.remove_inactive_peers(current_cutoff);

        if self.config.tracker_policy.remove_peerless_torrents {
            self.in_memory_torrent_repository
                .remove_peerless_torrents(&self.config.tracker_policy);
        }
    }
}
