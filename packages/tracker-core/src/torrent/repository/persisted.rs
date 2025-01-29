use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_primitives::PersistentTorrents;

use crate::databases::error::Error;
use crate::databases::Database;

/// Torrent repository implementation that persists the torrents in a database.
///
/// Not all the torrent in-memory data is persisted. For now only some of the
/// torrent metrics are persisted.
pub struct DatabasePersistentTorrentRepository {
    /// A database driver implementation: [`Sqlite3`](crate::core::databases::sqlite)
    /// or [`MySQL`](crate::core::databases::mysql)
    database: Arc<Box<dyn Database>>,
}

impl DatabasePersistentTorrentRepository {
    #[must_use]
    pub fn new(database: &Arc<Box<dyn Database>>) -> DatabasePersistentTorrentRepository {
        Self {
            database: database.clone(),
        }
    }

    /// It loads the persistent torrents from the database.
    ///
    /// # Errors
    ///
    /// Will return a database `Err` if unable to load.
    pub fn load_all(&self) -> Result<PersistentTorrents, Error> {
        self.database.load_persistent_torrents()
    }

    /// It saves the persistent torrent into the database.
    ///
    /// # Errors
    ///
    /// Will return a database `Err` if unable to save.
    pub fn save(&self, info_hash: &InfoHash, downloaded: u32) -> Result<(), Error> {
        self.database.save_persistent_torrent(info_hash, downloaded)
    }
}
