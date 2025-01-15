use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;

use super::databases::{self, Database};

pub struct WhiteListManager {
    /// A database driver implementation: [`Sqlite3`](crate::core::databases::sqlite)
    /// or [`MySQL`](crate::core::databases::mysql)
    database: Arc<Box<dyn Database>>,

    /// The list of allowed torrents. Only for listed trackers.
    whitelist: tokio::sync::RwLock<std::collections::HashSet<InfoHash>>,
}

impl WhiteListManager {
    #[must_use]
    pub fn new(database: Arc<Box<dyn Database>>) -> Self {
        Self {
            database,
            whitelist: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// It adds a torrent to the whitelist.
    /// Adding torrents is not relevant to public trackers.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `info_hash` into the whitelist database.
    pub async fn add_torrent_to_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.add_torrent_to_database_whitelist(info_hash)?;
        self.add_torrent_to_memory_whitelist(info_hash).await;
        Ok(())
    }

    /// It adds a torrent to the whitelist if it has not been whitelisted previously
    fn add_torrent_to_database_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        let is_whitelisted = self.database.is_info_hash_whitelisted(*info_hash)?;

        if is_whitelisted {
            return Ok(());
        }

        self.database.add_info_hash_to_whitelist(*info_hash)?;

        Ok(())
    }

    pub async fn add_torrent_to_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.insert(*info_hash)
    }

    /// It removes a torrent from the whitelist.
    /// Removing torrents is not relevant to public trackers.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub async fn remove_torrent_from_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.remove_torrent_from_database_whitelist(info_hash)?;
        self.remove_torrent_from_memory_whitelist(info_hash).await;
        Ok(())
    }

    /// It removes a torrent from the whitelist in the database.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub fn remove_torrent_from_database_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        let is_whitelisted = self.database.is_info_hash_whitelisted(*info_hash)?;

        if !is_whitelisted {
            return Ok(());
        }

        self.database.remove_info_hash_from_whitelist(*info_hash)?;

        Ok(())
    }

    /// It removes a torrent from the whitelist in memory.
    ///
    /// # Context: Whitelist
    pub async fn remove_torrent_from_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.remove(info_hash)
    }

    /// It checks if a torrent is whitelisted.
    ///
    /// # Context: Whitelist
    pub async fn is_info_hash_whitelisted(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.read().await.contains(info_hash)
    }

    /// It loads the whitelist from the database.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list whitelisted `info_hash`s from the database.
    pub async fn load_whitelist_from_database(&self) -> Result<(), databases::error::Error> {
        let whitelisted_torrents_from_database = self.database.load_whitelist()?;
        let mut whitelist = self.whitelist.write().await;

        whitelist.clear();

        for info_hash in whitelisted_torrents_from_database {
            let _: bool = whitelist.insert(info_hash);
        }

        Ok(())
    }
}
