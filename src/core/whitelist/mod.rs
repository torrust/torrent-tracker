use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;

use super::databases::{self, Database};

/// It handles the list of allowed torrents. Only for listed trackers.
pub struct WhiteListManager {
    /// The in-memory list of allowed torrents.
    in_memory_whitelist: InMemoryWhitelist,

    /// The persisted list of allowed torrents.
    database_whitelist: DatabaseWhitelist,
}

impl WhiteListManager {
    #[must_use]
    pub fn new(database: Arc<Box<dyn Database>>) -> Self {
        Self {
            in_memory_whitelist: InMemoryWhitelist::new(),
            database_whitelist: DatabaseWhitelist::new(database),
        }
    }

    /// It adds a torrent to the whitelist.
    /// Adding torrents is not relevant to public trackers.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `info_hash` into the whitelist database.
    pub async fn add_torrent_to_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.database_whitelist.add_torrent_to_database_whitelist(info_hash)?;
        self.in_memory_whitelist.add(info_hash).await;
        Ok(())
    }

    /// It removes a torrent from the whitelist.
    /// Removing torrents is not relevant to public trackers.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub async fn remove_torrent_from_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.database_whitelist.remove_torrent_from_database_whitelist(info_hash)?;
        self.in_memory_whitelist.remove(info_hash).await;
        Ok(())
    }

    /// It removes a torrent from the whitelist in the database.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub fn remove_torrent_from_database_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.database_whitelist.remove_torrent_from_database_whitelist(info_hash)
    }

    /// It adds a torrent from the whitelist in memory.
    pub async fn add_torrent_to_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.in_memory_whitelist.add(info_hash).await
    }

    /// It removes a torrent from the whitelist in memory.
    pub async fn remove_torrent_from_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.in_memory_whitelist.remove(info_hash).await
    }

    /// It checks if a torrent is whitelisted.
    pub async fn is_info_hash_whitelisted(&self, info_hash: &InfoHash) -> bool {
        self.in_memory_whitelist.contains(info_hash).await
    }

    /// It loads the whitelist from the database.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list whitelisted `info_hash`s from the database.
    pub async fn load_whitelist_from_database(&self) -> Result<(), databases::error::Error> {
        let whitelisted_torrents_from_database = self.database_whitelist.load_whitelist_from_database()?;

        self.in_memory_whitelist.clear().await;

        for info_hash in whitelisted_torrents_from_database {
            let _: bool = self.in_memory_whitelist.add(&info_hash).await;
        }

        Ok(())
    }
}

/// The in-memory list of allowed torrents.
struct InMemoryWhitelist {
    /// The list of allowed torrents.
    whitelist: tokio::sync::RwLock<std::collections::HashSet<InfoHash>>,
}

impl InMemoryWhitelist {
    pub fn new() -> Self {
        Self {
            whitelist: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// It adds a torrent from the whitelist in memory.
    pub async fn add(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.insert(*info_hash)
    }

    /// It removes a torrent from the whitelist in memory.
    pub async fn remove(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.remove(info_hash)
    }

    /// It checks if it contains an info-hash.
    pub async fn contains(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.read().await.contains(info_hash)
    }

    /// It clears the whitelist.
    pub async fn clear(&self) {
        let mut whitelist = self.whitelist.write().await;
        whitelist.clear();
    }
}

/// The persisted list of allowed torrents.
struct DatabaseWhitelist {
    /// A database driver implementation: [`Sqlite3`](crate::core::databases::sqlite)
    /// or [`MySQL`](crate::core::databases::mysql)
    database: Arc<Box<dyn Database>>,
}

impl DatabaseWhitelist {
    #[must_use]
    pub fn new(database: Arc<Box<dyn Database>>) -> Self {
        Self { database }
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

    /// It removes a torrent from the whitelist in the database.
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

    /// It loads the whitelist from the database.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list whitelisted `info_hash`s from the database.
    pub fn load_whitelist_from_database(&self) -> Result<Vec<InfoHash>, databases::error::Error> {
        self.database.load_whitelist()
    }
}

#[cfg(test)]
mod tests {
    use bittorrent_primitives::info_hash::InfoHash;

    fn sample_info_hash() -> InfoHash {
        "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap() // # DevSkim: ignore DS173237
    }

    mod in_memory_whitelist {

        use crate::core::whitelist::tests::sample_info_hash;
        use crate::core::whitelist::InMemoryWhitelist;

        #[tokio::test]
        async fn should_allow_adding_a_new_torrent_to_the_whitelist() {
            let info_hash = sample_info_hash();

            let whitelist = InMemoryWhitelist::new();

            whitelist.add(&info_hash).await;

            assert!(whitelist.contains(&info_hash).await);
        }

        #[tokio::test]
        async fn should_allow_removing_a_new_torrent_to_the_whitelist() {
            let info_hash = sample_info_hash();

            let whitelist = InMemoryWhitelist::new();

            whitelist.add(&info_hash).await;
            whitelist.remove(&sample_info_hash()).await;

            assert!(!whitelist.contains(&info_hash).await);
        }

        #[tokio::test]
        async fn should_allow_clearing_the_whitelist() {
            let info_hash = sample_info_hash();

            let whitelist = InMemoryWhitelist::new();

            whitelist.add(&info_hash).await;
            whitelist.clear().await;

            assert!(!whitelist.contains(&info_hash).await);
        }

        #[tokio::test]
        async fn should_allow_checking_if_an_infohash_is_whitelisted() {
            let info_hash = sample_info_hash();

            let whitelist = InMemoryWhitelist::new();

            whitelist.add(&info_hash).await;

            assert!(whitelist.contains(&info_hash).await);
        }
    }

    mod database_whitelist {}
}
