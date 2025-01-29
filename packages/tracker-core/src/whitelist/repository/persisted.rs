use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;

use crate::databases::{self, Database};

/// The persisted list of allowed torrents.
pub struct DatabaseWhitelist {
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
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `info_hash` to the whitelist database.
    pub fn add(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
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
    pub fn remove(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
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
    pub fn load_from_database(&self) -> Result<Vec<InfoHash>, databases::error::Error> {
        self.database.load_whitelist()
    }
}
