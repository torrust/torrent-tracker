use std::sync::Arc;

use crate::authentication::key::{Key, PeerKey};
use crate::databases::{self, Database};

/// The database repository for the authentication keys.
pub struct DatabaseKeyRepository {
    database: Arc<Box<dyn Database>>,
}

impl DatabaseKeyRepository {
    #[must_use]
    pub fn new(database: &Arc<Box<dyn Database>>) -> Self {
        Self {
            database: database.clone(),
        }
    }

    /// It adds a new key to the database.
    ///
    /// # Errors
    ///
    /// Will return a `databases::error::Error` if unable to add the `auth_key` to the database.
    pub fn add(&self, peer_key: &PeerKey) -> Result<(), databases::error::Error> {
        self.database.add_key_to_keys(peer_key)?;
        Ok(())
    }

    /// It removes an key from the database.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `key` from the database.
    pub fn remove(&self, key: &Key) -> Result<(), databases::error::Error> {
        self.database.remove_key_from_keys(key)?;
        Ok(())
    }

    /// It loads all keys from the database.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the keys from the database.
    pub fn load_keys(&self) -> Result<Vec<PeerKey>, databases::error::Error> {
        let keys = self.database.load_keys()?;
        Ok(keys)
    }
}
