use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;

use torrust_tracker_clock::clock::Time;
use torrust_tracker_configuration::Core;
use torrust_tracker_located_error::Located;
use torrust_tracker_primitives::DurationSinceUnixEpoch;

use super::databases::{self, Database};
use super::error::PeerKeyError;
use crate::CurrentClock;

pub mod key;

pub type PeerKey = key::PeerKey;
pub type Key = key::Key;
pub type Error = key::Error;

/// This type contains the info needed to add a new tracker key.
///
/// You can upload a pre-generated key or let the app to generate a new one.
/// You can also set an expiration date or leave it empty (`None`) if you want
/// to create a permanent key that does not expire.
#[derive(Debug)]
pub struct AddKeyRequest {
    /// The pre-generated key. Use `None` to generate a random key.
    pub opt_key: Option<String>,

    /// How long the key will be valid in seconds. Use `None` for permanent keys.
    pub opt_seconds_valid: Option<u64>,
}

pub struct Facade {
    /// The tracker configuration.
    config: Core,

    /// A database driver implementation: [`Sqlite3`](crate::core::databases::sqlite)
    /// or [`MySQL`](crate::core::databases::mysql)
    database: Arc<Box<dyn Database>>,

    /// Tracker users' keys. Only for private trackers.
    keys: tokio::sync::RwLock<std::collections::HashMap<Key, PeerKey>>,
}

impl Facade {
    #[must_use]
    pub fn new(config: &Core, database: &Arc<Box<dyn Database>>) -> Self {
        Self {
            config: config.clone(),
            database: database.clone(),
            keys: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// It authenticates the peer `key` against the `Tracker` authentication
    /// key list.
    ///
    /// # Errors
    ///
    /// Will return an error if the the authentication key cannot be verified.
    ///
    /// # Context: Authentication
    pub async fn authenticate(&self, key: &Key) -> Result<(), Error> {
        if self.is_private() {
            self.verify_auth_key(key).await
        } else {
            Ok(())
        }
    }

    /// Returns `true` is the tracker is in private mode.
    pub fn is_private(&self) -> bool {
        self.config.private
    }

    /// It verifies an authentication key.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `key::Error` if unable to get any `auth_key`.
    pub async fn verify_auth_key(&self, key: &Key) -> Result<(), Error> {
        match self.keys.read().await.get(key) {
            None => Err(Error::UnableToReadKey {
                location: Location::caller(),
                key: Box::new(key.clone()),
            }),
            Some(key) => match self.config.private_mode {
                Some(private_mode) => {
                    if private_mode.check_keys_expiration {
                        return key::verify_key_expiration(key);
                    }

                    Ok(())
                }
                None => key::verify_key_expiration(key),
            },
        }
    }

    /// Adds new peer keys to the tracker.
    ///
    /// Keys can be pre-generated or randomly created. They can also be permanent or expire.
    ///
    /// # Errors
    ///
    /// Will return an error if:
    ///
    /// - The key duration overflows the duration type maximum value.
    /// - The provided pre-generated key is invalid.
    /// - The key could not been persisted due to database issues.
    pub async fn add_peer_key(&self, add_key_req: AddKeyRequest) -> Result<PeerKey, PeerKeyError> {
        // code-review: all methods related to keys should be moved to a new independent "keys" service.

        match add_key_req.opt_key {
            // Upload pre-generated key
            Some(pre_existing_key) => {
                if let Some(seconds_valid) = add_key_req.opt_seconds_valid {
                    // Expiring key
                    let Some(valid_until) = CurrentClock::now_add(&Duration::from_secs(seconds_valid)) else {
                        return Err(PeerKeyError::DurationOverflow { seconds_valid });
                    };

                    let key = pre_existing_key.parse::<Key>();

                    match key {
                        Ok(key) => match self.add_auth_key(key, Some(valid_until)).await {
                            Ok(auth_key) => Ok(auth_key),
                            Err(err) => Err(PeerKeyError::DatabaseError {
                                source: Located(err).into(),
                            }),
                        },
                        Err(err) => Err(PeerKeyError::InvalidKey {
                            key: pre_existing_key,
                            source: Located(err).into(),
                        }),
                    }
                } else {
                    // Permanent key
                    let key = pre_existing_key.parse::<Key>();

                    match key {
                        Ok(key) => match self.add_permanent_auth_key(key).await {
                            Ok(auth_key) => Ok(auth_key),
                            Err(err) => Err(PeerKeyError::DatabaseError {
                                source: Located(err).into(),
                            }),
                        },
                        Err(err) => Err(PeerKeyError::InvalidKey {
                            key: pre_existing_key,
                            source: Located(err).into(),
                        }),
                    }
                }
            }
            // Generate a new random key
            None => match add_key_req.opt_seconds_valid {
                // Expiring key
                Some(seconds_valid) => match self.generate_auth_key(Some(Duration::from_secs(seconds_valid))).await {
                    Ok(auth_key) => Ok(auth_key),
                    Err(err) => Err(PeerKeyError::DatabaseError {
                        source: Located(err).into(),
                    }),
                },
                // Permanent key
                None => match self.generate_permanent_auth_key().await {
                    Ok(auth_key) => Ok(auth_key),
                    Err(err) => Err(PeerKeyError::DatabaseError {
                        source: Located(err).into(),
                    }),
                },
            },
        }
    }

    /// It generates a new permanent authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    pub async fn generate_permanent_auth_key(&self) -> Result<PeerKey, databases::error::Error> {
        self.generate_auth_key(None).await
    }

    /// It generates a new expiring authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    ///
    /// # Arguments
    ///
    /// * `lifetime` - The duration in seconds for the new key. The key will be
    ///   no longer valid after `lifetime` seconds.
    pub async fn generate_auth_key(&self, lifetime: Option<Duration>) -> Result<PeerKey, databases::error::Error> {
        let auth_key = key::generate_key(lifetime);

        self.database.add_key_to_keys(&auth_key)?;
        self.keys.write().await.insert(auth_key.key.clone(), auth_key.clone());
        Ok(auth_key)
    }

    /// It adds a pre-generated permanent authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the
    /// database. For example, if the key already exist.
    ///
    /// # Arguments
    ///
    /// * `key` - The pre-generated key.
    pub async fn add_permanent_auth_key(&self, key: Key) -> Result<PeerKey, databases::error::Error> {
        self.add_auth_key(key, None).await
    }

    /// It adds a pre-generated authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the
    /// database. For example, if the key already exist.
    ///
    /// # Arguments
    ///
    /// * `key` - The pre-generated key.
    /// * `lifetime` - The duration in seconds for the new key. The key will be
    ///   no longer valid after `lifetime` seconds.
    pub async fn add_auth_key(
        &self,
        key: Key,
        valid_until: Option<DurationSinceUnixEpoch>,
    ) -> Result<PeerKey, databases::error::Error> {
        let auth_key = PeerKey { key, valid_until };

        // code-review: should we return a friendly error instead of the DB
        // constrain error when the key already exist? For now, it's returning
        // the specif error for each DB driver when a UNIQUE constrain fails.
        self.database.add_key_to_keys(&auth_key)?;
        self.keys.write().await.insert(auth_key.key.clone(), auth_key.clone());
        Ok(auth_key)
    }

    /// It removes an authentication key.
    ///
    /// # Context: Authentication    
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `key` to the database.
    pub async fn remove_auth_key(&self, key: &Key) -> Result<(), databases::error::Error> {
        self.database.remove_key_from_keys(key)?;
        self.remove_in_memory_auth_key(key).await;
        Ok(())
    }

    /// It removes an authentication key from memory.
    ///
    /// # Context: Authentication    
    pub async fn remove_in_memory_auth_key(&self, key: &Key) {
        self.keys.write().await.remove(key);
    }

    /// The `Tracker` stores the authentication keys in memory and in the database.
    /// In case you need to restart the `Tracker` you can load the keys from the database
    /// into memory with this function. Keys are automatically stored in the database when they
    /// are generated.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to `load_keys` from the database.
    pub async fn load_keys_from_database(&self) -> Result<(), databases::error::Error> {
        let keys_from_database = self.database.load_keys()?;
        let mut keys = self.keys.write().await;

        keys.clear();

        for key in keys_from_database {
            keys.insert(key.key.clone(), key);
        }

        Ok(())
    }
}
