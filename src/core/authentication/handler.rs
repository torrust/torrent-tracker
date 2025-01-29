use std::sync::Arc;
use std::time::Duration;

use torrust_tracker_clock::clock::Time;
use torrust_tracker_located_error::Located;
use torrust_tracker_primitives::DurationSinceUnixEpoch;

use super::key::repository::in_memory::InMemoryKeyRepository;
use super::key::repository::persisted::DatabaseKeyRepository;
use super::{key, CurrentClock, Key, PeerKey};
use crate::core::databases;
use crate::core::error::PeerKeyError;

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

pub struct KeysHandler {
    /// The database repository for the authentication keys.
    db_key_repository: Arc<DatabaseKeyRepository>,

    /// In-memory implementation of the authentication key repository.
    in_memory_key_repository: Arc<InMemoryKeyRepository>,
}

impl KeysHandler {
    #[must_use]
    pub fn new(db_key_repository: &Arc<DatabaseKeyRepository>, in_memory_key_repository: &Arc<InMemoryKeyRepository>) -> Self {
        Self {
            db_key_repository: db_key_repository.clone(),
            in_memory_key_repository: in_memory_key_repository.clone(),
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
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    ///
    /// # Arguments
    ///
    /// * `lifetime` - The duration in seconds for the new key. The key will be
    ///   no longer valid after `lifetime` seconds.
    pub async fn generate_auth_key(&self, lifetime: Option<Duration>) -> Result<PeerKey, databases::error::Error> {
        let peer_key = key::generate_key(lifetime);

        self.db_key_repository.add(&peer_key)?;

        self.in_memory_key_repository.insert(&peer_key).await;

        Ok(peer_key)
    }

    /// It adds a pre-generated permanent authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
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
        let peer_key = PeerKey { key, valid_until };

        // code-review: should we return a friendly error instead of the DB
        // constrain error when the key already exist? For now, it's returning
        // the specif error for each DB driver when a UNIQUE constrain fails.
        self.db_key_repository.add(&peer_key)?;

        self.in_memory_key_repository.insert(&peer_key).await;

        Ok(peer_key)
    }

    /// It removes an authentication key.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `key` to the database.
    pub async fn remove_auth_key(&self, key: &Key) -> Result<(), databases::error::Error> {
        self.db_key_repository.remove(key)?;

        self.remove_in_memory_auth_key(key).await;

        Ok(())
    }

    /// It removes an authentication key from memory.
    pub async fn remove_in_memory_auth_key(&self, key: &Key) {
        self.in_memory_key_repository.remove(key).await;
    }

    /// The `Tracker` stores the authentication keys in memory and in the
    /// database. In case you need to restart the `Tracker` you can load the
    /// keys from the database into memory with this function. Keys are
    /// automatically stored in the database when they are generated.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to `load_keys` from the database.
    pub async fn load_keys_from_database(&self) -> Result<(), databases::error::Error> {
        let keys_from_database = self.db_key_repository.load_keys()?;

        self.in_memory_key_repository.reset_with(keys_from_database).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    mod the_keys_handler_when_tracker_is_configured_as_private {

        use std::sync::Arc;

        use torrust_tracker_configuration::v2_0_0::core::PrivateMode;
        use torrust_tracker_configuration::Configuration;
        use torrust_tracker_test_helpers::configuration;

        use crate::core::authentication::handler::KeysHandler;
        use crate::core::authentication::key::repository::in_memory::InMemoryKeyRepository;
        use crate::core::authentication::key::repository::persisted::DatabaseKeyRepository;
        use crate::core::databases::setup::initialize_database;

        fn instantiate_keys_handler() -> KeysHandler {
            let config = configuration::ephemeral_private();

            instantiate_keys_handler_with_configuration(&config)
        }

        #[allow(dead_code)]
        fn instantiate_keys_handler_with_checking_keys_expiration_disabled() -> KeysHandler {
            let mut config = configuration::ephemeral_private();

            config.core.private_mode = Some(PrivateMode {
                check_keys_expiration: false,
            });

            instantiate_keys_handler_with_configuration(&config)
        }

        fn instantiate_keys_handler_with_configuration(config: &Configuration) -> KeysHandler {
            let database = initialize_database(config);
            let db_key_repository = Arc::new(DatabaseKeyRepository::new(&database));
            let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());

            KeysHandler::new(&db_key_repository, &in_memory_key_repository)
        }

        mod with_expiring_and {

            mod randomly_generated_keys {
                use std::time::Duration;

                use torrust_tracker_clock::clock::Time;

                use crate::core::authentication::handler::tests::the_keys_handler_when_tracker_is_configured_as_private::instantiate_keys_handler;
                use crate::CurrentClock;

                #[tokio::test]
                async fn it_should_generate_the_key() {
                    let keys_handler = instantiate_keys_handler();

                    let peer_key = keys_handler.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

                    assert_eq!(
                        peer_key.valid_until,
                        Some(CurrentClock::now_add(&Duration::from_secs(100)).unwrap())
                    );
                }
            }

            mod pre_generated_keys {
                use std::time::Duration;

                use torrust_tracker_clock::clock::Time;

                use crate::core::authentication::handler::tests::the_keys_handler_when_tracker_is_configured_as_private::instantiate_keys_handler;
                use crate::core::authentication::handler::AddKeyRequest;
                use crate::core::authentication::Key;
                use crate::CurrentClock;

                #[tokio::test]
                async fn it_should_add_a_pre_generated_key() {
                    let keys_handler = instantiate_keys_handler();

                    let peer_key = keys_handler
                        .add_peer_key(AddKeyRequest {
                            opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                            opt_seconds_valid: Some(100),
                        })
                        .await
                        .unwrap();

                    assert_eq!(
                        peer_key.valid_until,
                        Some(CurrentClock::now_add(&Duration::from_secs(100)).unwrap())
                    );
                }
            }
        }

        mod with_permanent_and {

            mod randomly_generated_keys {
                use crate::core::authentication::handler::tests::the_keys_handler_when_tracker_is_configured_as_private::instantiate_keys_handler;

                #[tokio::test]
                async fn it_should_generate_the_key() {
                    let keys_handler = instantiate_keys_handler();

                    let peer_key = keys_handler.generate_permanent_auth_key().await.unwrap();

                    assert_eq!(peer_key.valid_until, None);
                }
            }

            mod pre_generated_keys {

                use crate::core::authentication::handler::tests::the_keys_handler_when_tracker_is_configured_as_private::instantiate_keys_handler;
                use crate::core::authentication::handler::AddKeyRequest;
                use crate::core::authentication::Key;

                #[tokio::test]
                async fn it_should_add_a_pre_generated_key() {
                    let keys_handler = instantiate_keys_handler();

                    let peer_key = keys_handler
                        .add_peer_key(AddKeyRequest {
                            opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                            opt_seconds_valid: None,
                        })
                        .await
                        .unwrap();

                    assert_eq!(peer_key.valid_until, None);
                }
            }
        }
    }
}
