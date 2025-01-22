use std::sync::Arc;
use std::time::Duration;

use handler::AddKeyRequest;
use torrust_tracker_primitives::DurationSinceUnixEpoch;

use super::databases::{self};
use super::error::PeerKeyError;
use crate::CurrentClock;

pub mod handler;
pub mod key;
pub mod service;

pub type PeerKey = key::PeerKey;
pub type Key = key::Key;
pub type Error = key::Error;

pub struct Facade {
    /// The keys handler.
    keys_handler: Arc<handler::KeysHandler>,
}

impl Facade {
    #[must_use]
    pub fn new(keys_handler: &Arc<handler::KeysHandler>) -> Self {
        Self {
            keys_handler: keys_handler.clone(),
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
        self.keys_handler.add_peer_key(add_key_req).await
    }

    /// It generates a new permanent authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    pub async fn generate_permanent_auth_key(&self) -> Result<PeerKey, databases::error::Error> {
        self.keys_handler.generate_permanent_auth_key().await
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
        self.keys_handler.generate_auth_key(lifetime).await
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
        self.keys_handler.add_auth_key(key, valid_until).await
    }

    /// It removes an authentication key.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `key` to the database.
    pub async fn remove_auth_key(&self, key: &Key) -> Result<(), databases::error::Error> {
        self.keys_handler.remove_auth_key(key).await
    }

    /// It removes an authentication key from memory.
    pub async fn remove_in_memory_auth_key(&self, key: &Key) {
        self.keys_handler.remove_in_memory_auth_key(key).await;
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
        self.keys_handler.load_keys_from_database().await
    }
}

#[cfg(test)]
mod tests {

    mod the_tracker_configured_as_private {

        use std::sync::Arc;
        use std::time::Duration;

        use torrust_tracker_configuration::v2_0_0::core::PrivateMode;
        use torrust_tracker_configuration::Configuration;
        use torrust_tracker_test_helpers::configuration;

        use crate::core::authentication::handler::KeysHandler;
        use crate::core::authentication::key::repository::in_memory::InMemoryKeyRepository;
        use crate::core::authentication::key::repository::persisted::DatabaseKeyRepository;
        use crate::core::authentication::service::AuthenticationService;
        use crate::core::authentication::{self, service};
        use crate::core::services::initialize_database;

        fn instantiate_keys_manager_and_authentication() -> (authentication::Facade, Arc<AuthenticationService>) {
            let config = configuration::ephemeral_private();

            instantiate_keys_manager_and_authentication_with_configuration(&config)
        }

        fn instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled(
        ) -> (authentication::Facade, Arc<AuthenticationService>) {
            let mut config = configuration::ephemeral_private();

            config.core.private_mode = Some(PrivateMode {
                check_keys_expiration: false,
            });

            instantiate_keys_manager_and_authentication_with_configuration(&config)
        }

        fn instantiate_keys_manager_and_authentication_with_configuration(
            config: &Configuration,
        ) -> (authentication::Facade, Arc<AuthenticationService>) {
            let database = initialize_database(config);

            let db_key_repository = Arc::new(DatabaseKeyRepository::new(&database));
            let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());

            let authentication_service = Arc::new(service::AuthenticationService::new(&config.core, &in_memory_key_repository));
            let keys_handler = Arc::new(KeysHandler::new(
                &db_key_repository.clone(),
                &in_memory_key_repository.clone(),
            ));

            let facade = authentication::Facade::new(&keys_handler);

            (facade, authentication_service)
        }

        #[tokio::test]
        async fn it_should_remove_an_authentication_key() {
            let (keys_manager, authentication_service) = instantiate_keys_manager_and_authentication();

            let expiring_key = keys_manager.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

            let result = keys_manager.remove_auth_key(&expiring_key.key()).await;

            assert!(result.is_ok());

            // The key should no longer be valid
            assert!(authentication_service.authenticate(&expiring_key.key()).await.is_err());
        }

        #[tokio::test]
        async fn it_should_load_authentication_keys_from_the_database() {
            let (keys_manager, authentication_service) = instantiate_keys_manager_and_authentication();

            let expiring_key = keys_manager.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

            // Remove the newly generated key in memory
            keys_manager.remove_in_memory_auth_key(&expiring_key.key()).await;

            let result = keys_manager.load_keys_from_database().await;

            assert!(result.is_ok());

            // The key should no longer be valid
            assert!(authentication_service.authenticate(&expiring_key.key()).await.is_ok());
        }

        mod with_expiring_and {

            mod randomly_generated_keys {
                use std::time::Duration;

                use crate::core::authentication::tests::the_tracker_configured_as_private::{
                    instantiate_keys_manager_and_authentication,
                    instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled,
                };
                use crate::core::authentication::Key;

                #[tokio::test]
                async fn it_should_authenticate_a_peer_with_the_key() {
                    let (keys_manager, authentication_service) = instantiate_keys_manager_and_authentication();

                    let peer_key = keys_manager.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

                    let result = authentication_service.authenticate(&peer_key.key()).await;

                    assert!(result.is_ok());
                }

                #[tokio::test]
                async fn it_should_accept_an_expired_key_when_checking_expiration_is_disabled_in_configuration() {
                    let (keys_manager, authentication_service) =
                        instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled();

                    let past_timestamp = Duration::ZERO;

                    let peer_key = keys_manager
                        .add_auth_key(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap(), Some(past_timestamp))
                        .await
                        .unwrap();

                    assert!(authentication_service.authenticate(&peer_key.key()).await.is_ok());
                }
            }

            mod pre_generated_keys {

                use crate::core::authentication::tests::the_tracker_configured_as_private::{
                    instantiate_keys_manager_and_authentication,
                    instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled,
                };
                use crate::core::authentication::{AddKeyRequest, Key};

                #[tokio::test]
                async fn it_should_authenticate_a_peer_with_the_key() {
                    let (keys_manager, authentication_service) = instantiate_keys_manager_and_authentication();

                    let peer_key = keys_manager
                        .add_peer_key(AddKeyRequest {
                            opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                            opt_seconds_valid: Some(100),
                        })
                        .await
                        .unwrap();

                    let result = authentication_service.authenticate(&peer_key.key()).await;

                    assert!(result.is_ok());
                }

                #[tokio::test]
                async fn it_should_accept_an_expired_key_when_checking_expiration_is_disabled_in_configuration() {
                    let (keys_manager, authentication_service) =
                        instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled();

                    let peer_key = keys_manager
                        .add_peer_key(AddKeyRequest {
                            opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                            opt_seconds_valid: Some(0),
                        })
                        .await
                        .unwrap();

                    assert!(authentication_service.authenticate(&peer_key.key()).await.is_ok());
                }
            }
        }

        mod with_permanent_and {

            mod randomly_generated_keys {
                use crate::core::authentication::tests::the_tracker_configured_as_private::instantiate_keys_manager_and_authentication;

                #[tokio::test]
                async fn it_should_authenticate_a_peer_with_the_key() {
                    let (keys_manager, authentication_service) = instantiate_keys_manager_and_authentication();

                    let peer_key = keys_manager.generate_permanent_auth_key().await.unwrap();

                    let result = authentication_service.authenticate(&peer_key.key()).await;

                    assert!(result.is_ok());
                }
            }

            mod pre_generated_keys {
                use crate::core::authentication::tests::the_tracker_configured_as_private::instantiate_keys_manager_and_authentication;
                use crate::core::authentication::{AddKeyRequest, Key};

                #[tokio::test]
                async fn it_should_authenticate_a_peer_with_the_key() {
                    let (keys_manager, authentication_service) = instantiate_keys_manager_and_authentication();

                    let peer_key = keys_manager
                        .add_peer_key(AddKeyRequest {
                            opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                            opt_seconds_valid: None,
                        })
                        .await
                        .unwrap();

                    let result = authentication_service.authenticate(&peer_key.key()).await;

                    assert!(result.is_ok());
                }
            }
        }
    }
}
