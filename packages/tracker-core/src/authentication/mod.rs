use crate::CurrentClock;

pub mod handler;
pub mod key;
pub mod service;

pub type PeerKey = key::PeerKey;
pub type Key = key::Key;
pub type Error = key::Error;

#[cfg(test)]
mod tests {

    // Integration tests for authentication.

    mod the_tracker_configured_as_private {

        use std::sync::Arc;
        use std::time::Duration;

        use torrust_tracker_configuration::v2_0_0::core::PrivateMode;
        use torrust_tracker_configuration::Configuration;
        use torrust_tracker_test_helpers::configuration;

        use crate::authentication::handler::KeysHandler;
        use crate::authentication::key::repository::in_memory::InMemoryKeyRepository;
        use crate::authentication::key::repository::persisted::DatabaseKeyRepository;
        use crate::authentication::service;
        use crate::authentication::service::AuthenticationService;
        use crate::databases::setup::initialize_database;

        fn instantiate_keys_manager_and_authentication() -> (Arc<KeysHandler>, Arc<AuthenticationService>) {
            let config = configuration::ephemeral_private();

            instantiate_keys_manager_and_authentication_with_configuration(&config)
        }

        fn instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled(
        ) -> (Arc<KeysHandler>, Arc<AuthenticationService>) {
            let mut config = configuration::ephemeral_private();

            config.core.private_mode = Some(PrivateMode {
                check_keys_expiration: false,
            });

            instantiate_keys_manager_and_authentication_with_configuration(&config)
        }

        fn instantiate_keys_manager_and_authentication_with_configuration(
            config: &Configuration,
        ) -> (Arc<KeysHandler>, Arc<AuthenticationService>) {
            let database = initialize_database(config);
            let db_key_repository = Arc::new(DatabaseKeyRepository::new(&database));
            let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());
            let authentication_service = Arc::new(service::AuthenticationService::new(&config.core, &in_memory_key_repository));
            let keys_handler = Arc::new(KeysHandler::new(
                &db_key_repository.clone(),
                &in_memory_key_repository.clone(),
            ));

            (keys_handler, authentication_service)
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

                use crate::authentication::tests::the_tracker_configured_as_private::{
                    instantiate_keys_manager_and_authentication,
                    instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled,
                };
                use crate::authentication::Key;

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

                use crate::authentication::handler::AddKeyRequest;
                use crate::authentication::tests::the_tracker_configured_as_private::{
                    instantiate_keys_manager_and_authentication,
                    instantiate_keys_manager_and_authentication_with_checking_keys_expiration_disabled,
                };
                use crate::authentication::Key;

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
                use crate::authentication::tests::the_tracker_configured_as_private::instantiate_keys_manager_and_authentication;

                #[tokio::test]
                async fn it_should_authenticate_a_peer_with_the_key() {
                    let (keys_manager, authentication_service) = instantiate_keys_manager_and_authentication();

                    let peer_key = keys_manager.generate_permanent_auth_key().await.unwrap();

                    let result = authentication_service.authenticate(&peer_key.key()).await;

                    assert!(result.is_ok());
                }
            }

            mod pre_generated_keys {
                use crate::authentication::handler::AddKeyRequest;
                use crate::authentication::tests::the_tracker_configured_as_private::instantiate_keys_manager_and_authentication;
                use crate::authentication::Key;

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
