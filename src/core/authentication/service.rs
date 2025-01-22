use std::panic::Location;
use std::sync::Arc;

use torrust_tracker_configuration::Core;

use super::key::repository::in_memory::InMemoryKeyRepository;
use super::{key, Error, Key};

#[derive(Debug)]
pub struct AuthenticationService {
    /// The tracker configuration.
    config: Core,

    /// In-memory implementation of the authentication key repository.
    in_memory_key_repository: Arc<InMemoryKeyRepository>,
}

impl AuthenticationService {
    #[must_use]
    pub fn new(config: &Core, in_memory_key_repository: &Arc<InMemoryKeyRepository>) -> Self {
        Self {
            config: config.clone(),
            in_memory_key_repository: in_memory_key_repository.clone(),
        }
    }

    /// It authenticates the peer `key` against the `Tracker` authentication
    /// key list.
    ///
    /// # Errors
    ///
    /// Will return an error if the the authentication key cannot be verified.
    pub async fn authenticate(&self, key: &Key) -> Result<(), Error> {
        if self.is_private() {
            self.verify_auth_key(key).await
        } else {
            Ok(())
        }
    }

    /// Returns `true` is the tracker is in private mode.
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.config.private
    }

    /// It verifies an authentication key.
    ///
    /// # Errors
    ///
    /// Will return a `key::Error` if unable to get any `auth_key`.
    async fn verify_auth_key(&self, key: &Key) -> Result<(), Error> {
        match self.in_memory_key_repository.get(key).await {
            None => Err(Error::UnableToReadKey {
                location: Location::caller(),
                key: Box::new(key.clone()),
            }),
            Some(key) => match self.config.private_mode {
                Some(private_mode) => {
                    if private_mode.check_keys_expiration {
                        return key::verify_key_expiration(&key);
                    }

                    Ok(())
                }
                None => key::verify_key_expiration(&key),
            },
        }
    }
}

#[cfg(test)]
mod tests {

    mod the_tracker_configured_as_private {

        use std::str::FromStr;
        use std::sync::Arc;

        use torrust_tracker_test_helpers::configuration;

        use crate::core::authentication;
        use crate::core::authentication::key::repository::in_memory::InMemoryKeyRepository;
        use crate::core::authentication::service::AuthenticationService;

        fn instantiate_authentication() -> AuthenticationService {
            let config = configuration::ephemeral_private();

            let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());

            AuthenticationService::new(&config.core, &in_memory_key_repository.clone())
        }

        #[tokio::test]
        async fn it_should_not_authenticate_an_unregistered_key() {
            let authentication = instantiate_authentication();

            let unregistered_key = authentication::Key::from_str("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap();

            let result = authentication.authenticate(&unregistered_key).await;

            assert!(result.is_err());
        }
    }
}
