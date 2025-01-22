//! This file contains only functions used for testing.
use std::sync::Arc;

use torrust_tracker_configuration::Configuration;

use crate::core::authentication::handler::KeysHandler;
use crate::core::authentication::key::repository::in_memory::InMemoryKeyRepository;
use crate::core::authentication::key::repository::persisted::DatabaseKeyRepository;
use crate::core::authentication::service::{self, AuthenticationService};
use crate::core::databases::Database;
use crate::core::services::initialize_database;
use crate::core::whitelist::repository::in_memory::InMemoryWhitelist;
use crate::core::{authentication, whitelist};

/// Initialize the tracker dependencies.
#[allow(clippy::type_complexity)]
#[must_use]
pub fn initialize_tracker_dependencies(
    config: &Configuration,
) -> (
    Arc<Box<dyn Database>>,
    Arc<InMemoryWhitelist>,
    Arc<whitelist::authorization::Authorization>,
    Arc<authentication::Facade>,
    Arc<AuthenticationService>,
) {
    let database = initialize_database(config);
    let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
    let whitelist_authorization = Arc::new(whitelist::authorization::Authorization::new(
        &config.core,
        &in_memory_whitelist.clone(),
    ));
    let db_key_repository = Arc::new(DatabaseKeyRepository::new(&database));
    let in_memory_key_repository = Arc::new(InMemoryKeyRepository::default());
    let authentication_service = Arc::new(service::AuthenticationService::new(&config.core, &in_memory_key_repository));
    let keys_handler = Arc::new(KeysHandler::new(
        &db_key_repository.clone(),
        &in_memory_key_repository.clone(),
    ));
    let authentication_facade = Arc::new(authentication::Facade::new(&keys_handler));

    (
        database,
        in_memory_whitelist,
        whitelist_authorization,
        authentication_facade,
        authentication_service,
    )
}
