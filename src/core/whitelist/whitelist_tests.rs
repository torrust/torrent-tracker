use std::sync::Arc;

use torrust_tracker_configuration::Configuration;

use super::authorization::WhitelistAuthorization;
use super::manager::WhitelistManager;
use super::repository::in_memory::InMemoryWhitelist;
use crate::core::databases::setup::initialize_database;
use crate::core::services::initialize_whitelist_manager;

#[must_use]
pub fn initialize_whitelist_services(config: &Configuration) -> (Arc<WhitelistAuthorization>, Arc<WhitelistManager>) {
    let database = initialize_database(config);
    let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
    let whitelist_authorization = Arc::new(WhitelistAuthorization::new(&config.core, &in_memory_whitelist.clone()));
    let whitelist_manager = initialize_whitelist_manager(database.clone(), in_memory_whitelist.clone());

    (whitelist_authorization, whitelist_manager)
}

#[cfg(test)]
#[must_use]
pub fn initialize_whitelist_services_for_listed_tracker() -> (Arc<WhitelistAuthorization>, Arc<WhitelistManager>) {
    use torrust_tracker_test_helpers::configuration;

    initialize_whitelist_services(&configuration::ephemeral_listed())
}
