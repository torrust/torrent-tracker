use std::sync::Arc;

use torrust_tracker_configuration::Configuration;

use super::authorization::WhitelistAuthorization;
use super::manager::WhiteListManager;
use super::repository::in_memory::InMemoryWhitelist;
use crate::core::services::{initialize_database, initialize_whitelist_manager};

#[must_use]
pub fn initialize_whitelist_services(config: &Configuration) -> (Arc<WhitelistAuthorization>, Arc<WhiteListManager>) {
    let database = initialize_database(config);
    let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
    let whitelist_authorization = Arc::new(WhitelistAuthorization::new(&config.core, &in_memory_whitelist.clone()));
    let whitelist_manager = initialize_whitelist_manager(database.clone(), in_memory_whitelist.clone());

    (whitelist_authorization, whitelist_manager)
}

#[cfg(test)]
#[must_use]
pub fn initialize_whitelist_services_for_listed_tracker() -> (Arc<WhitelistAuthorization>, Arc<WhiteListManager>) {
    use torrust_tracker_test_helpers::configuration;

    initialize_whitelist_services(&configuration::ephemeral_listed())
}
