//! This file contains only functions used for testing.
use std::sync::Arc;

use torrust_tracker_configuration::Configuration;

use crate::core::databases::Database;
use crate::core::services::initialize_database;
use crate::core::whitelist;
use crate::core::whitelist::repository::in_memory::InMemoryWhitelist;

/// Initialize the tracker dependencies.
#[allow(clippy::type_complexity)]
#[must_use]
pub fn initialize_tracker_dependencies(
    config: &Configuration,
) -> (
    Arc<Box<dyn Database>>,
    Arc<InMemoryWhitelist>,
    Arc<whitelist::authorization::Authorization>,
) {
    let database = initialize_database(config);
    let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
    let whitelist_authorization = Arc::new(whitelist::authorization::Authorization::new(
        &config.core,
        &in_memory_whitelist.clone(),
    ));

    (database, in_memory_whitelist, whitelist_authorization)
}
