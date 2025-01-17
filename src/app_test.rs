//! This file contains only functions used for testing.
use std::sync::Arc;

use torrust_tracker_configuration::Configuration;

use crate::core::databases::Database;
use crate::core::services::{initialize_database, initialize_whitelist};
use crate::core::whitelist::WhiteListManager;

/// Initialize the tracker dependencies.
#[allow(clippy::type_complexity)]
#[must_use]
pub fn initialize_tracker_dependencies(config: &Configuration) -> (Arc<Box<dyn Database>>, Arc<WhiteListManager>) {
    let database = initialize_database(config);
    let whitelist_manager = initialize_whitelist(database.clone());

    (database, whitelist_manager)
}
