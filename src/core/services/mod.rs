//! Tracker domain services. Core and statistics services.
//!
//! There are two types of service:
//!
//! - [Core tracker services](crate::core::services::torrent): related to the tracker main functionalities like getting info about torrents.
//! - [Services for statistics](crate::core::services::statistics): related to tracker metrics. Aggregate data about the tracker server.
pub mod statistics;
pub mod torrent;

use std::sync::Arc;

use databases::driver::Driver;
use torrust_tracker_configuration::v2_0_0::database;
use torrust_tracker_configuration::Configuration;

use super::databases::{self, Database};
use super::whitelist::manager::WhiteListManager;
use super::whitelist::repository::in_memory::InMemoryWhitelist;
use super::whitelist::repository::persisted::DatabaseWhitelist;

/// # Panics
///
/// Will panic if database cannot be initialized.
#[must_use]
pub fn initialize_database(config: &Configuration) -> Arc<Box<dyn Database>> {
    let driver = match config.core.database.driver {
        database::Driver::Sqlite3 => Driver::Sqlite3,
        database::Driver::MySQL => Driver::MySQL,
    };

    Arc::new(databases::driver::build(&driver, &config.core.database.path).expect("Database driver build failed."))
}

#[must_use]
pub fn initialize_whitelist_manager(
    database: Arc<Box<dyn Database>>,
    in_memory_whitelist: Arc<InMemoryWhitelist>,
) -> Arc<WhiteListManager> {
    let database_whitelist = Arc::new(DatabaseWhitelist::new(database));
    Arc::new(WhiteListManager::new(database_whitelist, in_memory_whitelist))
}
