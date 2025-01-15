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
use super::whitelist::persisted::DatabaseWhitelist;
use super::whitelist::WhiteListManager;
use crate::core::Tracker;

/// It returns a new tracker building its dependencies.
///
/// # Panics
///
/// Will panic if tracker cannot be instantiated.
#[must_use]
pub fn tracker_factory(config: &Configuration) -> Tracker {
    let database = initialize_database(config);

    let whitelist_manager = initialize_whitelist(database.clone());

    let (stats_event_sender, stats_repository) = statistics::setup::factory(config.core.tracker_usage_statistics);

    match Tracker::new(
        &Arc::new(config).core,
        &database,
        &whitelist_manager,
        stats_event_sender,
        stats_repository,
    ) {
        Ok(tracker) => tracker,
        Err(error) => {
            panic!("{}", error)
        }
    }
}

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
pub fn initialize_whitelist(database: Arc<Box<dyn Database>>) -> Arc<WhiteListManager> {
    let database_whitelist = Arc::new(DatabaseWhitelist::new(database));
    Arc::new(WhiteListManager::new(database_whitelist))
}
