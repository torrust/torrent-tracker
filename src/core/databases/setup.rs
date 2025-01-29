use std::sync::Arc;

use torrust_tracker_configuration::v2_0_0::database;
use torrust_tracker_configuration::Configuration;

use super::driver::{self, Driver};
use super::Database;

/// # Panics
///
/// Will panic if database cannot be initialized.
#[must_use]
pub fn initialize_database(config: &Configuration) -> Arc<Box<dyn Database>> {
    let driver = match config.core.database.driver {
        database::Driver::Sqlite3 => Driver::Sqlite3,
        database::Driver::MySQL => Driver::MySQL,
    };

    Arc::new(driver::build(&driver, &config.core.database.path).expect("Database driver build failed."))
}
