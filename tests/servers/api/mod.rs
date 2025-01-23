use std::sync::Arc;

use torrust_tracker_lib::core::databases::Database;
use torrust_tracker_lib::servers::apis::server;

pub mod connection_info;
pub mod environment;
pub mod v1;

pub type Started = environment::Environment<server::Running>;

/// It forces a database error by dropping all tables. That makes all queries
/// fail.
///
/// code-review:
///
/// Alternatively we could:
///
/// - Inject a database mock in the future.
/// - Inject directly the database reference passed to the Tracker type.
pub fn force_database_error(tracker: &Arc<Box<dyn Database>>) {
    tracker.drop_database_tables().unwrap();
}
