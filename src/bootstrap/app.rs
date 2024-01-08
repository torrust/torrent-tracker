//! Setup for the main tracker application.
//!
//! The [`setup`] only builds the application and its dependencies but it does not start the application.
//! In fact, there is no such thing as the main application process. When the application starts, the only thing it does is
//! starting a bunch of independent jobs. If you are looking for how things are started you should read [`app::start`](crate::app::start)
//! function documentation.
//!
//! Setup steps:
//!
//! 1. Load the global application configuration.
//! 2. Initialize static variables.
//! 3. Initialize logging.
//! 4. Initialize the domain tracker.
use std::sync::Arc;

use torrust_tracker_configuration::Configuration;

use super::config::initialize_configuration;
use crate::bootstrap;
use crate::core::services::tracker_factory;
use crate::core::Tracker;
use crate::shared::clock::static_time;
use crate::shared::crypto::ephemeral_instance_keys;

/// It loads the configuration from the environment and builds the main domain [`Tracker`] struct.
#[must_use]
pub fn setup() -> (Arc<Configuration>, Arc<Tracker>) {
    let configuration = Arc::new(initialize_configuration());
    let tracker = initialize_with_configuration(&configuration);

    (configuration, tracker)
}

/// It initializes the application with the given configuration.
///
/// The configuration may be obtained from the environment (via config file or env vars).
#[must_use]
pub fn initialize_with_configuration(configuration: &Arc<Configuration>) -> Arc<Tracker> {
    initialize_static();
    initialize_logging(configuration);
    Arc::new(initialize_tracker(configuration))
}

/// It initializes the application static values.
///
/// These values are accessible throughout the entire application:
///
/// - The time when the application started.
/// - An ephemeral instance random seed. This seed is used for encryption and it's changed when the main application process is restarted.
pub fn initialize_static() {
    // Set the time of Torrust app starting
    lazy_static::initialize(&static_time::TIME_AT_APP_START);

    // Initialize the Ephemeral Instance Random Seed
    lazy_static::initialize(&ephemeral_instance_keys::RANDOM_SEED);
}

/// It builds the domain tracker
///
/// The tracker is the domain layer service. It's the entrypoint to make requests to the domain layer.
/// It's used by other higher-level components like the UDP and HTTP trackers or the tracker API.
#[must_use]
pub fn initialize_tracker(config: &Arc<Configuration>) -> Tracker {
    tracker_factory(config.clone())
}

/// It initializes the log level, format and channel.
///
/// See [the logging setup](crate::bootstrap::logging::setup) for more info about logging.
pub fn initialize_logging(config: &Arc<Configuration>) {
    bootstrap::logging::setup(config);
}
