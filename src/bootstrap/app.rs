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

use tokio::sync::RwLock;
use torrust_tracker_clock::static_time;
use torrust_tracker_configuration::validator::Validator;
use torrust_tracker_configuration::Configuration;
use tracing::instrument;

use super::config::initialize_configuration;
use crate::bootstrap;
use crate::container::AppContainer;
use crate::core::databases::Database;
use crate::core::services::{initialize_database, initialize_whitelist, statistics, tracker_factory};
use crate::core::whitelist::WhiteListManager;
use crate::servers::udp::server::banning::BanService;
use crate::servers::udp::server::launcher::MAX_CONNECTION_ID_ERRORS_PER_IP;
use crate::shared::crypto::ephemeral_instance_keys;
use crate::shared::crypto::keys::{self, Keeper as _};

/// It loads the configuration from the environment and builds the main domain [`Tracker`] struct.
///
/// # Panics
///
/// Setup can file if the configuration is invalid.
#[must_use]
#[instrument(skip())]
pub fn setup() -> (Configuration, AppContainer) {
    #[cfg(not(test))]
    check_seed();

    let configuration = initialize_configuration();

    if let Err(e) = configuration.validate() {
        panic!("Configuration error: {e}");
    }

    initialize_global_services(&configuration);

    tracing::info!("Configuration:\n{}", configuration.clone().mask_secrets().to_json());

    let app_container = initialize_app_container(&configuration);

    (configuration, app_container)
}

/// checks if the seed is the instance seed in production.
///
/// # Panics
///
/// It would panic if the seed is not the instance seed.
pub fn check_seed() {
    let seed = keys::Current::get_seed();
    let instance = keys::Instance::get_seed();

    assert_eq!(seed, instance, "maybe using zeroed seed in production!?");
}

/// It initializes the global services.
#[instrument(skip())]
pub fn initialize_global_services(configuration: &Configuration) {
    initialize_static();
    initialize_logging(configuration);
}

/// It initializes the IoC Container.
#[instrument(skip())]
pub fn initialize_app_container(configuration: &Configuration) -> AppContainer {
    let (stats_event_sender, stats_repository) = statistics::setup::factory(configuration.core.tracker_usage_statistics);
    let stats_event_sender = Arc::new(stats_event_sender);
    let stats_repository = Arc::new(stats_repository);
    let ban_service = Arc::new(RwLock::new(BanService::new(MAX_CONNECTION_ID_ERRORS_PER_IP)));
    let database = initialize_database(configuration);
    let whitelist_manager = initialize_whitelist(database.clone());
    let tracker = Arc::new(tracker_factory(configuration, &database, &whitelist_manager));

    AppContainer {
        tracker,
        ban_service,
        stats_event_sender,
        stats_repository,
    }
}

/// It initializes the application static values.
///
/// These values are accessible throughout the entire application:
///
/// - The time when the application started.
/// - An ephemeral instance random seed. This seed is used for encryption and it's changed when the main application process is restarted.
#[instrument(skip())]
pub fn initialize_static() {
    // Set the time of Torrust app starting
    lazy_static::initialize(&static_time::TIME_AT_APP_START);

    // Initialize the Ephemeral Instance Random Seed
    lazy_static::initialize(&ephemeral_instance_keys::RANDOM_SEED);

    // Initialize the Ephemeral Instance Random Cipher
    lazy_static::initialize(&ephemeral_instance_keys::RANDOM_CIPHER_BLOWFISH);

    // Initialize the Zeroed Cipher
    lazy_static::initialize(&ephemeral_instance_keys::ZEROED_TEST_CIPHER_BLOWFISH);
}

#[allow(clippy::type_complexity)]
#[must_use]
pub fn initialize_tracker_dependencies(config: &Configuration) -> (Arc<Box<dyn Database>>, Arc<WhiteListManager>) {
    let database = initialize_database(config);
    let whitelist_manager = initialize_whitelist(database.clone());

    (database, whitelist_manager)
}

/// It initializes the log threshold, format and channel.
///
/// See [the logging setup](crate::bootstrap::logging::setup) for more info about logging.
#[instrument(skip(config))]
pub fn initialize_logging(config: &Configuration) {
    bootstrap::logging::setup(config);
}
