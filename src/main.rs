use std::sync::Arc;

use log::info;
use torrust_tracker::tracker::statistics::StatsTracker;
use torrust_tracker::tracker::tracker::TorrentTracker;
use torrust_tracker::{logging, setup, static_time, Configuration};

#[tokio::main]
async fn main() {
    const CONFIG_PATH: &str = "config.toml";

    // Set the time of Torrust app starting
    lazy_static::initialize(&static_time::TIME_AT_APP_START);

    // Initialize Torrust config
    let config = match Configuration::load_from_file(CONFIG_PATH) {
        Ok(config) => Arc::new(config),
        Err(error) => {
            panic!("{}", error)
        }
    };

    // Initialize stats tracker
    let stats_tracker = StatsTracker::new_running_instance();

    // Initialize Torrust tracker
    let tracker = match TorrentTracker::new(config.clone(), Box::new(stats_tracker)) {
        Ok(tracker) => Arc::new(tracker),
        Err(error) => {
            panic!("{}", error)
        }
    };

    // Initialize logging
    logging::setup_logging(&config);

    // Run jobs
    let jobs = setup::setup(&config, tracker.clone()).await;

    // handle the signals here
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Torrust shutting down..");

            // Await for all jobs to shutdown
            futures::future::join_all(jobs).await;
            info!("Torrust successfully shutdown.");
        }
    }
}
