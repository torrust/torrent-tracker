//! Statistics services.
//!
//! It includes:
//!
//! - A [`factory`](crate::core::services::statistics::setup::factory) function to build the structs needed to collect the tracker metrics.
//! - A [`get_metrics`] service to get the [`tracker metrics`](crate::core::statistics::Metrics).
//!
//! Tracker metrics are collected using a Publisher-Subscribe pattern.
//!
//! The factory function builds two structs:
//!
//! - An statistics [`EventSender`](crate::core::statistics::EventSender)
//! - An statistics [`Repo`](crate::core::statistics::Repo)
//!
//! ```text
//! let (stats_event_sender, stats_repository) = factory(tracker_usage_statistics);
//! ```
//!
//! The statistics repository is responsible for storing the metrics in memory.
//! The statistics event sender allows sending events related to metrics.
//! There is an event listener that is receiving all the events and processing them with an event handler.
//! Then, the event handler updates the metrics depending on the received event.
//!
//! For example, if you send the event [`Event::Udp4Connect`](crate::core::statistics::Event::Udp4Connect):
//!
//! ```text
//! let result = event_sender.send_event(Event::Udp4Connect).await;
//! ```
//!
//! Eventually the counter for UDP connections from IPv4 peers will be increased.
//!
//! ```rust,no_run
//! pub struct Metrics {
//!     // ...
//!     pub udp4_connections_handled: u64,  // This will be incremented
//!     // ...
//! }
//! ```
pub mod setup;

use std::sync::Arc;

use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;

use crate::core::statistics::Metrics;
use crate::core::Tracker;

/// All the metrics collected by the tracker.
#[derive(Debug, PartialEq)]
pub struct TrackerMetrics {
    /// Domain level metrics.
    ///
    /// General metrics for all torrents (number of seeders, leechers, etcetera)
    pub torrents_metrics: TorrentsMetrics,

    /// Application level metrics. Usage statistics/metrics.
    ///
    /// Metrics about how the tracker is been used (number of udp announce requests, number of http scrape requests, etcetera)
    pub protocol_metrics: Metrics,
}

/// It returns all the [`TrackerMetrics`]
pub async fn get_metrics(tracker: Arc<Tracker>) -> TrackerMetrics {
    let torrents_metrics = tracker.get_torrents_metrics();
    let stats = tracker.get_stats().await;

    TrackerMetrics {
        torrents_metrics,
        protocol_metrics: Metrics {
            tcp4_connections_handled: stats.tcp4_connections_handled,
            tcp4_announces_handled: stats.tcp4_announces_handled,
            tcp4_scrapes_handled: stats.tcp4_scrapes_handled,
            tcp6_connections_handled: stats.tcp6_connections_handled,
            tcp6_announces_handled: stats.tcp6_announces_handled,
            tcp6_scrapes_handled: stats.tcp6_scrapes_handled,
            udp4_connections_handled: stats.udp4_connections_handled,
            udp4_announces_handled: stats.udp4_announces_handled,
            udp4_scrapes_handled: stats.udp4_scrapes_handled,
            udp4_errors_handled: stats.udp4_errors_handled,
            udp6_connections_handled: stats.udp6_connections_handled,
            udp6_announces_handled: stats.udp6_announces_handled,
            udp6_scrapes_handled: stats.udp6_scrapes_handled,
            udp6_errors_handled: stats.udp6_errors_handled,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use torrust_tracker_configuration::Configuration;
    use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
    use torrust_tracker_test_helpers::configuration;

    use crate::core;
    use crate::core::services::statistics::{get_metrics, TrackerMetrics};
    use crate::core::services::tracker_factory;

    pub fn tracker_configuration() -> Configuration {
        configuration::ephemeral()
    }

    #[tokio::test]
    async fn the_statistics_service_should_return_the_tracker_metrics() {
        let tracker = Arc::new(tracker_factory(&tracker_configuration()));

        let tracker_metrics = get_metrics(tracker.clone()).await;

        assert_eq!(
            tracker_metrics,
            TrackerMetrics {
                torrents_metrics: TorrentsMetrics::default(),
                protocol_metrics: core::statistics::Metrics::default(),
            }
        );
    }
}
