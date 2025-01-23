//! Statistics services.
//!
//! It includes:
//!
//! - A [`factory`](crate::core::services::statistics::setup::factory) function to build the structs needed to collect the tracker metrics.
//! - A [`get_metrics`] service to get the tracker [`metrics`](crate::core::statistics::metrics::Metrics).
//!
//! Tracker metrics are collected using a Publisher-Subscribe pattern.
//!
//! The factory function builds two structs:
//!
//! - An statistics event [`Sender`](crate::core::statistics::event::sender::Sender)
//! - An statistics [`Repository`]
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
//! For example, if you send the event [`Event::Udp4Connect`](crate::core::statistics::event::Event::Udp4Connect):
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

use tokio::sync::RwLock;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;

use crate::core::statistics::metrics::Metrics;
use crate::core::statistics::repository::Repository;
use crate::core::Tracker;
use crate::servers::udp::server::banning::BanService;

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
pub async fn get_metrics(
    tracker: Arc<Tracker>,
    ban_service: Arc<RwLock<BanService>>,
    stats_repository: Arc<Repository>,
) -> TrackerMetrics {
    let torrents_metrics = tracker.get_torrents_metrics();
    let stats = stats_repository.get_stats().await;
    let udp_banned_ips_total = ban_service.read().await.get_banned_ips_total();

    TrackerMetrics {
        torrents_metrics,
        protocol_metrics: Metrics {
            // TCPv4
            tcp4_connections_handled: stats.tcp4_connections_handled,
            tcp4_announces_handled: stats.tcp4_announces_handled,
            tcp4_scrapes_handled: stats.tcp4_scrapes_handled,
            // TCPv6
            tcp6_connections_handled: stats.tcp6_connections_handled,
            tcp6_announces_handled: stats.tcp6_announces_handled,
            tcp6_scrapes_handled: stats.tcp6_scrapes_handled,
            // UDP
            udp_requests_aborted: stats.udp_requests_aborted,
            udp_requests_banned: stats.udp_requests_banned,
            udp_banned_ips_total: udp_banned_ips_total as u64,
            udp_avg_connect_processing_time_ns: stats.udp_avg_connect_processing_time_ns,
            udp_avg_announce_processing_time_ns: stats.udp_avg_announce_processing_time_ns,
            udp_avg_scrape_processing_time_ns: stats.udp_avg_scrape_processing_time_ns,
            // UDPv4
            udp4_requests: stats.udp4_requests,
            udp4_connections_handled: stats.udp4_connections_handled,
            udp4_announces_handled: stats.udp4_announces_handled,
            udp4_scrapes_handled: stats.udp4_scrapes_handled,
            udp4_responses: stats.udp4_responses,
            udp4_errors_handled: stats.udp4_errors_handled,
            // UDPv6
            udp6_requests: stats.udp6_requests,
            udp6_connections_handled: stats.udp6_connections_handled,
            udp6_announces_handled: stats.udp6_announces_handled,
            udp6_scrapes_handled: stats.udp6_scrapes_handled,
            udp6_responses: stats.udp6_responses,
            udp6_errors_handled: stats.udp6_errors_handled,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;
    use torrust_tracker_configuration::Configuration;
    use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
    use torrust_tracker_test_helpers::configuration;

    use crate::app_test::initialize_tracker_dependencies;
    use crate::core::services::initialize_tracker;
    use crate::core::services::statistics::{self, get_metrics, TrackerMetrics};
    use crate::core::{self};
    use crate::servers::udp::server::banning::BanService;
    use crate::servers::udp::server::launcher::MAX_CONNECTION_ID_ERRORS_PER_IP;

    pub fn tracker_configuration() -> Configuration {
        configuration::ephemeral()
    }

    #[tokio::test]
    async fn the_statistics_service_should_return_the_tracker_metrics() {
        let config = tracker_configuration();

        let (
            _database,
            _in_memory_whitelist,
            whitelist_authorization,
            _authentication_service,
            in_memory_torrent_repository,
            db_torrent_repository,
            torrents_manager,
        ) = initialize_tracker_dependencies(&config);

        let (_stats_event_sender, stats_repository) = statistics::setup::factory(config.core.tracker_usage_statistics);
        let stats_repository = Arc::new(stats_repository);

        let tracker = Arc::new(initialize_tracker(
            &config,
            &whitelist_authorization,
            &in_memory_torrent_repository,
            &db_torrent_repository,
            &torrents_manager,
        ));

        let ban_service = Arc::new(RwLock::new(BanService::new(MAX_CONNECTION_ID_ERRORS_PER_IP)));

        let tracker_metrics = get_metrics(tracker.clone(), ban_service.clone(), stats_repository.clone()).await;

        assert_eq!(
            tracker_metrics,
            TrackerMetrics {
                torrents_metrics: TorrentsMetrics::default(),
                protocol_metrics: core::statistics::metrics::Metrics::default(),
            }
        );
    }
}
