//! API responses for the [`stats`](crate::servers::apis::v1::context::stats)
//! API context.
use axum::response::{IntoResponse, Json, Response};

use super::resources::Stats;
use crate::core::statistics::services::TrackerMetrics;

/// `200` response that contains the [`Stats`] resource as json.
#[must_use]
pub fn stats_response(tracker_metrics: TrackerMetrics) -> Response {
    Json(Stats::from(tracker_metrics)).into_response()
}

/// `200` response that contains the [`Stats`] resource in Prometheus Text Exposition Format .
#[must_use]
pub fn metrics_response(tracker_metrics: &TrackerMetrics) -> Response {
    let mut lines = vec![];

    lines.push(format!("torrents {}", tracker_metrics.torrents_metrics.torrents));
    lines.push(format!("seeders {}", tracker_metrics.torrents_metrics.complete));
    lines.push(format!("completed {}", tracker_metrics.torrents_metrics.downloaded));
    lines.push(format!("leechers {}", tracker_metrics.torrents_metrics.incomplete));

    // TCP

    // TCPv4

    lines.push(format!(
        "tcp4_connections_handled {}",
        tracker_metrics.protocol_metrics.tcp4_connections_handled
    ));
    lines.push(format!(
        "tcp4_announces_handled {}",
        tracker_metrics.protocol_metrics.tcp4_announces_handled
    ));
    lines.push(format!(
        "tcp4_scrapes_handled {}",
        tracker_metrics.protocol_metrics.tcp4_scrapes_handled
    ));

    // TCPv6

    lines.push(format!(
        "tcp6_connections_handled {}",
        tracker_metrics.protocol_metrics.tcp6_connections_handled
    ));
    lines.push(format!(
        "tcp6_announces_handled {}",
        tracker_metrics.protocol_metrics.tcp6_announces_handled
    ));
    lines.push(format!(
        "tcp6_scrapes_handled {}",
        tracker_metrics.protocol_metrics.tcp6_scrapes_handled
    ));

    // UDP

    lines.push(format!(
        "udp_requests_aborted {}",
        tracker_metrics.protocol_metrics.udp_requests_aborted
    ));
    lines.push(format!(
        "udp_requests_banned {}",
        tracker_metrics.protocol_metrics.udp_requests_banned
    ));
    lines.push(format!(
        "udp_banned_ips_total {}",
        tracker_metrics.protocol_metrics.udp_banned_ips_total
    ));
    lines.push(format!(
        "udp_avg_connect_processing_time_ns {}",
        tracker_metrics.protocol_metrics.udp_avg_connect_processing_time_ns
    ));
    lines.push(format!(
        "udp_avg_announce_processing_time_ns {}",
        tracker_metrics.protocol_metrics.udp_avg_announce_processing_time_ns
    ));
    lines.push(format!(
        "udp_avg_scrape_processing_time_ns {}",
        tracker_metrics.protocol_metrics.udp_avg_scrape_processing_time_ns
    ));

    // UDPv4

    lines.push(format!("udp4_requests {}", tracker_metrics.protocol_metrics.udp4_requests));
    lines.push(format!(
        "udp4_connections_handled {}",
        tracker_metrics.protocol_metrics.udp4_connections_handled
    ));
    lines.push(format!(
        "udp4_announces_handled {}",
        tracker_metrics.protocol_metrics.udp4_announces_handled
    ));
    lines.push(format!(
        "udp4_scrapes_handled {}",
        tracker_metrics.protocol_metrics.udp4_scrapes_handled
    ));
    lines.push(format!("udp4_responses {}", tracker_metrics.protocol_metrics.udp4_responses));
    lines.push(format!(
        "udp4_errors_handled {}",
        tracker_metrics.protocol_metrics.udp4_errors_handled
    ));

    // UDPv6

    lines.push(format!("udp6_requests {}", tracker_metrics.protocol_metrics.udp6_requests));
    lines.push(format!(
        "udp6_connections_handled {}",
        tracker_metrics.protocol_metrics.udp6_connections_handled
    ));
    lines.push(format!(
        "udp6_announces_handled {}",
        tracker_metrics.protocol_metrics.udp6_announces_handled
    ));
    lines.push(format!(
        "udp6_scrapes_handled {}",
        tracker_metrics.protocol_metrics.udp6_scrapes_handled
    ));
    lines.push(format!("udp6_responses {}", tracker_metrics.protocol_metrics.udp6_responses));
    lines.push(format!(
        "udp6_errors_handled {}",
        tracker_metrics.protocol_metrics.udp6_errors_handled
    ));

    // Return the plain text response
    lines.join("\n").into_response()
}
