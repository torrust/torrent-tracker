//! API handlers for the [`stats`](crate::servers::apis::v1::context::stats)
//! API context.
use std::sync::Arc;

use axum::extract::State;
use axum::response::Response;
use axum_extra::extract::Query;
use bittorrent_tracker_core::statistics::repository::Repository;
use bittorrent_tracker_core::torrent::repository::in_memory::InMemoryTorrentRepository;
use serde::Deserialize;
use tokio::sync::RwLock;

use super::responses::{metrics_response, stats_response};
use crate::core::statistics::services::get_metrics;
use crate::servers::udp::server::banning::BanService;

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    #[default]
    Json,
    Prometheus,
}

#[derive(Deserialize, Debug)]
pub struct QueryParams {
    /// The [`Format`] of the stats.
    #[serde(default)]
    pub format: Option<Format>,
}

/// It handles the request to get the tracker statistics.
///
/// By default it returns a `200` response with the stats in JSON format.
///
/// You can add the GET parameter `format=prometheus` to get the stats in
/// Prometheus Text Exposition Format.
///
/// Refer to the [API endpoint documentation](crate::servers::apis::v1::context::stats#get-tracker-statistics)
/// for more information about this endpoint.
#[allow(clippy::type_complexity)]
pub async fn get_stats_handler(
    State(state): State<(Arc<InMemoryTorrentRepository>, Arc<RwLock<BanService>>, Arc<Repository>)>,
    params: Query<QueryParams>,
) -> Response {
    let metrics = get_metrics(state.0.clone(), state.1.clone(), state.2.clone()).await;

    match params.0.format {
        Some(format) => match format {
            Format::Json => stats_response(metrics),
            Format::Prometheus => metrics_response(&metrics),
        },
        None => stats_response(metrics),
    }
}
