//! API routes for the [`torrent`](crate::servers::apis::v1::context::torrent) API context.
//!
//! - `GET /torrent/:info_hash`
//! - `GET /torrents`
//!
//! Refer to the [API endpoint documentation](crate::servers::apis::v1::context::torrent).
use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use super::handlers::{get_torrent_handler, get_torrents_handler};
use crate::core::Tracker;

/// It adds the routes to the router for the [`torrent`](crate::servers::apis::v1::context::torrent) API context.
pub fn add(prefix: &str, router: Router, tracker: Arc<Tracker>) -> Router {
    // Torrents
    router
        .route(
            &format!("{prefix}/torrent/{{info_hash}}"),
            get(get_torrent_handler).with_state(tracker.clone()),
        )
        .route(&format!("{prefix}/torrents"), get(get_torrents_handler).with_state(tracker))
}
