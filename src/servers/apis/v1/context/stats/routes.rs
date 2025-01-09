//! API routes for the [`stats`](crate::servers::apis::v1::context::stats) API context.
//!
//! - `GET /stats`
//!
//! Refer to the [API endpoint documentation](crate::servers::apis::v1::context::stats).
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use tokio::sync::RwLock;

use super::handlers::get_stats_handler;
use crate::core::Tracker;
use crate::servers::udp::server::banning::BanService;

/// It adds the routes to the router for the [`stats`](crate::servers::apis::v1::context::stats) API context.
pub fn add(prefix: &str, router: Router, tracker: Arc<Tracker>, ban_service: Arc<RwLock<BanService>>) -> Router {
    router.route(
        &format!("{prefix}/stats"),
        get(get_stats_handler).with_state((tracker, ban_service)),
    )
}
