//! API routes for the [`stats`](crate::servers::apis::v1::context::stats) API context.
//!
//! - `GET /stats`
//!
//! Refer to the [API endpoint documentation](crate::servers::apis::v1::context::stats).
use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use super::handlers::get_stats_handler;
use crate::container::HttpApiContainer;

/// It adds the routes to the router for the [`stats`](crate::servers::apis::v1::context::stats) API context.
pub fn add(prefix: &str, router: Router, http_api_container: &Arc<HttpApiContainer>) -> Router {
    router.route(
        &format!("{prefix}/stats"),
        get(get_stats_handler).with_state((
            http_api_container.in_memory_torrent_repository.clone(),
            http_api_container.ban_service.clone(),
            http_api_container.http_stats_repository.clone(),
            http_api_container.udp_stats_repository.clone(),
        )),
    )
}
