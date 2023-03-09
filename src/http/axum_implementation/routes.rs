use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use axum_client_ip::SecureClientIpSource;

use super::handlers::{announce, scrape};
use crate::tracker::Tracker;

#[allow(clippy::needless_pass_by_value)]
pub fn router(tracker: Arc<Tracker>) -> Router {
    Router::new()
        // Announce request
        .route("/announce", get(announce::handle_without_key).with_state(tracker.clone()))
        .route("/announce/:key", get(announce::handle_with_key).with_state(tracker.clone()))
        // Scrape request
        .route("/scrape", get(scrape::handle_without_key).with_state(tracker.clone()))
        .route("/scrape/:key", get(scrape::handle_with_key).with_state(tracker.clone()))
        // Add extension to get the client IP from the connection info
        .layer(SecureClientIpSource::ConnectInfo.into_extension())
}
