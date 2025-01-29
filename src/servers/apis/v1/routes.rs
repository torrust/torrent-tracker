//! Route initialization for the v1 API.
use std::sync::Arc;

use axum::Router;

use super::context::{auth_key, stats, torrent, whitelist};
use crate::container::HttpApiContainer;

/// Add the routes for the v1 API.
pub fn add(prefix: &str, router: Router, http_api_container: &Arc<HttpApiContainer>) -> Router {
    let v1_prefix = format!("{prefix}/v1");

    let router = auth_key::routes::add(&v1_prefix, router, &http_api_container.keys_handler.clone());
    let router = stats::routes::add(&v1_prefix, router, http_api_container);
    let router = whitelist::routes::add(&v1_prefix, router, &http_api_container.whitelist_manager);

    torrent::routes::add(&v1_prefix, router, &http_api_container.in_memory_torrent_repository.clone())
}
