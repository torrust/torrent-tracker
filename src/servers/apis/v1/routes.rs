//! Route initialization for the v1 API.
use std::sync::Arc;

use axum::Router;
use tokio::sync::RwLock;

use super::context::{auth_key, stats, torrent, whitelist};
use crate::core::statistics::event::sender::Sender;
use crate::core::statistics::repository::Repository;
use crate::core::whitelist::manager::WhiteListManager;
use crate::core::Tracker;
use crate::servers::udp::server::banning::BanService;

/// Add the routes for the v1 API.
pub fn add(
    prefix: &str,
    router: Router,
    tracker: Arc<Tracker>,
    whitelist_manager: &Arc<WhiteListManager>,
    ban_service: Arc<RwLock<BanService>>,
    stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    stats_repository: Arc<Repository>,
) -> Router {
    let v1_prefix = format!("{prefix}/v1");

    let router = auth_key::routes::add(&v1_prefix, router, tracker.clone());
    let router = stats::routes::add(
        &v1_prefix,
        router,
        tracker.clone(),
        ban_service,
        stats_event_sender,
        stats_repository,
    );
    let router = whitelist::routes::add(&v1_prefix, router, whitelist_manager);

    torrent::routes::add(&v1_prefix, router, tracker)
}
