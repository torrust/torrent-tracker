//! Route initialization for the v1 API.
use std::sync::Arc;

use axum::Router;
use tokio::sync::RwLock;

use super::context::{auth_key, stats, torrent, whitelist};
use crate::core::authentication::handler::KeysHandler;
use crate::core::statistics::event::sender::Sender;
use crate::core::statistics::repository::Repository;
use crate::core::torrent::repository::in_memory::InMemoryTorrentRepository;
use crate::core::whitelist::manager::WhitelistManager;
use crate::servers::udp::server::banning::BanService;

/// Add the routes for the v1 API.
#[allow(clippy::too_many_arguments)]
pub fn add(
    prefix: &str,
    router: Router,
    in_memory_torrent_repository: &Arc<InMemoryTorrentRepository>,
    keys_handler: &Arc<KeysHandler>,
    whitelist_manager: &Arc<WhitelistManager>,
    ban_service: Arc<RwLock<BanService>>,
    stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    stats_repository: Arc<Repository>,
) -> Router {
    let v1_prefix = format!("{prefix}/v1");

    let router = auth_key::routes::add(&v1_prefix, router, keys_handler.clone());
    let router = stats::routes::add(
        &v1_prefix,
        router,
        in_memory_torrent_repository.clone(),
        ban_service,
        stats_event_sender,
        stats_repository,
    );
    let router = whitelist::routes::add(&v1_prefix, router, whitelist_manager);

    torrent::routes::add(&v1_prefix, router, in_memory_torrent_repository.clone())
}
