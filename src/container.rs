use std::sync::Arc;

use tokio::sync::RwLock;
use torrust_tracker_configuration::{Core, UdpTracker};

use crate::core::announce_handler::AnnounceHandler;
use crate::core::authentication::handler::KeysHandler;
use crate::core::authentication::service::AuthenticationService;
use crate::core::databases::Database;
use crate::core::scrape_handler::ScrapeHandler;
use crate::core::statistics::event::sender::Sender;
use crate::core::statistics::repository::Repository;
use crate::core::torrent::manager::TorrentsManager;
use crate::core::torrent::repository::in_memory::InMemoryTorrentRepository;
use crate::core::torrent::repository::persisted::DatabasePersistentTorrentRepository;
use crate::core::whitelist;
use crate::core::whitelist::manager::WhitelistManager;
use crate::servers::udp::server::banning::BanService;

pub struct AppContainer {
    pub core_config: Arc<Core>,
    pub database: Arc<Box<dyn Database>>,
    pub announce_handler: Arc<AnnounceHandler>,
    pub scrape_handler: Arc<ScrapeHandler>,
    pub keys_handler: Arc<KeysHandler>,
    pub authentication_service: Arc<AuthenticationService>,
    pub whitelist_authorization: Arc<whitelist::authorization::WhitelistAuthorization>,
    pub ban_service: Arc<RwLock<BanService>>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
    pub whitelist_manager: Arc<WhitelistManager>,
    pub in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,
    pub db_torrent_repository: Arc<DatabasePersistentTorrentRepository>,
    pub torrents_manager: Arc<TorrentsManager>,
}

pub struct UdpTrackerContainer {
    pub core_config: Arc<Core>,
    pub udp_tracker_config: Arc<UdpTracker>,
    pub announce_handler: Arc<AnnounceHandler>,
    pub scrape_handler: Arc<ScrapeHandler>,
    pub whitelist_authorization: Arc<whitelist::authorization::WhitelistAuthorization>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub ban_service: Arc<RwLock<BanService>>,
}

impl UdpTrackerContainer {
    #[must_use]
    pub fn from_app_container(udp_tracker_config: &Arc<UdpTracker>, app_container: &Arc<AppContainer>) -> Self {
        Self {
            udp_tracker_config: udp_tracker_config.clone(),
            core_config: app_container.core_config.clone(),
            announce_handler: app_container.announce_handler.clone(),
            scrape_handler: app_container.scrape_handler.clone(),
            whitelist_authorization: app_container.whitelist_authorization.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            ban_service: app_container.ban_service.clone(),
        }
    }
}
