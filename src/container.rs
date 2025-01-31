use std::sync::Arc;

use bittorrent_tracker_core::announce_handler::AnnounceHandler;
use bittorrent_tracker_core::authentication::handler::KeysHandler;
use bittorrent_tracker_core::authentication::service::AuthenticationService;
use bittorrent_tracker_core::databases::Database;
use bittorrent_tracker_core::scrape_handler::ScrapeHandler;
use bittorrent_tracker_core::torrent::manager::TorrentsManager;
use bittorrent_tracker_core::torrent::repository::in_memory::InMemoryTorrentRepository;
use bittorrent_tracker_core::torrent::repository::persisted::DatabasePersistentTorrentRepository;
use bittorrent_tracker_core::whitelist;
use bittorrent_tracker_core::whitelist::manager::WhitelistManager;
use packages::statistics::event::sender::Sender;
use packages::statistics::repository::Repository;
use tokio::sync::RwLock;
use torrust_tracker_configuration::{Core, HttpApi, HttpTracker, UdpTracker};

use crate::packages::{self, http_tracker_core, udp_tracker_core};
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
    pub http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    pub udp_stats_event_sender: Arc<Option<Box<dyn udp_tracker_core::statistics::event::sender::Sender>>>,
    pub stats_repository: Arc<Repository>,
    pub http_stats_repository: Arc<http_tracker_core::statistics::repository::Repository>,
    pub udp_stats_repository: Arc<udp_tracker_core::statistics::repository::Repository>,
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
    pub udp_stats_event_sender: Arc<Option<Box<dyn udp_tracker_core::statistics::event::sender::Sender>>>,
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
            udp_stats_event_sender: app_container.udp_stats_event_sender.clone(),
            ban_service: app_container.ban_service.clone(),
        }
    }
}

pub struct HttpTrackerContainer {
    pub core_config: Arc<Core>,
    pub http_tracker_config: Arc<HttpTracker>,
    pub announce_handler: Arc<AnnounceHandler>,
    pub scrape_handler: Arc<ScrapeHandler>,
    pub whitelist_authorization: Arc<whitelist::authorization::WhitelistAuthorization>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub http_stats_event_sender: Arc<Option<Box<dyn http_tracker_core::statistics::event::sender::Sender>>>,
    pub authentication_service: Arc<AuthenticationService>,
}

impl HttpTrackerContainer {
    #[must_use]
    pub fn from_app_container(http_tracker_config: &Arc<HttpTracker>, app_container: &Arc<AppContainer>) -> Self {
        Self {
            http_tracker_config: http_tracker_config.clone(),
            core_config: app_container.core_config.clone(),
            announce_handler: app_container.announce_handler.clone(),
            scrape_handler: app_container.scrape_handler.clone(),
            whitelist_authorization: app_container.whitelist_authorization.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            http_stats_event_sender: app_container.http_stats_event_sender.clone(),
            authentication_service: app_container.authentication_service.clone(),
        }
    }
}

pub struct HttpApiContainer {
    pub core_config: Arc<Core>,
    pub http_api_config: Arc<HttpApi>,
    pub in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,
    pub keys_handler: Arc<KeysHandler>,
    pub whitelist_manager: Arc<WhitelistManager>,
    pub ban_service: Arc<RwLock<BanService>>,
    pub stats_event_sender: Arc<Option<Box<dyn Sender>>>,
    pub stats_repository: Arc<Repository>,
}

impl HttpApiContainer {
    #[must_use]
    pub fn from_app_container(http_api_config: &Arc<HttpApi>, app_container: &Arc<AppContainer>) -> Self {
        Self {
            http_api_config: http_api_config.clone(),
            core_config: app_container.core_config.clone(),
            in_memory_torrent_repository: app_container.in_memory_torrent_repository.clone(),
            keys_handler: app_container.keys_handler.clone(),
            whitelist_manager: app_container.whitelist_manager.clone(),
            ban_service: app_container.ban_service.clone(),
            stats_event_sender: app_container.stats_event_sender.clone(),
            stats_repository: app_container.stats_repository.clone(),
        }
    }
}
