use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::Configuration;

use super::announce_handler::AnnounceHandler;
use super::scrape_handler::ScrapeHandler;
use super::services::initialize_database;
use super::torrent::repository::in_memory::InMemoryTorrentRepository;
use super::torrent::repository::persisted::DatabasePersistentTorrentRepository;
use super::whitelist::repository::in_memory::InMemoryWhitelist;
use super::whitelist::{self};

/// # Panics
///
/// Will panic if the string representation of the info hash is not a valid info hash.
#[must_use]
pub fn sample_info_hash() -> InfoHash {
    "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0" // DevSkim: ignore DS173237
        .parse::<InfoHash>()
        .expect("String should be a valid info hash")
}

#[must_use]
pub fn initialize_handlers(config: &Configuration) -> (Arc<AnnounceHandler>, Arc<ScrapeHandler>) {
    let database = initialize_database(config);
    let in_memory_whitelist = Arc::new(InMemoryWhitelist::default());
    let whitelist_authorization = Arc::new(whitelist::authorization::Authorization::new(
        &config.core,
        &in_memory_whitelist.clone(),
    ));
    let in_memory_torrent_repository = Arc::new(InMemoryTorrentRepository::default());
    let db_torrent_repository = Arc::new(DatabasePersistentTorrentRepository::new(&database));

    let announce_handler = Arc::new(AnnounceHandler::new(
        &config.core,
        &in_memory_torrent_repository,
        &db_torrent_repository,
    ));

    let scrape_handler = Arc::new(ScrapeHandler::new(&whitelist_authorization, &in_memory_torrent_repository));

    (announce_handler, scrape_handler)
}
