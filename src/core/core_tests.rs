//! Some generic test helpers functions.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::Configuration;
use torrust_tracker_primitives::peer::Peer;
use torrust_tracker_primitives::DurationSinceUnixEpoch;

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

/// Sample peer whose state is not relevant for the tests.
#[must_use]
pub fn sample_peer() -> Peer {
    complete_peer()
}

#[must_use]
pub fn seeder() -> Peer {
    complete_peer()
}

#[must_use]
pub fn leecher() -> Peer {
    incomplete_peer()
}

#[must_use]
pub fn started_peer() -> Peer {
    incomplete_peer()
}

#[must_use]
pub fn completed_peer() -> Peer {
    complete_peer()
}

/// A peer that counts as `complete` is swarm metadata
/// IMPORTANT!: it only counts if the it has been announce at least once before
/// announcing the `AnnounceEvent::Completed` event.
#[must_use]
pub fn complete_peer() -> Peer {
    Peer {
        peer_id: PeerId(*b"-qB00000000000000000"),
        peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
        updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
        uploaded: NumberOfBytes::new(0),
        downloaded: NumberOfBytes::new(0),
        left: NumberOfBytes::new(0), // No bytes left to download
        event: AnnounceEvent::Completed,
    }
}

/// A peer that counts as `incomplete` is swarm metadata
#[must_use]
pub fn incomplete_peer() -> Peer {
    Peer {
        peer_id: PeerId(*b"-qB00000000000000000"),
        peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
        updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
        uploaded: NumberOfBytes::new(0),
        downloaded: NumberOfBytes::new(0),
        left: NumberOfBytes::new(1000), // Still bytes to download
        event: AnnounceEvent::Started,
    }
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
