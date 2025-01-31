//! The core `tracker` module contains the generic `BitTorrent` tracker logic which is independent of the delivery layer.
//!
//! It contains the tracker services and their dependencies. It's a domain layer which does not
//! specify how the end user should connect to the `Tracker`.
//!
//! Typically this module is intended to be used by higher modules like:
//!
//! - A UDP tracker
//! - A HTTP tracker
//! - A tracker REST API
//!
//! ```text
//! Delivery layer     Domain layer
//!
//!     HTTP tracker |
//!      UDP tracker |> Core tracker
//! Tracker REST API |
//! ```
//!
//! # Table of contents
//!
//! - [Tracker](#tracker)
//!   - [Announce request](#announce-request)
//!   - [Scrape request](#scrape-request)
//!   - [Torrents](#torrents)
//!   - [Peers](#peers)
//! - [Configuration](#configuration)
//! - [Services](#services)
//! - [Authentication](#authentication)
//! - [Statistics](#statistics)
//! - [Persistence](#persistence)
//!
//! # Tracker
//!
//! The `Tracker` is the main struct in this module. `The` tracker has some groups of responsibilities:
//!
//! - **Core tracker**: it handles the information about torrents and peers.
//! - **Authentication**: it handles authentication keys which are used by HTTP trackers.
//! - **Authorization**: it handles the permission to perform requests.
//! - **Whitelist**: when the tracker runs in `listed` or `private_listed` mode all operations are restricted to whitelisted torrents.
//! - **Statistics**: it keeps and serves the tracker statistics.
//!
//! Refer to [torrust-tracker-configuration](https://docs.rs/torrust-tracker-configuration) crate docs to get more information about the tracker settings.
//!
//! ## Announce request
//!
//! Handling `announce` requests is the most important task for a `BitTorrent` tracker.
//!
//! A `BitTorrent` swarm is a network of peers that are all trying to download the same torrent.
//! When a peer wants to find other peers it announces itself to the swarm via the tracker.
//! The peer sends its data to the tracker so that the tracker can add it to the swarm.
//! The tracker responds to the peer with the list of other peers in the swarm so that
//! the peer can contact them to start downloading pieces of the file from them.
//!
//! Once you have instantiated the `AnnounceHandler` you can `announce` a new [`peer::Peer`](torrust_tracker_primitives::peer::Peer) with:
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use std::net::IpAddr;
//! use std::net::Ipv4Addr;
//! use std::str::FromStr;
//!
//! use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
//! use torrust_tracker_primitives::DurationSinceUnixEpoch;
//! use torrust_tracker_primitives::peer;
//! use bittorrent_primitives::info_hash::InfoHash;
//!
//! let info_hash = InfoHash::from_str("3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0").unwrap();
//!
//! let peer = peer::Peer {
//!     peer_id: PeerId(*b"-qB00000000000000001"),
//!     peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8081),
//!     updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
//!     uploaded: NumberOfBytes::new(0),
//!     downloaded: NumberOfBytes::new(0),
//!     left: NumberOfBytes::new(0),
//!     event: AnnounceEvent::Completed,
//! };
//!
//! let peer_ip = IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap());
//! ```
//!
//! ```text
//! let announce_data = announce_handler.announce(&info_hash, &mut peer, &peer_ip).await;
//! ```
//!
//! The `Tracker` returns the list of peers for the torrent with the infohash `3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0`,
//! filtering out the peer that is making the `announce` request.
//!
//! > **NOTICE**: that the peer argument is mutable because the `Tracker` can change the peer IP if the peer is using a loopback IP.
//!
//! The `peer_ip` argument is the resolved peer ip. It's a common practice that trackers ignore the peer ip in the `announce` request params,
//! and resolve the peer ip using the IP of the client making the request. As the tracker is a domain service, the peer IP must be provided
//! for the `Tracker` user, which is usually a higher component with access the the request metadata, for example, connection data, proxy headers,
//! etcetera.
//!
//! The returned struct is:
//!
//! ```rust,no_run
//! use torrust_tracker_primitives::peer;
//! use torrust_tracker_configuration::AnnouncePolicy;
//!
//! pub struct AnnounceData {
//!     pub peers: Vec<peer::Peer>,
//!     pub swarm_stats: SwarmMetadata,
//!     pub policy: AnnouncePolicy, // the tracker announce policy.
//! }
//!
//! pub struct SwarmMetadata {
//!     pub completed: u32, // The number of peers that have ever completed downloading
//!     pub seeders: u32,   // The number of active peers that have completed downloading (seeders)
//!     pub leechers: u32,  // The number of active peers that have not completed downloading (leechers)
//! }
//!
//! // Core tracker configuration
//! pub struct AnnounceInterval {
//!     // ...
//!     pub interval: u32, // Interval in seconds that the client should wait between sending regular announce requests to the tracker
//!     pub interval_min: u32, // Minimum announce interval. Clients must not reannounce more frequently than this
//!     // ...
//! }
//! ```
//!
//! Refer to `BitTorrent` BEPs and other sites for more information about the `announce` request:
//!
//! - [BEP 3. The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
//! - [BEP 23. Tracker Returns Compact Peer Lists](https://www.bittorrent.org/beps/bep_0023.html)
//! - [Vuze docs](https://wiki.vuze.com/w/Announce)
//!
//! ## Scrape request
//!
//! The `scrape` request allows clients to query metadata about the swarm in bulk.
//!
//! An `scrape` request includes a list of infohashes whose swarm metadata you want to collect.
//!
//! The returned struct is:
//!
//! ```rust,no_run
//! use bittorrent_primitives::info_hash::InfoHash;
//! use std::collections::HashMap;
//!
//! pub struct ScrapeData {
//!     pub files: HashMap<InfoHash, SwarmMetadata>,
//! }
//!
//! pub struct SwarmMetadata {
//!     pub complete: u32,   // The number of active peers that have completed downloading (seeders)
//!     pub downloaded: u32, // The number of peers that have ever completed downloading
//!     pub incomplete: u32, // The number of active peers that have not completed downloading (leechers)
//! }
//! ```
//!
//! The JSON representation of a sample `scrape` response would be like the following:
//!
//! ```json
//! {
//!     'files': {
//!       'xxxxxxxxxxxxxxxxxxxx': {'complete': 11, 'downloaded': 13772, 'incomplete': 19},
//!       'yyyyyyyyyyyyyyyyyyyy': {'complete': 21, 'downloaded': 206, 'incomplete': 20}
//!     }
//! }
//! ```
//!  
//! `xxxxxxxxxxxxxxxxxxxx` and `yyyyyyyyyyyyyyyyyyyy` are 20-byte infohash arrays.
//! There are two data structures for infohashes: byte arrays and hex strings:
//!
//! ```rust,no_run
//! use bittorrent_primitives::info_hash::InfoHash;
//! use std::str::FromStr;
//!
//! let info_hash: InfoHash = [255u8; 20].into();
//!
//! assert_eq!(
//!     info_hash,
//!     InfoHash::from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap()
//! );
//! ```
//! Refer to `BitTorrent` BEPs and other sites for more information about the `scrape` request:
//!
//! - [BEP 48. Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html)
//! - [BEP 15. UDP Tracker Protocol for `BitTorrent`. Scrape section](https://www.bittorrent.org/beps/bep_0015.html)
//! - [Vuze docs](https://wiki.vuze.com/w/Scrape)
//!
//! ## Torrents
//!
//! The [`torrent`] module contains all the data structures stored by the `Tracker` except for peers.
//!
//! We can represent the data stored in memory internally by the `Tracker` with this JSON object:
//!
//! ```json
//! {
//!     "c1277613db1d28709b034a017ab2cae4be07ae10": {
//!         "completed": 0,
//!         "peers": {
//!             "-qB00000000000000001": {
//!                 "peer_id": "-qB00000000000000001",
//!                 "peer_addr": "2.137.87.41:1754",
//!                 "updated": 1672419840,
//!                 "uploaded": 120,
//!                 "downloaded": 60,
//!                 "left": 60,
//!                 "event": "started"
//!             },
//!             "-qB00000000000000002": {
//!                 "peer_id": "-qB00000000000000002",
//!                 "peer_addr": "23.17.287.141:2345",
//!                 "updated": 1679415984,
//!                 "uploaded": 80,
//!                 "downloaded": 20,
//!                 "left": 40,
//!                 "event": "started"
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! The `Tracker` maintains an indexed-by-info-hash list of torrents. For each torrent, it stores a torrent `Entry`.
//! The torrent entry has two attributes:
//!
//! - `completed`: which is hte number of peers that have completed downloading the torrent file/s. As they have completed downloading,
//!   they have a full version of the torrent data, and they can provide the full data to other peers. That's why they are also known as "seeders".
//! - `peers`: an indexed and orderer list of peer for the torrent. Each peer contains the data received from the peer in the `announce` request.
//!
//! The [`torrent`] module not only contains the original data obtained from peer via `announce` requests, it also contains
//! aggregate data that can be derived from the original data. For example:
//!
//! ```rust,no_run
//! pub struct SwarmMetadata {
//!     pub complete: u32,   // The number of active peers that have completed downloading (seeders)
//!     pub downloaded: u32, // The number of peers that have ever completed downloading
//!     pub incomplete: u32, // The number of active peers that have not completed downloading (leechers)
//! }
//!
//! ```
//!
//! > **NOTICE**: that `complete` or `completed` peers are the peers that have completed downloading, but only the active ones are considered "seeders".
//!
//! `SwarmMetadata` struct follows name conventions for `scrape` responses. See [BEP 48](https://www.bittorrent.org/beps/bep_0048.html), while `SwarmMetadata`
//! is used for the rest of cases.
//!
//! Refer to [`torrent`] module for more details about these data structures.
//!
//! ## Peers
//!
//! A `Peer` is the struct used by the `Tracker` to keep peers data:
//!
//! ```rust,no_run
//! use std::net::SocketAddr;

//! use aquatic_udp_protocol::PeerId;
//! use torrust_tracker_primitives::DurationSinceUnixEpoch;
//! use aquatic_udp_protocol::NumberOfBytes;
//! use aquatic_udp_protocol::AnnounceEvent;
//!
//! pub struct Peer {
//!     pub peer_id: PeerId,                     // The peer ID
//!     pub peer_addr: SocketAddr,           // Peer socket address
//!     pub updated: DurationSinceUnixEpoch, // Last time (timestamp) when the peer was updated
//!     pub uploaded: NumberOfBytes,         // Number of bytes the peer has uploaded so far
//!     pub downloaded: NumberOfBytes,       // Number of bytes the peer has downloaded so far   
//!     pub left: NumberOfBytes,             // The number of bytes this peer still has to download
//!     pub event: AnnounceEvent,            // The event the peer has announced: `started`, `completed`, `stopped`
//! }
//! ```
//!
//! Notice that most of the attributes are obtained from the `announce` request.
//! For example, an HTTP announce request would contain the following `GET` parameters:
//!
//! <http://0.0.0.0:7070/announce?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00&peer_addr=2.137.87.41&downloaded=0&uploaded=0&peer_id=-qB00000000000000001&port=17548&left=0&event=completed&compact=0>
//!
//! The `Tracker` keeps an in-memory ordered data structure with all the torrents and a list of peers for each torrent, together with some swarm metrics.
//!
//! We can represent the data stored in memory with this JSON object:
//!
//! ```json
//! {
//!     "c1277613db1d28709b034a017ab2cae4be07ae10": {
//!         "completed": 0,
//!         "peers": {
//!             "-qB00000000000000001": {
//!                 "peer_id": "-qB00000000000000001",
//!                 "peer_addr": "2.137.87.41:1754",
//!                 "updated": 1672419840,
//!                 "uploaded": 120,
//!                 "downloaded": 60,
//!                 "left": 60,
//!                 "event": "started"
//!             },
//!             "-qB00000000000000002": {
//!                 "peer_id": "-qB00000000000000002",
//!                 "peer_addr": "23.17.287.141:2345",
//!                 "updated": 1679415984,
//!                 "uploaded": 80,
//!                 "downloaded": 20,
//!                 "left": 40,
//!                 "event": "started"
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! That JSON object does not exist, it's only a representation of the `Tracker` torrents data.
//!
//! `c1277613db1d28709b034a017ab2cae4be07ae10` is the torrent infohash and `completed` contains the number of peers
//! that have a full version of the torrent data, also known as seeders.
//!
//! Refer to [`peer`](torrust_tracker_primitives::peer) for more information about peers.
//!
//! # Configuration
//!
//! You can control the behavior of this module with the module settings:
//!
//! ```toml
//! [logging]
//! threshold = "debug"
//!
//! [core]
//! inactive_peer_cleanup_interval = 600
//! listed = false
//! private = false
//! tracker_usage_statistics = true
//!
//! [core.announce_policy]
//! interval = 120
//! interval_min = 120
//!
//! [core.database]
//! driver = "sqlite3"
//! path = "./storage/tracker/lib/database/sqlite3.db"
//!
//! [core.net]
//! on_reverse_proxy = false
//! external_ip = "2.137.87.41"
//!
//! [core.tracker_policy]
//! max_peer_timeout = 900
//! persistent_torrent_completed_stat = false
//! remove_peerless_torrents = true
//! ```
//!
//! Refer to the [`configuration` module documentation](https://docs.rs/torrust-tracker-configuration) to get more information about all options.
//!
//! # Services
//!
//! Services are domain services on top of the core tracker domain. Right now there are two types of service:
//!
//! - For statistics: [`crate::packages::statistics::services`]
//! - For torrents: [`crate::core::torrent::services`]
//!
//! Services usually format the data inside the tracker to make it easier to consume by other parts.
//! They also decouple the internal data structure, used by the tracker, from the way we deliver that data to the consumers.
//! The internal data structure is designed for performance or low memory consumption. And it should be changed
//! without affecting the external consumers.
//!
//! Services can include extra features like pagination, for example.
//!
//! # Authentication
//!
//! One of the core `Tracker` responsibilities is to create and keep authentication keys. Auth keys are used by HTTP trackers
//! when the tracker is running in `private` or `private_listed` mode.
//!
//! HTTP tracker's clients need to obtain an auth key before starting requesting the tracker. Once the get one they have to include
//! a `PATH` param with the key in all the HTTP requests. For example, when a peer wants to `announce` itself it has to use the
//! HTTP tracker endpoint `GET /announce/:key`.
//!
//! The common way to obtain the keys is by using the tracker API directly or via other applications like the [Torrust Index](https://github.com/torrust/torrust-index).
//!
//! To learn more about tracker authentication, refer to the following modules :
//!
//! - [`authentication`] module.
//! - [`core`](crate::core) module.
//! - [`http`](crate::servers::http) module.
//!
//! # Statistics
//!
//! The `Tracker` keeps metrics for some events:
//!
//! ```rust,no_run
//! pub struct Metrics {
//!     // IP version 4
//!
//!     // HTTP tracker
//!     pub tcp4_connections_handled: u64,
//!     pub tcp4_announces_handled: u64,
//!     pub tcp4_scrapes_handled: u64,
//!
//!     // UDP tracker
//!     pub udp4_connections_handled: u64,
//!     pub udp4_announces_handled: u64,
//!     pub udp4_scrapes_handled: u64,
//!
//!     // IP version 6
//!
//!     // HTTP tracker
//!     pub tcp6_connections_handled: u64,
//!     pub tcp6_announces_handled: u64,
//!     pub tcp6_scrapes_handled: u64,
//!
//!     // UDP tracker
//!     pub udp6_connections_handled: u64,
//!     pub udp6_announces_handled: u64,
//!     pub udp6_scrapes_handled: u64,
//! }
//! ```
//!
//! The metrics maintained by the `Tracker` are:
//!
//! - `connections_handled`: number of connections handled by the tracker
//! - `announces_handled`: number of `announce` requests handled by the tracker
//! - `scrapes_handled`: number of `scrape` handled requests by the tracker
//!
//! > **NOTICE**: as the HTTP tracker does not have an specific `connection` request like the UDP tracker, `connections_handled` are
//! > increased on every `announce` and `scrape` requests.
//!
//! The tracker exposes an event sender API that allows the tracker users to send events. When a higher application service handles a
//! `connection` , `announce` or `scrape` requests, it notifies the `Tracker` by sending statistics events.
//!
//! For example, the HTTP tracker would send an event like the following when it handles an `announce` request received from a peer using IP version 4.
//!
//! ```text
//! stats_event_sender.send_stats_event(statistics::event::Event::Tcp4Announce).await
//! ```
//!
//! Refer to [`statistics`] module for more information about statistics.
//!
//! # Persistence
//!
//! Right now the `Tracker` is responsible for storing and load data into and
//! from the database, when persistence is enabled.
//!
//! There are three types of persistent object:
//!
//! - Authentication keys (only expiring keys)
//! - Torrent whitelist
//! - Torrent metrics
//!
//! Refer to [`databases`] module for more information about persistence.
pub mod announce_handler;
pub mod authentication;
pub mod databases;
pub mod error;
pub mod scrape_handler;
pub mod torrent;
pub mod whitelist;

pub mod core_tests;
pub mod peer_tests;

use torrust_tracker_clock::clock;
/// This code needs to be copied into each crate.
/// Working version, for production.
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) type CurrentClock = clock::Working;

/// Stopped version, for testing.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) type CurrentClock = clock::Stopped;

#[cfg(test)]
mod tests {
    mod the_tracker {
        use std::net::{IpAddr, Ipv4Addr};
        use std::str::FromStr;
        use std::sync::Arc;

        use torrust_tracker_test_helpers::configuration;

        use crate::announce_handler::AnnounceHandler;
        use crate::core_tests::initialize_handlers;
        use crate::scrape_handler::ScrapeHandler;

        fn initialize_handlers_for_public_tracker() -> (Arc<AnnounceHandler>, Arc<ScrapeHandler>) {
            let config = configuration::ephemeral_public();
            initialize_handlers(&config)
        }

        fn initialize_handlers_for_listed_tracker() -> (Arc<AnnounceHandler>, Arc<ScrapeHandler>) {
            let config = configuration::ephemeral_listed();
            initialize_handlers(&config)
        }

        // The client peer IP
        fn peer_ip() -> IpAddr {
            IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap())
        }

        mod for_all_config_modes {

            mod handling_a_scrape_request {

                use std::net::{IpAddr, Ipv4Addr};

                use bittorrent_primitives::info_hash::InfoHash;
                use torrust_tracker_primitives::core::ScrapeData;
                use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

                use crate::announce_handler::PeersWanted;
                use crate::core_tests::{complete_peer, incomplete_peer};
                use crate::tests::the_tracker::initialize_handlers_for_public_tracker;

                #[tokio::test]
                async fn it_should_return_the_swarm_metadata_for_the_requested_file_if_the_tracker_has_that_torrent() {
                    let (announce_handler, scrape_handler) = initialize_handlers_for_public_tracker();

                    let info_hash = "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap(); // DevSkim: ignore DS173237

                    // Announce a "complete" peer for the torrent
                    let mut complete_peer = complete_peer();
                    announce_handler.announce(
                        &info_hash,
                        &mut complete_peer,
                        &IpAddr::V4(Ipv4Addr::new(126, 0, 0, 10)),
                        &PeersWanted::All,
                    );

                    // Announce an "incomplete" peer for the torrent
                    let mut incomplete_peer = incomplete_peer();
                    announce_handler.announce(
                        &info_hash,
                        &mut incomplete_peer,
                        &IpAddr::V4(Ipv4Addr::new(126, 0, 0, 11)),
                        &PeersWanted::All,
                    );

                    // Scrape
                    let scrape_data = scrape_handler.scrape(&vec![info_hash]).await;

                    // The expected swarm metadata for the file
                    let mut expected_scrape_data = ScrapeData::empty();
                    expected_scrape_data.add_file(
                        &info_hash,
                        SwarmMetadata {
                            complete: 0, // the "complete" peer does not count because it was not previously known
                            downloaded: 0,
                            incomplete: 1, // the "incomplete" peer we have just announced
                        },
                    );

                    assert_eq!(scrape_data, expected_scrape_data);
                }
            }
        }

        mod configured_as_whitelisted {

            mod handling_a_scrape_request {

                use bittorrent_primitives::info_hash::InfoHash;
                use torrust_tracker_primitives::core::ScrapeData;
                use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

                use crate::announce_handler::PeersWanted;
                use crate::core_tests::{complete_peer, incomplete_peer};
                use crate::tests::the_tracker::{initialize_handlers_for_listed_tracker, peer_ip};

                #[tokio::test]
                async fn it_should_return_the_zeroed_swarm_metadata_for_the_requested_file_if_it_is_not_whitelisted() {
                    let (announce_handler, scrape_handler) = initialize_handlers_for_listed_tracker();

                    let info_hash = "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap(); // DevSkim: ignore DS173237

                    let mut peer = incomplete_peer();
                    announce_handler.announce(&info_hash, &mut peer, &peer_ip(), &PeersWanted::All);

                    // Announce twice to force non zeroed swarm metadata
                    let mut peer = complete_peer();
                    announce_handler.announce(&info_hash, &mut peer, &peer_ip(), &PeersWanted::All);

                    let scrape_data = scrape_handler.scrape(&vec![info_hash]).await;

                    // The expected zeroed swarm metadata for the file
                    let mut expected_scrape_data = ScrapeData::empty();
                    expected_scrape_data.add_file(&info_hash, SwarmMetadata::zeroed());

                    assert_eq!(scrape_data, expected_scrape_data);
                }
            }
        }
    }
}
