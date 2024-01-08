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
//! Once you have instantiated the `Tracker` you can `announce` a new [`Peer`] with:
//!
//! ```rust,no_run
//! use torrust_tracker::core::peer;
//! use torrust_tracker::shared::bit_torrent::info_hash::InfoHash;
//! use torrust_tracker::shared::clock::DurationSinceUnixEpoch;
//! use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes};
//! use std::net::SocketAddr;
//! use std::net::IpAddr;
//! use std::net::Ipv4Addr;
//! use std::str::FromStr;
//!
//!
//! let info_hash = InfoHash::from_str("3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0").unwrap();
//!
//! let peer = peer::Peer {
//!     peer_id: peer::Id(*b"-qB00000000000000001"),
//!     peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8081),
//!     updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
//!     uploaded: NumberOfBytes(0),
//!     downloaded: NumberOfBytes(0),
//!     left: NumberOfBytes(0),
//!     event: AnnounceEvent::Completed,
//! };
//!
//! let peer_ip = IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap());
//! ```
//!
//! ```text
//! let announce_data = tracker.announce(&info_hash, &mut peer, &peer_ip).await;
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
//! use torrust_tracker::core::peer::Peer;
//!
//! pub struct AnnounceData {
//!     pub peers: Vec<Peer>,
//!     pub swarm_stats: SwarmStats,
//!     pub interval: u32, // Option `announce_interval` from core tracker configuration
//!     pub interval_min: u32, // Option `min_announce_interval` from core tracker configuration
//! }
//!
//! pub struct SwarmStats {
//!     pub completed: u32, // The number of peers that have ever completed downloading
//!     pub seeders: u32,   // The number of active peers that have completed downloading (seeders)
//!     pub leechers: u32,  // The number of active peers that have not completed downloading (leechers)
//! }
//!
//! // Core tracker configuration
//! pub struct Configuration {
//!     // ...
//!     pub announce_interval: u32, // Interval in seconds that the client should wait between sending regular announce requests to the tracker
//!     pub min_announce_interval: u32, // Minimum announce interval. Clients must not reannounce more frequently than this
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
//! use torrust_tracker::shared::bit_torrent::info_hash::InfoHash;
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
//! use torrust_tracker::shared::bit_torrent::info_hash::InfoHash;
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
//!  they have a full version of the torrent data, and they can provide the full data to other peers. That's why they are also known as "seeders".
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
//! pub struct SwarmStats {
//!     pub completed: u32, // The number of peers that have ever completed downloading
//!     pub seeders: u32,   // The number of active peers that have completed downloading (seeders)
//!     pub leechers: u32,  // The number of active peers that have not completed downloading (leechers)
//! }
//! ```
//!
//! > **NOTICE**: that `complete` or `completed` peers are the peers that have completed downloading, but only the active ones are considered "seeders".
//!
//! `SwarmStats` struct follows name conventions for `scrape` responses. See [BEP 48](https://www.bittorrent.org/beps/bep_0048.html), while `SwarmStats`
//! is used for the rest of cases.
//!
//! Refer to [`torrent`] module for more details about these data structures.
//!
//! ## Peers
//!
//! A `Peer` is the struct used by the `Tracker` to keep peers data:
//!
//! ```rust,no_run
//! use torrust_tracker::core::peer::Id;
//! use std::net::SocketAddr;
//! use torrust_tracker::shared::clock::DurationSinceUnixEpoch;
//! use aquatic_udp_protocol::NumberOfBytes;
//! use aquatic_udp_protocol::AnnounceEvent;
//!
//! pub struct Peer {
//!     pub peer_id: Id,                     // The peer ID
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
//! Refer to [`peer`] module for more information about peers.
//!
//! # Configuration
//!
//! You can control the behavior of this module with the module settings:
//!
//! ```toml
//! log_level = "debug"
//! mode = "public"
//! db_driver = "Sqlite3"
//! db_path = "./storage/tracker/lib/database/sqlite3.db"
//! announce_interval = 120
//! min_announce_interval = 120
//! max_peer_timeout = 900
//! on_reverse_proxy = false
//! external_ip = "2.137.87.41"
//! tracker_usage_statistics = true
//! persistent_torrent_completed_stat = true
//! inactive_peer_cleanup_interval = 600
//! remove_peerless_torrents = false
//! ```
//!
//! Refer to the [`configuration` module documentation](https://docs.rs/torrust-tracker-configuration) to get more information about all options.
//!
//! # Services
//!
//! Services are domain services on top of the core tracker. Right now there are two types of service:
//!
//! - For statistics
//! - For torrents
//!
//! Services usually format the data inside the tracker to make it easier to consume by other parts.
//! They also decouple the internal data structure, used by the tracker, from the way we deliver that data to the consumers.
//! The internal data structure is designed for performance or low memory consumption. And it should be changed
//! without affecting the external consumers.
//!
//! Services can include extra features like pagination, for example.
//!
//! Refer to [`services`] module for more information about services.
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
//! - [`auth`] module.
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
//! increased on every `announce` and `scrape` requests.
//!
//! The tracker exposes an event sender API that allows the tracker users to send events. When a higher application service handles a
//! `connection` , `announce` or `scrape` requests, it notifies the `Tracker` by sending statistics events.
//!
//! For example, the HTTP tracker would send an event like the following when it handles an `announce` request received from a peer using IP version 4.
//!
//! ```text
//! tracker.send_stats_event(statistics::Event::Tcp4Announce).await
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
pub mod auth;
pub mod databases;
pub mod error;
pub mod peer;
pub mod services;
pub mod statistics;
pub mod torrent;

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use tokio::sync::mpsc::error::SendError;
use torrust_tracker_configuration::Configuration;
use torrust_tracker_primitives::TrackerMode;

use self::auth::Key;
use self::error::Error;
use self::peer::Peer;
use self::torrent::repository::{RepositoryAsyncSingle, TRepositoryAsync};
use crate::core::databases::Database;
use crate::core::torrent::{SwarmMetadata, SwarmStats};
use crate::shared::bit_torrent::info_hash::InfoHash;

/// The maximum number of returned peers for a torrent.
pub const TORRENT_PEERS_LIMIT: usize = 74;

/// The domain layer tracker service.
///
/// Its main responsibility is to handle the `announce` and `scrape` requests.
/// But it's also a container for the `Tracker` configuration, persistence,
/// authentication and other services.
///
/// > **NOTICE**: the `Tracker` is not responsible for handling the network layer.
/// Typically, the `Tracker` is used by a higher application service that handles
/// the network layer.
pub struct Tracker {
    /// `Tracker` configuration. See [`torrust-tracker-configuration`](torrust_tracker_configuration)
    pub config: Arc<Configuration>,
    /// A database driver implementation: [`Sqlite3`](crate::core::databases::sqlite)
    /// or [`MySQL`](crate::core::databases::mysql)
    pub database: Arc<Box<dyn Database>>,
    mode: TrackerMode,
    keys: tokio::sync::RwLock<std::collections::HashMap<Key, auth::ExpiringKey>>,
    whitelist: tokio::sync::RwLock<std::collections::HashSet<InfoHash>>,
    pub torrents: Arc<RepositoryAsyncSingle>,
    stats_event_sender: Option<Box<dyn statistics::EventSender>>,
    stats_repository: statistics::Repo,
}

/// Structure that holds general `Tracker` torrents metrics.
///
/// Metrics are aggregate values for all torrents.
#[derive(Debug, PartialEq, Default)]
pub struct TorrentsMetrics {
    /// Total number of seeders for all torrents
    pub seeders: u64,
    /// Total number of peers that have ever completed downloading for all torrents.
    pub completed: u64,
    /// Total number of leechers for all torrents.
    pub leechers: u64,
    /// Total number of torrents.
    pub torrents: u64,
}

/// Structure that holds the data returned by the `announce` request.
#[derive(Debug, PartialEq, Default)]
pub struct AnnounceData {
    /// The list of peers that are downloading the same torrent.
    /// It excludes the peer that made the request.
    pub peers: Vec<Peer>,
    /// Swarm statistics
    pub swarm_stats: SwarmStats,
    /// The interval in seconds that the client should wait between sending
    /// regular requests to the tracker.
    /// Refer to [`announce_interval`](torrust_tracker_configuration::Configuration::announce_interval).
    pub interval: u32,
    /// The minimum announce interval in seconds that the client should wait.
    /// Refer to [`min_announce_interval`](torrust_tracker_configuration::Configuration::min_announce_interval).
    pub interval_min: u32,
}

/// Structure that holds the data returned by the `scrape` request.
#[derive(Debug, PartialEq, Default)]
pub struct ScrapeData {
    /// A map of infohashes and swarm metadata for each torrent.
    pub files: HashMap<InfoHash, SwarmMetadata>,
}

impl ScrapeData {
    /// Creates a new empty `ScrapeData` with no files (torrents).
    #[must_use]
    pub fn empty() -> Self {
        let files: HashMap<InfoHash, SwarmMetadata> = HashMap::new();
        Self { files }
    }

    /// Creates a new `ScrapeData` with zeroed metadata for each torrent.
    #[must_use]
    pub fn zeroed(info_hashes: &Vec<InfoHash>) -> Self {
        let mut scrape_data = Self::empty();

        for info_hash in info_hashes {
            scrape_data.add_file(info_hash, SwarmMetadata::zeroed());
        }

        scrape_data
    }

    /// Adds a torrent to the `ScrapeData`.
    pub fn add_file(&mut self, info_hash: &InfoHash, swarm_metadata: SwarmMetadata) {
        self.files.insert(*info_hash, swarm_metadata);
    }

    /// Adds a torrent to the `ScrapeData` with zeroed metadata.
    pub fn add_file_with_zeroed_metadata(&mut self, info_hash: &InfoHash) {
        self.files.insert(*info_hash, SwarmMetadata::zeroed());
    }
}

impl Tracker {
    /// `Tracker` constructor.
    ///
    /// # Errors
    ///
    /// Will return a `databases::error::Error` if unable to connect to database. The `Tracker` is responsible for the persistence.
    pub fn new(
        config: Arc<Configuration>,
        stats_event_sender: Option<Box<dyn statistics::EventSender>>,
        stats_repository: statistics::Repo,
    ) -> Result<Tracker, databases::error::Error> {
        let database = Arc::new(databases::driver::build(&config.db_driver, &config.db_path)?);

        let mode = config.mode;

        Ok(Tracker {
            config,
            mode,
            keys: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            whitelist: tokio::sync::RwLock::new(std::collections::HashSet::new()),
            torrents: Arc::new(RepositoryAsyncSingle::new()),
            stats_event_sender,
            stats_repository,
            database,
        })
    }

    /// Returns `true` is the tracker is in public mode.
    pub fn is_public(&self) -> bool {
        self.mode == TrackerMode::Public
    }

    /// Returns `true` is the tracker is in private mode.
    pub fn is_private(&self) -> bool {
        self.mode == TrackerMode::Private || self.mode == TrackerMode::PrivateListed
    }

    /// Returns `true` is the tracker is in whitelisted mode.
    pub fn is_whitelisted(&self) -> bool {
        self.mode == TrackerMode::Listed || self.mode == TrackerMode::PrivateListed
    }

    /// Returns `true` if the tracker requires authentication.
    pub fn requires_authentication(&self) -> bool {
        self.is_private()
    }

    /// It handles an announce request.
    ///
    /// # Context: Tracker
    ///
    /// BEP 03: [The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html).
    pub async fn announce(&self, info_hash: &InfoHash, peer: &mut Peer, remote_client_ip: &IpAddr) -> AnnounceData {
        // code-review: maybe instead of mutating the peer we could just return
        // a tuple with the new peer and the announce data: (Peer, AnnounceData).
        // It could even be a different struct: `StoredPeer` or `PublicPeer`.

        // code-review: in the `scrape` function we perform an authorization check.
        // We check if the torrent is whitelisted. Should we also check authorization here?
        // I think so because the `Tracker` has the responsibility for checking authentication and authorization.
        // The `Tracker` has delegated that responsibility to the handlers
        // (because we want to return a friendly error response) but that does not mean we should
        // double-check authorization at this domain level too.
        // I would propose to return a `Result<AnnounceData, Error>` here.
        // Besides, regarding authentication the `Tracker` is also responsible for authentication but
        // we are actually handling authentication at the handlers level. So I would extract that
        // responsibility into another authentication service.

        peer.change_ip(&assign_ip_address_to_peer(remote_client_ip, self.config.get_ext_ip()));

        let swarm_stats = self.update_torrent_with_peer_and_get_stats(info_hash, peer).await;

        let peers = self.get_torrent_peers_for_peer(info_hash, peer).await;

        AnnounceData {
            peers,
            swarm_stats,
            interval: self.config.announce_interval,
            interval_min: self.config.min_announce_interval,
        }
    }

    /// It handles a scrape request.
    ///
    /// # Context: Tracker
    ///
    /// BEP 48: [Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html).
    pub async fn scrape(&self, info_hashes: &Vec<InfoHash>) -> ScrapeData {
        let mut scrape_data = ScrapeData::empty();

        for info_hash in info_hashes {
            let swarm_metadata = match self.authorize(info_hash).await {
                Ok(()) => self.get_swarm_metadata(info_hash).await,
                Err(_) => SwarmMetadata::zeroed(),
            };
            scrape_data.add_file(info_hash, swarm_metadata);
        }

        scrape_data
    }

    /// It returns the data for a `scrape` response.
    async fn get_swarm_metadata(&self, info_hash: &InfoHash) -> SwarmMetadata {
        let torrents = self.torrents.get_torrents().await;

        match torrents.get(info_hash) {
            Some(torrent_entry) => torrent_entry.get_swarm_metadata(),
            None => SwarmMetadata::default(),
        }
    }

    /// It loads the torrents from database into memory. It only loads the torrent entry list with the number of seeders for each torrent.
    /// Peers data is not persisted.
    ///
    /// # Context: Tracker
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list of `persistent_torrents` from the database.
    pub async fn load_torrents_from_database(&self) -> Result<(), databases::error::Error> {
        let persistent_torrents = self.database.load_persistent_torrents().await?;

        let mut torrents = self.torrents.get_torrents_mut().await;

        for (info_hash, completed) in persistent_torrents {
            // Skip if torrent entry already exists
            if torrents.contains_key(&info_hash) {
                continue;
            }

            let torrent_entry = torrent::Entry {
                peers: BTreeMap::default(),
                completed,
            };

            torrents.insert(info_hash, torrent_entry);
        }

        Ok(())
    }

    async fn get_torrent_peers_for_peer(&self, info_hash: &InfoHash, peer: &Peer) -> Vec<peer::Peer> {
        let read_lock = self.torrents.get_torrents().await;

        match read_lock.get(info_hash) {
            None => vec![],
            Some(entry) => entry
                .get_peers_for_peer(peer, TORRENT_PEERS_LIMIT)
                .into_iter()
                .copied()
                .collect(),
        }
    }

    /// # Context: Tracker
    ///
    /// Get all torrent peers for a given torrent
    pub async fn get_torrent_peers(&self, info_hash: &InfoHash) -> Vec<peer::Peer> {
        let read_lock = self.torrents.get_torrents().await;

        match read_lock.get(info_hash) {
            None => vec![],
            Some(entry) => entry.get_peers(TORRENT_PEERS_LIMIT).into_iter().copied().collect(),
        }
    }

    /// It updates the torrent entry in memory, it also stores in the database
    /// the torrent info data which is persistent, and finally return the data
    /// needed for a `announce` request response.
    ///
    /// # Context: Tracker
    pub async fn update_torrent_with_peer_and_get_stats(&self, info_hash: &InfoHash, peer: &peer::Peer) -> torrent::SwarmStats {
        // code-review: consider splitting the function in two (command and query segregation).
        // `update_torrent_with_peer` and `get_stats`

        let (stats, stats_updated) = self.torrents.update_torrent_with_peer_and_get_stats(info_hash, peer).await;

        if self.config.persistent_torrent_completed_stat && stats_updated {
            let completed = stats.completed;
            let info_hash = *info_hash;

            drop(self.database.save_persistent_torrent(&info_hash, completed).await);
        }

        stats
    }

    /// It calculates and returns the general `Tracker`
    /// [`TorrentsMetrics`]
    ///
    /// # Context: Tracker
    ///
    /// # Panics
    /// Panics if unable to get the torrent metrics.
    pub async fn get_torrents_metrics(&self) -> TorrentsMetrics {
        let arc_torrents_metrics = Arc::new(tokio::sync::Mutex::new(TorrentsMetrics {
            seeders: 0,
            completed: 0,
            leechers: 0,
            torrents: 0,
        }));

        let db = self.torrents.get_torrents().await.clone();

        let futures = db
            .values()
            .map(|torrent_entry| {
                let torrent_entry = torrent_entry.clone();
                let torrents_metrics = arc_torrents_metrics.clone();

                async move {
                    tokio::spawn(async move {
                        let (seeders, completed, leechers) = torrent_entry.get_stats();
                        torrents_metrics.lock().await.seeders += u64::from(seeders);
                        torrents_metrics.lock().await.completed += u64::from(completed);
                        torrents_metrics.lock().await.leechers += u64::from(leechers);
                        torrents_metrics.lock().await.torrents += 1;
                    })
                    .await
                    .expect("Error torrent_metrics spawn");
                }
            })
            .collect::<Vec<_>>();

        join_all(futures).await;

        let torrents_metrics = Arc::try_unwrap(arc_torrents_metrics).expect("Could not unwrap arc_torrents_metrics");

        torrents_metrics.into_inner()
    }

    /// Remove inactive peers and (optionally) peerless torrents
    ///
    /// # Context: Tracker
    pub async fn cleanup_torrents(&self) {
        let mut torrents_lock = self.torrents.get_torrents_mut().await;

        // If we don't need to remove torrents we will use the faster iter
        if self.config.remove_peerless_torrents {
            let mut cleaned_torrents_map: BTreeMap<InfoHash, torrent::Entry> = BTreeMap::new();

            for (info_hash, torrent_entry) in &mut *torrents_lock {
                torrent_entry.remove_inactive_peers(self.config.max_peer_timeout);

                if torrent_entry.peers.is_empty() {
                    continue;
                }

                if self.config.persistent_torrent_completed_stat && torrent_entry.completed == 0 {
                    continue;
                }

                cleaned_torrents_map.insert(*info_hash, torrent_entry.clone());
            }

            *torrents_lock = cleaned_torrents_map;
        } else {
            for torrent_entry in (*torrents_lock).values_mut() {
                torrent_entry.remove_inactive_peers(self.config.max_peer_timeout);
            }
        }
    }

    /// It authenticates the peer `key` against the `Tracker` authentication
    /// key list.
    ///
    /// # Errors
    ///
    /// Will return an error if the the authentication key cannot be verified.
    ///
    /// # Context: Authentication
    pub async fn authenticate(&self, key: &Key) -> Result<(), auth::Error> {
        if self.is_private() {
            self.verify_auth_key(key).await
        } else {
            Ok(())
        }
    }

    /// It generates a new expiring authentication key.
    /// `lifetime` param is the duration in seconds for the new key.
    /// The key will be no longer valid after `lifetime` seconds.
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    pub async fn generate_auth_key(&self, lifetime: Duration) -> Result<auth::ExpiringKey, databases::error::Error> {
        let auth_key = auth::generate(lifetime);
        self.database.add_key_to_keys(&auth_key).await?;
        self.keys.write().await.insert(auth_key.key.clone(), auth_key.clone());
        Ok(auth_key)
    }

    /// It removes an authentication key.
    ///
    /// # Context: Authentication    
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `key` to the database.
    ///
    /// # Panics
    ///
    /// Will panic if key cannot be converted into a valid `Key`.
    pub async fn remove_auth_key(&self, key: &Key) -> Result<(), databases::error::Error> {
        self.database.remove_key_from_keys(key).await?;
        self.keys.write().await.remove(key);
        Ok(())
    }

    /// It verifies an authentication key.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `key::Error` if unable to get any `auth_key`.
    pub async fn verify_auth_key(&self, key: &Key) -> Result<(), auth::Error> {
        // code-review: this function is public only because it's used in a test.
        // We should change the test and make it private.
        match self.keys.read().await.get(key) {
            None => Err(auth::Error::UnableToReadKey {
                location: Location::caller(),
                key: Box::new(key.clone()),
            }),
            Some(key) => auth::verify(key),
        }
    }

    /// The `Tracker` stores the authentication keys in memory and in the database.
    /// In case you need to restart the `Tracker` you can load the keys from the database
    /// into memory with this function. Keys are automatically stored in the database when they
    /// are generated.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to `load_keys` from the database.
    pub async fn load_keys_from_database(&self) -> Result<(), databases::error::Error> {
        let keys_from_database = self.database.load_keys().await?;
        let mut keys = self.keys.write().await;

        keys.clear();

        for key in keys_from_database {
            keys.insert(key.key.clone(), key);
        }

        Ok(())
    }

    /// Right now, there is only authorization when the `Tracker` runs in
    /// `listed` or `private_listed` modes.
    ///
    /// # Context: Authorization
    ///
    /// # Errors
    ///
    /// Will return an error if the tracker is running in `listed` mode
    /// and the infohash is not whitelisted.
    pub async fn authorize(&self, info_hash: &InfoHash) -> Result<(), Error> {
        if !self.is_whitelisted() {
            return Ok(());
        }

        if self.is_info_hash_whitelisted(info_hash).await {
            return Ok(());
        }

        Err(Error::TorrentNotWhitelisted {
            info_hash: *info_hash,
            location: Location::caller(),
        })
    }

    /// It adds a torrent to the whitelist.
    /// Adding torrents is not relevant to public trackers.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `info_hash` into the whitelist database.
    pub async fn add_torrent_to_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.add_torrent_to_database_whitelist(info_hash).await?;
        self.add_torrent_to_memory_whitelist(info_hash).await;
        Ok(())
    }

    /// It adds a torrent to the whitelist if it has not been whitelisted previously
    async fn add_torrent_to_database_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        let is_whitelisted = self.database.is_info_hash_whitelisted(info_hash).await?;

        if is_whitelisted {
            return Ok(());
        }

        self.database.add_info_hash_to_whitelist(*info_hash).await?;

        Ok(())
    }

    pub async fn add_torrent_to_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.insert(*info_hash)
    }

    /// It removes a torrent from the whitelist.
    /// Removing torrents is not relevant to public trackers.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub async fn remove_torrent_from_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.remove_torrent_from_database_whitelist(info_hash).await?;
        self.remove_torrent_from_memory_whitelist(info_hash).await;
        Ok(())
    }

    /// It removes a torrent from the whitelist in the database.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub async fn remove_torrent_from_database_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        let is_whitelisted = self.database.is_info_hash_whitelisted(info_hash).await?;

        if !is_whitelisted {
            return Ok(());
        }

        self.database.remove_info_hash_from_whitelist(*info_hash).await?;

        Ok(())
    }

    /// It removes a torrent from the whitelist in memory.
    ///
    /// # Context: Whitelist
    pub async fn remove_torrent_from_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.remove(info_hash)
    }

    /// It checks if a torrent is whitelisted.
    ///
    /// # Context: Whitelist
    pub async fn is_info_hash_whitelisted(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.read().await.contains(info_hash)
    }

    /// It loads the whitelist from the database.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list whitelisted `info_hash`s from the database.
    pub async fn load_whitelist_from_database(&self) -> Result<(), databases::error::Error> {
        let whitelisted_torrents_from_database = self.database.load_whitelist().await?;
        let mut whitelist = self.whitelist.write().await;

        whitelist.clear();

        for info_hash in whitelisted_torrents_from_database {
            let _: bool = whitelist.insert(info_hash);
        }

        Ok(())
    }

    /// It return the `Tracker` [`statistics::Metrics`].
    ///
    /// # Context: Statistics
    pub async fn get_stats(&self) -> tokio::sync::RwLockReadGuard<'_, statistics::Metrics> {
        self.stats_repository.get_stats().await
    }

    /// It allows to send a statistic events which eventually will be used to update [`statistics::Metrics`].
    ///
    /// # Context: Statistics
    pub async fn send_stats_event(&self, event: statistics::Event) -> Option<Result<(), SendError<statistics::Event>>> {
        match &self.stats_event_sender {
            None => None,
            Some(stats_event_sender) => stats_event_sender.send_event(event).await,
        }
    }
}

#[must_use]
fn assign_ip_address_to_peer(remote_client_ip: &IpAddr, tracker_external_ip: Option<IpAddr>) -> IpAddr {
    if let Some(host_ip) = tracker_external_ip.filter(|_| remote_client_ip.is_loopback()) {
        host_ip
    } else {
        *remote_client_ip
    }
}

#[cfg(test)]
mod tests {

    mod the_tracker {

        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::str::FromStr;
        use std::sync::Arc;

        use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes};
        use torrust_tracker_test_helpers::configuration;

        use crate::core::peer::{self, Peer};
        use crate::core::services::tracker_factory;
        use crate::core::{TorrentsMetrics, Tracker};
        use crate::shared::bit_torrent::info_hash::InfoHash;
        use crate::shared::clock::DurationSinceUnixEpoch;

        fn public_tracker() -> Tracker {
            tracker_factory(configuration::ephemeral_mode_public().into())
        }

        fn private_tracker() -> Tracker {
            tracker_factory(configuration::ephemeral_mode_private().into())
        }

        fn whitelisted_tracker() -> Tracker {
            tracker_factory(configuration::ephemeral_mode_whitelisted().into())
        }

        pub fn tracker_persisting_torrents_in_database() -> Tracker {
            let mut configuration = configuration::ephemeral();
            configuration.persistent_torrent_completed_stat = true;
            tracker_factory(Arc::new(configuration))
        }

        fn sample_info_hash() -> InfoHash {
            "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap()
        }

        // The client peer IP
        fn peer_ip() -> IpAddr {
            IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap())
        }

        /// Sample peer whose state is not relevant for the tests
        fn sample_peer() -> Peer {
            complete_peer()
        }

        /// Sample peer when for tests that need more than one peer
        fn sample_peer_1() -> Peer {
            Peer {
                peer_id: peer::Id(*b"-qB00000000000000001"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8081),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes(0),
                downloaded: NumberOfBytes(0),
                left: NumberOfBytes(0),
                event: AnnounceEvent::Completed,
            }
        }

        /// Sample peer when for tests that need more than one peer
        fn sample_peer_2() -> Peer {
            Peer {
                peer_id: peer::Id(*b"-qB00000000000000002"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 2)), 8082),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes(0),
                downloaded: NumberOfBytes(0),
                left: NumberOfBytes(0),
                event: AnnounceEvent::Completed,
            }
        }

        fn seeder() -> Peer {
            complete_peer()
        }

        fn leecher() -> Peer {
            incomplete_peer()
        }

        fn started_peer() -> Peer {
            incomplete_peer()
        }

        fn completed_peer() -> Peer {
            complete_peer()
        }

        /// A peer that counts as `complete` is swarm metadata
        /// IMPORTANT!: it only counts if the it has been announce at least once before
        /// announcing the `AnnounceEvent::Completed` event.
        fn complete_peer() -> Peer {
            Peer {
                peer_id: peer::Id(*b"-qB00000000000000000"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes(0),
                downloaded: NumberOfBytes(0),
                left: NumberOfBytes(0), // No bytes left to download
                event: AnnounceEvent::Completed,
            }
        }

        /// A peer that counts as `incomplete` is swarm metadata
        fn incomplete_peer() -> Peer {
            Peer {
                peer_id: peer::Id(*b"-qB00000000000000000"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes(0),
                downloaded: NumberOfBytes(0),
                left: NumberOfBytes(1000), // Still bytes to download
                event: AnnounceEvent::Started,
            }
        }

        #[tokio::test]
        async fn should_collect_torrent_metrics() {
            let tracker = public_tracker();

            let torrents_metrics = tracker.get_torrents_metrics().await;

            assert_eq!(
                torrents_metrics,
                TorrentsMetrics {
                    seeders: 0,
                    completed: 0,
                    leechers: 0,
                    torrents: 0
                }
            );
        }

        #[tokio::test]
        async fn it_should_return_all_the_peers_for_a_given_torrent() {
            let tracker = public_tracker();

            let info_hash = sample_info_hash();
            let peer = sample_peer();

            tracker.update_torrent_with_peer_and_get_stats(&info_hash, &peer).await;

            let peers = tracker.get_torrent_peers(&info_hash).await;

            assert_eq!(peers, vec![peer]);
        }

        #[tokio::test]
        async fn it_should_return_all_the_peers_for_a_given_torrent_excluding_a_given_peer() {
            let tracker = public_tracker();

            let info_hash = sample_info_hash();
            let peer = sample_peer();

            tracker.update_torrent_with_peer_and_get_stats(&info_hash, &peer).await;

            let peers = tracker.get_torrent_peers_for_peer(&info_hash, &peer).await;

            assert_eq!(peers, vec![]);
        }

        #[tokio::test]
        async fn it_should_return_the_torrent_metrics() {
            let tracker = public_tracker();

            tracker
                .update_torrent_with_peer_and_get_stats(&sample_info_hash(), &leecher())
                .await;

            let torrent_metrics = tracker.get_torrents_metrics().await;

            assert_eq!(
                torrent_metrics,
                TorrentsMetrics {
                    seeders: 0,
                    completed: 0,
                    leechers: 1,
                    torrents: 1,
                }
            );
        }

        mod for_all_config_modes {

            mod handling_an_announce_request {

                use crate::core::tests::the_tracker::{
                    peer_ip, public_tracker, sample_info_hash, sample_peer, sample_peer_1, sample_peer_2,
                };

                mod should_assign_the_ip_to_the_peer {

                    use std::net::{IpAddr, Ipv4Addr};

                    use crate::core::assign_ip_address_to_peer;

                    #[test]
                    fn using_the_source_ip_instead_of_the_ip_in_the_announce_request() {
                        let remote_ip = IpAddr::V4(Ipv4Addr::new(126, 0, 0, 2));

                        let peer_ip = assign_ip_address_to_peer(&remote_ip, None);

                        assert_eq!(peer_ip, remote_ip);
                    }

                    mod and_when_the_client_ip_is_a_ipv4_loopback_ip {

                        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
                        use std::str::FromStr;

                        use crate::core::assign_ip_address_to_peer;

                        #[test]
                        fn it_should_use_the_loopback_ip_if_the_tracker_does_not_have_the_external_ip_configuration() {
                            let remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, None);

                            assert_eq!(peer_ip, remote_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_tracker_ip_in_tracker_configuration_if_it_is_defined() {
                            let remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

                            let tracker_external_ip = IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_ip_in_the_tracker_configuration_if_it_is_defined_even_if_the_external_ip_is_an_ipv6_ip(
                        ) {
                            let remote_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

                            let tracker_external_ip =
                                IpAddr::V6(Ipv6Addr::from_str("2345:0425:2CA1:0000:0000:0567:5673:23b5").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }
                    }

                    mod and_when_client_ip_is_a_ipv6_loopback_ip {

                        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
                        use std::str::FromStr;

                        use crate::core::assign_ip_address_to_peer;

                        #[test]
                        fn it_should_use_the_loopback_ip_if_the_tracker_does_not_have_the_external_ip_configuration() {
                            let remote_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, None);

                            assert_eq!(peer_ip, remote_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_ip_in_tracker_configuration_if_it_is_defined() {
                            let remote_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

                            let tracker_external_ip =
                                IpAddr::V6(Ipv6Addr::from_str("2345:0425:2CA1:0000:0000:0567:5673:23b5").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }

                        #[test]
                        fn it_should_use_the_external_ip_in_the_tracker_configuration_if_it_is_defined_even_if_the_external_ip_is_an_ipv4_ip(
                        ) {
                            let remote_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

                            let tracker_external_ip = IpAddr::V4(Ipv4Addr::from_str("126.0.0.1").unwrap());

                            let peer_ip = assign_ip_address_to_peer(&remote_ip, Some(tracker_external_ip));

                            assert_eq!(peer_ip, tracker_external_ip);
                        }
                    }
                }

                #[tokio::test]
                async fn it_should_return_the_announce_data_with_an_empty_peer_list_when_it_is_the_first_announced_peer() {
                    let tracker = public_tracker();

                    let mut peer = sample_peer();

                    let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip()).await;

                    assert_eq!(announce_data.peers, vec![]);
                }

                #[tokio::test]
                async fn it_should_return_the_announce_data_with_the_previously_announced_peers() {
                    let tracker = public_tracker();

                    let mut previously_announced_peer = sample_peer_1();
                    tracker
                        .announce(&sample_info_hash(), &mut previously_announced_peer, &peer_ip())
                        .await;

                    let mut peer = sample_peer_2();
                    let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip()).await;

                    assert_eq!(announce_data.peers, vec![previously_announced_peer]);
                }

                mod it_should_update_the_swarm_stats_for_the_torrent {

                    use crate::core::tests::the_tracker::{
                        completed_peer, leecher, peer_ip, public_tracker, sample_info_hash, seeder, started_peer,
                    };

                    #[tokio::test]
                    async fn when_the_peer_is_a_seeder() {
                        let tracker = public_tracker();

                        let mut peer = seeder();

                        let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip()).await;

                        assert_eq!(announce_data.swarm_stats.seeders, 1);
                    }

                    #[tokio::test]
                    async fn when_the_peer_is_a_leecher() {
                        let tracker = public_tracker();

                        let mut peer = leecher();

                        let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip()).await;

                        assert_eq!(announce_data.swarm_stats.leechers, 1);
                    }

                    #[tokio::test]
                    async fn when_a_previously_announced_started_peer_has_completed_downloading() {
                        let tracker = public_tracker();

                        // We have to announce with "started" event because peer does not count if peer was not previously known
                        let mut started_peer = started_peer();
                        tracker.announce(&sample_info_hash(), &mut started_peer, &peer_ip()).await;

                        let mut completed_peer = completed_peer();
                        let announce_data = tracker.announce(&sample_info_hash(), &mut completed_peer, &peer_ip()).await;

                        assert_eq!(announce_data.swarm_stats.completed, 1);
                    }
                }
            }

            mod handling_a_scrape_request {

                use std::net::{IpAddr, Ipv4Addr};

                use crate::core::tests::the_tracker::{complete_peer, incomplete_peer, public_tracker};
                use crate::core::{ScrapeData, SwarmMetadata};
                use crate::shared::bit_torrent::info_hash::InfoHash;

                #[tokio::test]
                async fn it_should_return_a_zeroed_swarm_metadata_for_the_requested_file_if_the_tracker_does_not_have_that_torrent(
                ) {
                    let tracker = public_tracker();

                    let info_hashes = vec!["3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap()];

                    let scrape_data = tracker.scrape(&info_hashes).await;

                    let mut expected_scrape_data = ScrapeData::empty();

                    expected_scrape_data.add_file_with_zeroed_metadata(&info_hashes[0]);

                    assert_eq!(scrape_data, expected_scrape_data);
                }

                #[tokio::test]
                async fn it_should_return_the_swarm_metadata_for_the_requested_file_if_the_tracker_has_that_torrent() {
                    let tracker = public_tracker();

                    let info_hash = "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap();

                    // Announce a "complete" peer for the torrent
                    let mut complete_peer = complete_peer();
                    tracker
                        .announce(&info_hash, &mut complete_peer, &IpAddr::V4(Ipv4Addr::new(126, 0, 0, 10)))
                        .await;

                    // Announce an "incomplete" peer for the torrent
                    let mut incomplete_peer = incomplete_peer();
                    tracker
                        .announce(&info_hash, &mut incomplete_peer, &IpAddr::V4(Ipv4Addr::new(126, 0, 0, 11)))
                        .await;

                    // Scrape
                    let scrape_data = tracker.scrape(&vec![info_hash]).await;

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

                #[tokio::test]
                async fn it_should_allow_scraping_for_multiple_torrents() {
                    let tracker = public_tracker();

                    let info_hashes = vec![
                        "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap(),
                        "99c82bb73505a3c0b453f9fa0e881d6e5a32a0c1".parse::<InfoHash>().unwrap(),
                    ];

                    let scrape_data = tracker.scrape(&info_hashes).await;

                    let mut expected_scrape_data = ScrapeData::empty();
                    expected_scrape_data.add_file_with_zeroed_metadata(&info_hashes[0]);
                    expected_scrape_data.add_file_with_zeroed_metadata(&info_hashes[1]);

                    assert_eq!(scrape_data, expected_scrape_data);
                }
            }
        }

        mod configured_as_whitelisted {

            mod handling_authorization {
                use crate::core::tests::the_tracker::{sample_info_hash, whitelisted_tracker};

                #[tokio::test]
                async fn it_should_authorize_the_announce_and_scrape_actions_on_whitelisted_torrents() {
                    let tracker = whitelisted_tracker();

                    let info_hash = sample_info_hash();

                    let result = tracker.add_torrent_to_whitelist(&info_hash).await;
                    assert!(result.is_ok());

                    let result = tracker.authorize(&info_hash).await;
                    assert!(result.is_ok());
                }

                #[tokio::test]
                async fn it_should_not_authorize_the_announce_and_scrape_actions_on_not_whitelisted_torrents() {
                    let tracker = whitelisted_tracker();

                    let info_hash = sample_info_hash();

                    let result = tracker.authorize(&info_hash).await;
                    assert!(result.is_err());
                }
            }

            mod handling_the_torrent_whitelist {
                use crate::core::tests::the_tracker::{sample_info_hash, whitelisted_tracker};

                #[tokio::test]
                async fn it_should_add_a_torrent_to_the_whitelist() {
                    let tracker = whitelisted_tracker();

                    let info_hash = sample_info_hash();

                    tracker.add_torrent_to_whitelist(&info_hash).await.unwrap();

                    assert!(tracker.is_info_hash_whitelisted(&info_hash).await);
                }

                #[tokio::test]
                async fn it_should_remove_a_torrent_from_the_whitelist() {
                    let tracker = whitelisted_tracker();

                    let info_hash = sample_info_hash();

                    tracker.add_torrent_to_whitelist(&info_hash).await.unwrap();

                    tracker.remove_torrent_from_whitelist(&info_hash).await.unwrap();

                    assert!(!tracker.is_info_hash_whitelisted(&info_hash).await);
                }

                mod persistence {
                    use crate::core::tests::the_tracker::{sample_info_hash, whitelisted_tracker};

                    #[tokio::test]
                    async fn it_should_load_the_whitelist_from_the_database() {
                        let tracker = whitelisted_tracker();

                        let info_hash = sample_info_hash();

                        tracker.add_torrent_to_whitelist(&info_hash).await.unwrap();

                        // Remove torrent from the in-memory whitelist
                        tracker.whitelist.write().await.remove(&info_hash);
                        assert!(!tracker.is_info_hash_whitelisted(&info_hash).await);

                        tracker.load_whitelist_from_database().await.unwrap();

                        assert!(tracker.is_info_hash_whitelisted(&info_hash).await);
                    }
                }
            }

            mod handling_an_announce_request {}

            mod handling_an_scrape_request {

                use crate::core::tests::the_tracker::{
                    complete_peer, incomplete_peer, peer_ip, sample_info_hash, whitelisted_tracker,
                };
                use crate::core::torrent::SwarmMetadata;
                use crate::core::ScrapeData;
                use crate::shared::bit_torrent::info_hash::InfoHash;

                #[test]
                fn it_should_be_able_to_build_a_zeroed_scrape_data_for_a_list_of_info_hashes() {
                    // Zeroed scrape data is used when the authentication for the scrape request fails.

                    let sample_info_hash = sample_info_hash();

                    let mut expected_scrape_data = ScrapeData::empty();
                    expected_scrape_data.add_file_with_zeroed_metadata(&sample_info_hash);

                    assert_eq!(ScrapeData::zeroed(&vec![sample_info_hash]), expected_scrape_data);
                }

                #[tokio::test]
                async fn it_should_return_the_zeroed_swarm_metadata_for_the_requested_file_if_it_is_not_whitelisted() {
                    let tracker = whitelisted_tracker();

                    let info_hash = "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap();

                    let mut peer = incomplete_peer();
                    tracker.announce(&info_hash, &mut peer, &peer_ip()).await;

                    // Announce twice to force non zeroed swarm metadata
                    let mut peer = complete_peer();
                    tracker.announce(&info_hash, &mut peer, &peer_ip()).await;

                    let scrape_data = tracker.scrape(&vec![info_hash]).await;

                    // The expected zeroed swarm metadata for the file
                    let mut expected_scrape_data = ScrapeData::empty();
                    expected_scrape_data.add_file(&info_hash, SwarmMetadata::zeroed());

                    assert_eq!(scrape_data, expected_scrape_data);
                }
            }
        }

        mod configured_as_private {

            mod handling_authentication {
                use std::str::FromStr;
                use std::time::Duration;

                use crate::core::auth;
                use crate::core::tests::the_tracker::private_tracker;

                #[tokio::test]
                async fn it_should_generate_the_expiring_authentication_keys() {
                    let tracker = private_tracker();

                    let key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    assert_eq!(key.valid_until, Duration::from_secs(100));
                }

                #[tokio::test]
                async fn it_should_authenticate_a_peer_by_using_a_key() {
                    let tracker = private_tracker();

                    let expiring_key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    let result = tracker.authenticate(&expiring_key.key()).await;

                    assert!(result.is_ok());
                }

                #[tokio::test]
                async fn it_should_fail_authenticating_a_peer_when_it_uses_an_unregistered_key() {
                    let tracker = private_tracker();

                    let unregistered_key = auth::Key::from_str("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap();

                    let result = tracker.authenticate(&unregistered_key).await;

                    assert!(result.is_err());
                }

                #[tokio::test]
                async fn it_should_verify_a_valid_authentication_key() {
                    // todo: this should not be tested directly because
                    // `verify_auth_key` should be a private method.
                    let tracker = private_tracker();

                    let expiring_key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    assert!(tracker.verify_auth_key(&expiring_key.key()).await.is_ok());
                }

                #[tokio::test]
                async fn it_should_fail_verifying_an_unregistered_authentication_key() {
                    let tracker = private_tracker();

                    let unregistered_key = auth::Key::from_str("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap();

                    assert!(tracker.verify_auth_key(&unregistered_key).await.is_err());
                }

                #[tokio::test]
                async fn it_should_remove_an_authentication_key() {
                    let tracker = private_tracker();

                    let expiring_key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    let result = tracker.remove_auth_key(&expiring_key.key()).await;

                    assert!(result.is_ok());
                    assert!(tracker.verify_auth_key(&expiring_key.key()).await.is_err());
                }

                #[tokio::test]
                async fn it_should_load_authentication_keys_from_the_database() {
                    let tracker = private_tracker();

                    let expiring_key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    // Remove the newly generated key in memory
                    tracker.keys.write().await.remove(&expiring_key.key());

                    let result = tracker.load_keys_from_database().await;

                    assert!(result.is_ok());
                    assert!(tracker.verify_auth_key(&expiring_key.key()).await.is_ok());
                }
            }

            mod handling_an_announce_request {}

            mod handling_an_scrape_request {}
        }

        mod configured_as_private_and_whitelisted {

            mod handling_an_announce_request {}

            mod handling_an_scrape_request {}
        }

        mod handling_torrent_persistence {
            use aquatic_udp_protocol::AnnounceEvent;

            use crate::core::tests::the_tracker::{sample_info_hash, sample_peer, tracker_persisting_torrents_in_database};

            #[tokio::test]
            async fn it_should_persist_the_number_of_completed_peers_for_all_torrents_into_the_database() {
                let tracker = tracker_persisting_torrents_in_database();

                let info_hash = sample_info_hash();

                let mut peer = sample_peer();

                peer.event = AnnounceEvent::Started;
                let swarm_stats = tracker.update_torrent_with_peer_and_get_stats(&info_hash, &peer).await;
                assert_eq!(swarm_stats.completed, 0);

                peer.event = AnnounceEvent::Completed;
                let swarm_stats = tracker.update_torrent_with_peer_and_get_stats(&info_hash, &peer).await;
                assert_eq!(swarm_stats.completed, 1);

                // Remove the newly updated torrent from memory
                tracker.torrents.get_torrents_mut().await.remove(&info_hash);

                tracker.load_torrents_from_database().await.unwrap();

                let torrents = tracker.torrents.get_torrents().await;
                assert!(torrents.contains_key(&info_hash));

                let torrent_entry = torrents.get(&info_hash).unwrap();

                // It persists the number of completed peers.
                assert_eq!(torrent_entry.completed, 1);

                // It does not persist the peers
                assert!(torrent_entry.peers.is_empty());
            }
        }
    }
}
