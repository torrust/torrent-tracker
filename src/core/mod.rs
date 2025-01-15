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
//! Once you have instantiated the `Tracker` you can `announce` a new [`peer::Peer`] with:
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
//! Refer to [`peer`] module for more information about peers.
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
//! > increased on every `announce` and `scrape` requests.
//!
//! The tracker exposes an event sender API that allows the tracker users to send events. When a higher application service handles a
//! `connection` , `announce` or `scrape` requests, it notifies the `Tracker` by sending statistics events.
//!
//! For example, the HTTP tracker would send an event like the following when it handles an `announce` request received from a peer using IP version 4.
//!
//! ```text
//! tracker.send_stats_event(statistics::event::Event::Tcp4Announce).await
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
pub mod services;
pub mod statistics;
pub mod torrent;
pub mod whitelist;

pub mod peer_tests;

use std::cmp::max;
use std::net::IpAddr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;

use auth::PeerKey;
use bittorrent_primitives::info_hash::InfoHash;
use error::PeerKeyError;
use tokio::sync::mpsc::error::SendError;
use torrust_tracker_clock::clock::Time;
use torrust_tracker_configuration::{AnnouncePolicy, Core, TORRENT_PEERS_LIMIT};
use torrust_tracker_located_error::Located;
use torrust_tracker_primitives::core::{AnnounceData, ScrapeData};
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
use torrust_tracker_primitives::torrent_metrics::TorrentsMetrics;
use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch};
use torrust_tracker_torrent_repository::entry::EntrySync;
use torrust_tracker_torrent_repository::repository::Repository;
use tracing::instrument;
use whitelist::WhiteListManager;

use self::auth::Key;
use self::error::Error;
use self::torrent::Torrents;
use crate::core::databases::Database;
use crate::CurrentClock;

/// The domain layer tracker service.
///
/// Its main responsibility is to handle the `announce` and `scrape` requests.
/// But it's also a container for the `Tracker` configuration, persistence,
/// authentication and other services.
///
/// > **NOTICE**: the `Tracker` is not responsible for handling the network layer.
/// > Typically, the `Tracker` is used by a higher application service that handles
/// > the network layer.
pub struct Tracker {
    /// The tracker configuration.
    config: Core,

    /// A database driver implementation: [`Sqlite3`](crate::core::databases::sqlite)
    /// or [`MySQL`](crate::core::databases::mysql)
    database: Arc<Box<dyn Database>>,

    /// Tracker users' keys. Only for private trackers.
    keys: tokio::sync::RwLock<std::collections::HashMap<Key, auth::PeerKey>>,

    /// The list of allowed torrents. Only for listed trackers.
    pub whitelist_manager: Arc<WhiteListManager>,

    /// The in-memory torrents repository.
    torrents: Arc<Torrents>,

    /// Service to send stats events.
    stats_event_sender: Option<Box<dyn statistics::event::sender::Sender>>,

    /// The in-memory stats repo.
    stats_repository: statistics::repository::Repository,
}

/// How many peers the peer announcing wants in the announce response.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum PeersWanted {
    /// The peer wants as many peers as possible in the announce response.
    #[default]
    All,
    /// The peer only wants a certain amount of peers in the announce response.
    Only { amount: usize },
}

impl PeersWanted {
    #[must_use]
    pub fn only(limit: u32) -> Self {
        let amount: usize = match limit.try_into() {
            Ok(amount) => amount,
            Err(_) => TORRENT_PEERS_LIMIT,
        };

        Self::Only { amount }
    }

    fn limit(&self) -> usize {
        match self {
            PeersWanted::All => TORRENT_PEERS_LIMIT,
            PeersWanted::Only { amount } => *amount,
        }
    }
}

impl From<i32> for PeersWanted {
    fn from(value: i32) -> Self {
        if value > 0 {
            match value.try_into() {
                Ok(peers_wanted) => Self::Only { amount: peers_wanted },
                Err(_) => Self::All,
            }
        } else {
            Self::All
        }
    }
}

/// This type contains the info needed to add a new tracker key.
///
/// You can upload a pre-generated key or let the app to generate a new one.
/// You can also set an expiration date or leave it empty (`None`) if you want
/// to create a permanent key that does not expire.
#[derive(Debug)]
pub struct AddKeyRequest {
    /// The pre-generated key. Use `None` to generate a random key.
    pub opt_key: Option<String>,

    /// How long the key will be valid in seconds. Use `None` for permanent keys.
    pub opt_seconds_valid: Option<u64>,
}

impl Tracker {
    /// `Tracker` constructor.
    ///
    /// # Errors
    ///
    /// Will return a `databases::error::Error` if unable to connect to database. The `Tracker` is responsible for the persistence.
    pub fn new(
        config: &Core,
        database: &Arc<Box<dyn Database>>,
        whitelist_manager: &Arc<WhiteListManager>,
        stats_event_sender: Option<Box<dyn statistics::event::sender::Sender>>,
        stats_repository: statistics::repository::Repository,
    ) -> Result<Tracker, databases::error::Error> {
        Ok(Tracker {
            config: config.clone(),
            database: database.clone(),
            keys: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            whitelist_manager: whitelist_manager.clone(),
            torrents: Arc::default(),
            stats_event_sender,
            stats_repository,
        })
    }

    /// Returns `true` is the tracker is in public mode.
    pub fn is_public(&self) -> bool {
        !self.config.private
    }

    /// Returns `true` is the tracker is in private mode.
    pub fn is_private(&self) -> bool {
        self.config.private
    }

    /// Returns `true` is the tracker is in whitelisted mode.
    pub fn is_listed(&self) -> bool {
        self.config.listed
    }

    /// Returns `true` if the tracker requires authentication.
    pub fn requires_authentication(&self) -> bool {
        self.is_private()
    }

    /// Returns `true` is the tracker is in whitelisted mode.
    pub fn is_behind_reverse_proxy(&self) -> bool {
        self.config.net.on_reverse_proxy
    }

    pub fn get_announce_policy(&self) -> AnnouncePolicy {
        self.config.announce_policy
    }

    pub fn get_maybe_external_ip(&self) -> Option<IpAddr> {
        self.config.net.external_ip
    }

    /// It handles an announce request.
    ///
    /// # Context: Tracker
    ///
    /// BEP 03: [The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html).
    pub fn announce(
        &self,
        info_hash: &InfoHash,
        peer: &mut peer::Peer,
        remote_client_ip: &IpAddr,
        peers_wanted: &PeersWanted,
    ) -> AnnounceData {
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

        tracing::debug!("Before: {peer:?}");
        peer.change_ip(&assign_ip_address_to_peer(remote_client_ip, self.config.net.external_ip));
        tracing::debug!("After: {peer:?}");

        let stats = self.upsert_peer_and_get_stats(info_hash, peer);

        let peers = self.get_peers_for(info_hash, peer, peers_wanted.limit());

        AnnounceData {
            peers,
            stats,
            policy: self.get_announce_policy(),
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
                Ok(()) => self.get_swarm_metadata(info_hash),
                Err(_) => SwarmMetadata::zeroed(),
            };
            scrape_data.add_file(info_hash, swarm_metadata);
        }

        scrape_data
    }

    /// It returns the data for a `scrape` response.
    fn get_swarm_metadata(&self, info_hash: &InfoHash) -> SwarmMetadata {
        match self.torrents.get(info_hash) {
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
    pub fn load_torrents_from_database(&self) -> Result<(), databases::error::Error> {
        let persistent_torrents = self.database.load_persistent_torrents()?;

        self.torrents.import_persistent(&persistent_torrents);

        Ok(())
    }

    /// # Context: Tracker
    ///
    /// Get torrent peers for a given torrent and client.
    ///
    /// It filters out the client making the request.
    fn get_peers_for(&self, info_hash: &InfoHash, peer: &peer::Peer, limit: usize) -> Vec<Arc<peer::Peer>> {
        match self.torrents.get(info_hash) {
            None => vec![],
            Some(entry) => entry.get_peers_for_client(&peer.peer_addr, Some(max(limit, TORRENT_PEERS_LIMIT))),
        }
    }

    /// # Context: Tracker
    ///
    /// Get torrent peers for a given torrent.
    pub fn get_torrent_peers(&self, info_hash: &InfoHash) -> Vec<Arc<peer::Peer>> {
        match self.torrents.get(info_hash) {
            None => vec![],
            Some(entry) => entry.get_peers(Some(TORRENT_PEERS_LIMIT)),
        }
    }

    /// It updates the torrent entry in memory, it also stores in the database
    /// the torrent info data which is persistent, and finally return the data
    /// needed for a `announce` request response.
    ///
    /// # Context: Tracker
    pub fn upsert_peer_and_get_stats(&self, info_hash: &InfoHash, peer: &peer::Peer) -> SwarmMetadata {
        let swarm_metadata_before = match self.torrents.get_swarm_metadata(info_hash) {
            Some(swarm_metadata) => swarm_metadata,
            None => SwarmMetadata::zeroed(),
        };

        self.torrents.upsert_peer(info_hash, peer);

        let swarm_metadata_after = match self.torrents.get_swarm_metadata(info_hash) {
            Some(swarm_metadata) => swarm_metadata,
            None => SwarmMetadata::zeroed(),
        };

        if swarm_metadata_before != swarm_metadata_after {
            self.persist_stats(info_hash, &swarm_metadata_after);
        }

        swarm_metadata_after
    }

    /// It stores the torrents stats into the database (if persistency is enabled).
    ///
    /// # Context: Tracker
    fn persist_stats(&self, info_hash: &InfoHash, swarm_metadata: &SwarmMetadata) {
        if self.config.tracker_policy.persistent_torrent_completed_stat {
            let completed = swarm_metadata.downloaded;
            let info_hash = *info_hash;

            drop(self.database.save_persistent_torrent(&info_hash, completed));
        }
    }

    /// It calculates and returns the general `Tracker`
    /// [`TorrentsMetrics`]
    ///
    /// # Context: Tracker
    ///
    /// # Panics
    /// Panics if unable to get the torrent metrics.
    pub fn get_torrents_metrics(&self) -> TorrentsMetrics {
        self.torrents.get_metrics()
    }

    /// Remove inactive peers and (optionally) peerless torrents.
    ///
    /// # Context: Tracker
    pub fn cleanup_torrents(&self) {
        let current_cutoff = CurrentClock::now_sub(&Duration::from_secs(u64::from(self.config.tracker_policy.max_peer_timeout)))
            .unwrap_or_default();

        self.torrents.remove_inactive_peers(current_cutoff);

        if self.config.tracker_policy.remove_peerless_torrents {
            self.torrents.remove_peerless_torrents(&self.config.tracker_policy);
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

    /// Adds new peer keys to the tracker.
    ///
    /// Keys can be pre-generated or randomly created. They can also be permanent or expire.
    ///
    /// # Errors
    ///
    /// Will return an error if:
    ///
    /// - The key duration overflows the duration type maximum value.
    /// - The provided pre-generated key is invalid.
    /// - The key could not been persisted due to database issues.
    pub async fn add_peer_key(&self, add_key_req: AddKeyRequest) -> Result<auth::PeerKey, PeerKeyError> {
        // code-review: all methods related to keys should be moved to a new independent "keys" service.

        match add_key_req.opt_key {
            // Upload pre-generated key
            Some(pre_existing_key) => {
                if let Some(seconds_valid) = add_key_req.opt_seconds_valid {
                    // Expiring key
                    let Some(valid_until) = CurrentClock::now_add(&Duration::from_secs(seconds_valid)) else {
                        return Err(PeerKeyError::DurationOverflow { seconds_valid });
                    };

                    let key = pre_existing_key.parse::<Key>();

                    match key {
                        Ok(key) => match self.add_auth_key(key, Some(valid_until)).await {
                            Ok(auth_key) => Ok(auth_key),
                            Err(err) => Err(PeerKeyError::DatabaseError {
                                source: Located(err).into(),
                            }),
                        },
                        Err(err) => Err(PeerKeyError::InvalidKey {
                            key: pre_existing_key,
                            source: Located(err).into(),
                        }),
                    }
                } else {
                    // Permanent key
                    let key = pre_existing_key.parse::<Key>();

                    match key {
                        Ok(key) => match self.add_permanent_auth_key(key).await {
                            Ok(auth_key) => Ok(auth_key),
                            Err(err) => Err(PeerKeyError::DatabaseError {
                                source: Located(err).into(),
                            }),
                        },
                        Err(err) => Err(PeerKeyError::InvalidKey {
                            key: pre_existing_key,
                            source: Located(err).into(),
                        }),
                    }
                }
            }
            // Generate a new random key
            None => match add_key_req.opt_seconds_valid {
                // Expiring key
                Some(seconds_valid) => match self.generate_auth_key(Some(Duration::from_secs(seconds_valid))).await {
                    Ok(auth_key) => Ok(auth_key),
                    Err(err) => Err(PeerKeyError::DatabaseError {
                        source: Located(err).into(),
                    }),
                },
                // Permanent key
                None => match self.generate_permanent_auth_key().await {
                    Ok(auth_key) => Ok(auth_key),
                    Err(err) => Err(PeerKeyError::DatabaseError {
                        source: Located(err).into(),
                    }),
                },
            },
        }
    }

    /// It generates a new permanent authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    pub async fn generate_permanent_auth_key(&self) -> Result<auth::PeerKey, databases::error::Error> {
        self.generate_auth_key(None).await
    }

    /// It generates a new expiring authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    ///
    /// # Arguments
    ///
    /// * `lifetime` - The duration in seconds for the new key. The key will be
    ///   no longer valid after `lifetime` seconds.
    pub async fn generate_auth_key(&self, lifetime: Option<Duration>) -> Result<auth::PeerKey, databases::error::Error> {
        let auth_key = auth::generate_key(lifetime);

        self.database.add_key_to_keys(&auth_key)?;
        self.keys.write().await.insert(auth_key.key.clone(), auth_key.clone());
        Ok(auth_key)
    }

    /// It adds a pre-generated permanent authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the
    /// database. For example, if the key already exist.
    ///
    /// # Arguments
    ///
    /// * `key` - The pre-generated key.
    pub async fn add_permanent_auth_key(&self, key: Key) -> Result<auth::PeerKey, databases::error::Error> {
        self.add_auth_key(key, None).await
    }

    /// It adds a pre-generated authentication key.
    ///
    /// Authentication keys are used by HTTP trackers.
    ///
    /// # Context: Authentication
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the
    /// database. For example, if the key already exist.
    ///
    /// # Arguments
    ///
    /// * `key` - The pre-generated key.
    /// * `lifetime` - The duration in seconds for the new key. The key will be
    ///   no longer valid after `lifetime` seconds.
    pub async fn add_auth_key(
        &self,
        key: Key,
        valid_until: Option<DurationSinceUnixEpoch>,
    ) -> Result<auth::PeerKey, databases::error::Error> {
        let auth_key = PeerKey { key, valid_until };

        // code-review: should we return a friendly error instead of the DB
        // constrain error when the key already exist? For now, it's returning
        // the specif error for each DB driver when a UNIQUE constrain fails.
        self.database.add_key_to_keys(&auth_key)?;
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
    pub async fn remove_auth_key(&self, key: &Key) -> Result<(), databases::error::Error> {
        self.database.remove_key_from_keys(key)?;
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
    async fn verify_auth_key(&self, key: &Key) -> Result<(), auth::Error> {
        match self.keys.read().await.get(key) {
            None => Err(auth::Error::UnableToReadKey {
                location: Location::caller(),
                key: Box::new(key.clone()),
            }),
            Some(key) => match self.config.private_mode {
                Some(private_mode) => {
                    if private_mode.check_keys_expiration {
                        return auth::verify_key_expiration(key);
                    }

                    Ok(())
                }
                None => auth::verify_key_expiration(key),
            },
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
        let keys_from_database = self.database.load_keys()?;
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
    #[instrument(skip(self, info_hash), err)]
    pub async fn authorize(&self, info_hash: &InfoHash) -> Result<(), Error> {
        if !self.is_listed() {
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
        self.whitelist_manager.add_torrent_to_whitelist(info_hash).await
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
        self.whitelist_manager.remove_torrent_from_whitelist(info_hash).await
    }

    /// It checks if a torrent is whitelisted.
    ///
    /// # Context: Whitelist
    pub async fn is_info_hash_whitelisted(&self, info_hash: &InfoHash) -> bool {
        self.whitelist_manager.is_info_hash_whitelisted(info_hash).await
    }

    /// It loads the whitelist from the database.
    ///
    /// # Context: Whitelist
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list whitelisted `info_hash`s from the database.
    pub async fn load_whitelist_from_database(&self) -> Result<(), databases::error::Error> {
        self.whitelist_manager.load_whitelist_from_database().await
    }

    /// It return the `Tracker` [`statistics::metrics::Metrics`].
    ///
    /// # Context: Statistics
    pub async fn get_stats(&self) -> tokio::sync::RwLockReadGuard<'_, statistics::metrics::Metrics> {
        self.stats_repository.get_stats().await
    }

    /// It allows to send a statistic events which eventually will be used to update [`statistics::metrics::Metrics`].
    ///
    /// # Context: Statistics
    pub async fn send_stats_event(
        &self,
        event: statistics::event::Event,
    ) -> Option<Result<(), SendError<statistics::event::Event>>> {
        match &self.stats_event_sender {
            None => None,
            Some(stats_event_sender) => stats_event_sender.send_event(event).await,
        }
    }

    /// It drops the database tables.
    ///
    /// # Errors
    ///
    /// Will return `Err` if unable to drop tables.
    pub fn drop_database_tables(&self) -> Result<(), databases::error::Error> {
        // todo: this is only used for testing. WE have to pass the database
        // reference directly to the tests instead of via the tracker.
        self.database.drop_database_tables()
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

        use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
        use bittorrent_primitives::info_hash::fixture::gen_seeded_infohash;
        use bittorrent_primitives::info_hash::InfoHash;
        use torrust_tracker_configuration::TORRENT_PEERS_LIMIT;
        use torrust_tracker_primitives::DurationSinceUnixEpoch;
        use torrust_tracker_test_helpers::configuration;

        use crate::core::peer::Peer;
        use crate::core::services::tracker_factory;
        use crate::core::{TorrentsMetrics, Tracker};

        fn public_tracker() -> Tracker {
            tracker_factory(&configuration::ephemeral_public())
        }

        fn private_tracker() -> Tracker {
            tracker_factory(&configuration::ephemeral_private())
        }

        fn whitelisted_tracker() -> Tracker {
            tracker_factory(&configuration::ephemeral_listed())
        }

        pub fn tracker_persisting_torrents_in_database() -> Tracker {
            let mut configuration = configuration::ephemeral();
            configuration.core.tracker_policy.persistent_torrent_completed_stat = true;
            tracker_factory(&configuration)
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
                peer_id: PeerId(*b"-qB00000000000000001"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8081),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes::new(0),
                downloaded: NumberOfBytes::new(0),
                left: NumberOfBytes::new(0),
                event: AnnounceEvent::Completed,
            }
        }

        /// Sample peer when for tests that need more than one peer
        fn sample_peer_2() -> Peer {
            Peer {
                peer_id: PeerId(*b"-qB00000000000000002"),
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 2)), 8082),
                updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                uploaded: NumberOfBytes::new(0),
                downloaded: NumberOfBytes::new(0),
                left: NumberOfBytes::new(0),
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
        fn incomplete_peer() -> Peer {
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

        #[tokio::test]
        async fn should_collect_torrent_metrics() {
            let tracker = public_tracker();

            let torrents_metrics = tracker.get_torrents_metrics();

            assert_eq!(
                torrents_metrics,
                TorrentsMetrics {
                    complete: 0,
                    downloaded: 0,
                    incomplete: 0,
                    torrents: 0
                }
            );
        }

        #[tokio::test]
        async fn it_should_return_the_peers_for_a_given_torrent() {
            let tracker = public_tracker();

            let info_hash = sample_info_hash();
            let peer = sample_peer();

            tracker.upsert_peer_and_get_stats(&info_hash, &peer);

            let peers = tracker.get_torrent_peers(&info_hash);

            assert_eq!(peers, vec![Arc::new(peer)]);
        }

        /// It generates a peer id from a number where the number is the last
        /// part of the peer ID. For example, for `12` it returns
        /// `-qB00000000000000012`.
        fn numeric_peer_id(two_digits_value: i32) -> PeerId {
            // Format idx as a string with leading zeros, ensuring it has exactly 2 digits
            let idx_str = format!("{two_digits_value:02}");

            // Create the base part of the peer ID.
            let base = b"-qB00000000000000000";

            // Concatenate the base with idx bytes, ensuring the total length is 20 bytes.
            let mut peer_id_bytes = [0u8; 20];
            peer_id_bytes[..base.len()].copy_from_slice(base);
            peer_id_bytes[base.len() - idx_str.len()..].copy_from_slice(idx_str.as_bytes());

            PeerId(peer_id_bytes)
        }

        #[tokio::test]
        async fn it_should_return_74_peers_at_the_most_for_a_given_torrent() {
            let tracker = public_tracker();

            let info_hash = sample_info_hash();

            for idx in 1..=75 {
                let peer = Peer {
                    peer_id: numeric_peer_id(idx),
                    peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, idx.try_into().unwrap())), 8080),
                    updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                    uploaded: NumberOfBytes::new(0),
                    downloaded: NumberOfBytes::new(0),
                    left: NumberOfBytes::new(0), // No bytes left to download
                    event: AnnounceEvent::Completed,
                };

                tracker.upsert_peer_and_get_stats(&info_hash, &peer);
            }

            let peers = tracker.get_torrent_peers(&info_hash);

            assert_eq!(peers.len(), 74);
        }

        #[tokio::test]
        async fn it_should_return_the_peers_for_a_given_torrent_excluding_a_given_peer() {
            let tracker = public_tracker();

            let info_hash = sample_info_hash();
            let peer = sample_peer();

            tracker.upsert_peer_and_get_stats(&info_hash, &peer);

            let peers = tracker.get_peers_for(&info_hash, &peer, TORRENT_PEERS_LIMIT);

            assert_eq!(peers, vec![]);
        }

        #[tokio::test]
        async fn it_should_return_74_peers_at_the_most_for_a_given_torrent_when_it_filters_out_a_given_peer() {
            let tracker = public_tracker();

            let info_hash = sample_info_hash();

            let excluded_peer = sample_peer();

            tracker.upsert_peer_and_get_stats(&info_hash, &excluded_peer);

            // Add 74 peers
            for idx in 2..=75 {
                let peer = Peer {
                    peer_id: numeric_peer_id(idx),
                    peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, idx.try_into().unwrap())), 8080),
                    updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
                    uploaded: NumberOfBytes::new(0),
                    downloaded: NumberOfBytes::new(0),
                    left: NumberOfBytes::new(0), // No bytes left to download
                    event: AnnounceEvent::Completed,
                };

                tracker.upsert_peer_and_get_stats(&info_hash, &peer);
            }

            let peers = tracker.get_peers_for(&info_hash, &excluded_peer, TORRENT_PEERS_LIMIT);

            assert_eq!(peers.len(), 74);
        }

        #[tokio::test]
        async fn it_should_return_the_torrent_metrics() {
            let tracker = public_tracker();

            tracker.upsert_peer_and_get_stats(&sample_info_hash(), &leecher());

            let torrent_metrics = tracker.get_torrents_metrics();

            assert_eq!(
                torrent_metrics,
                TorrentsMetrics {
                    complete: 0,
                    downloaded: 0,
                    incomplete: 1,
                    torrents: 1,
                }
            );
        }

        #[tokio::test]
        async fn it_should_get_many_the_torrent_metrics() {
            let tracker = public_tracker();

            let start_time = std::time::Instant::now();
            for i in 0..1_000_000 {
                tracker.upsert_peer_and_get_stats(&gen_seeded_infohash(&i), &leecher());
            }
            let result_a = start_time.elapsed();

            let start_time = std::time::Instant::now();
            let torrent_metrics = tracker.get_torrents_metrics();
            let result_b = start_time.elapsed();

            assert_eq!(
                (torrent_metrics),
                (TorrentsMetrics {
                    complete: 0,
                    downloaded: 0,
                    incomplete: 1_000_000,
                    torrents: 1_000_000,
                }),
                "{result_a:?} {result_b:?}"
            );
        }

        mod for_all_config_modes {

            mod handling_an_announce_request {

                use std::sync::Arc;

                use crate::core::tests::the_tracker::{
                    peer_ip, public_tracker, sample_info_hash, sample_peer, sample_peer_1, sample_peer_2,
                };
                use crate::core::PeersWanted;

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

                    let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                    assert_eq!(announce_data.peers, vec![]);
                }

                #[tokio::test]
                async fn it_should_return_the_announce_data_with_the_previously_announced_peers() {
                    let tracker = public_tracker();

                    let mut previously_announced_peer = sample_peer_1();
                    tracker.announce(
                        &sample_info_hash(),
                        &mut previously_announced_peer,
                        &peer_ip(),
                        &PeersWanted::All,
                    );

                    let mut peer = sample_peer_2();
                    let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                    assert_eq!(announce_data.peers, vec![Arc::new(previously_announced_peer)]);
                }

                mod it_should_update_the_swarm_stats_for_the_torrent {

                    use crate::core::tests::the_tracker::{
                        completed_peer, leecher, peer_ip, public_tracker, sample_info_hash, seeder, started_peer,
                    };
                    use crate::core::PeersWanted;

                    #[tokio::test]
                    async fn when_the_peer_is_a_seeder() {
                        let tracker = public_tracker();

                        let mut peer = seeder();

                        let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                        assert_eq!(announce_data.stats.complete, 1);
                    }

                    #[tokio::test]
                    async fn when_the_peer_is_a_leecher() {
                        let tracker = public_tracker();

                        let mut peer = leecher();

                        let announce_data = tracker.announce(&sample_info_hash(), &mut peer, &peer_ip(), &PeersWanted::All);

                        assert_eq!(announce_data.stats.incomplete, 1);
                    }

                    #[tokio::test]
                    async fn when_a_previously_announced_started_peer_has_completed_downloading() {
                        let tracker = public_tracker();

                        // We have to announce with "started" event because peer does not count if peer was not previously known
                        let mut started_peer = started_peer();
                        tracker.announce(&sample_info_hash(), &mut started_peer, &peer_ip(), &PeersWanted::All);

                        let mut completed_peer = completed_peer();
                        let announce_data =
                            tracker.announce(&sample_info_hash(), &mut completed_peer, &peer_ip(), &PeersWanted::All);

                        assert_eq!(announce_data.stats.downloaded, 1);
                    }
                }
            }

            mod handling_a_scrape_request {

                use std::net::{IpAddr, Ipv4Addr};

                use bittorrent_primitives::info_hash::InfoHash;

                use crate::core::tests::the_tracker::{complete_peer, incomplete_peer, public_tracker};
                use crate::core::{PeersWanted, ScrapeData, SwarmMetadata};

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
                    tracker.announce(
                        &info_hash,
                        &mut complete_peer,
                        &IpAddr::V4(Ipv4Addr::new(126, 0, 0, 10)),
                        &PeersWanted::All,
                    );

                    // Announce an "incomplete" peer for the torrent
                    let mut incomplete_peer = incomplete_peer();
                    tracker.announce(
                        &info_hash,
                        &mut incomplete_peer,
                        &IpAddr::V4(Ipv4Addr::new(126, 0, 0, 11)),
                        &PeersWanted::All,
                    );

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
                        tracker
                            .whitelist_manager
                            .remove_torrent_from_memory_whitelist(&info_hash)
                            .await;
                        assert!(!tracker.is_info_hash_whitelisted(&info_hash).await);

                        tracker.load_whitelist_from_database().await.unwrap();

                        assert!(tracker.is_info_hash_whitelisted(&info_hash).await);
                    }
                }
            }

            mod handling_an_announce_request {}

            mod handling_an_scrape_request {

                use bittorrent_primitives::info_hash::InfoHash;
                use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

                use crate::core::tests::the_tracker::{
                    complete_peer, incomplete_peer, peer_ip, sample_info_hash, whitelisted_tracker,
                };
                use crate::core::{PeersWanted, ScrapeData};

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
                    tracker.announce(&info_hash, &mut peer, &peer_ip(), &PeersWanted::All);

                    // Announce twice to force non zeroed swarm metadata
                    let mut peer = complete_peer();
                    tracker.announce(&info_hash, &mut peer, &peer_ip(), &PeersWanted::All);

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

                use crate::core::auth::{self};
                use crate::core::tests::the_tracker::private_tracker;

                #[tokio::test]
                async fn it_should_fail_authenticating_a_peer_when_it_uses_an_unregistered_key() {
                    let tracker = private_tracker();

                    let unregistered_key = auth::Key::from_str("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap();

                    let result = tracker.authenticate(&unregistered_key).await;

                    assert!(result.is_err());
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

                    let expiring_key = tracker.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

                    let result = tracker.remove_auth_key(&expiring_key.key()).await;

                    assert!(result.is_ok());
                    assert!(tracker.verify_auth_key(&expiring_key.key()).await.is_err());
                }

                #[tokio::test]
                async fn it_should_load_authentication_keys_from_the_database() {
                    let tracker = private_tracker();

                    let expiring_key = tracker.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

                    // Remove the newly generated key in memory
                    tracker.keys.write().await.remove(&expiring_key.key());

                    let result = tracker.load_keys_from_database().await;

                    assert!(result.is_ok());
                    assert!(tracker.verify_auth_key(&expiring_key.key()).await.is_ok());
                }

                mod with_expiring_and {

                    mod randomly_generated_keys {
                        use std::time::Duration;

                        use torrust_tracker_clock::clock::Time;
                        use torrust_tracker_configuration::v2_0_0::core::PrivateMode;

                        use crate::core::auth::Key;
                        use crate::core::tests::the_tracker::private_tracker;
                        use crate::CurrentClock;

                        #[tokio::test]
                        async fn it_should_generate_the_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

                            assert_eq!(
                                peer_key.valid_until,
                                Some(CurrentClock::now_add(&Duration::from_secs(100)).unwrap())
                            );
                        }

                        #[tokio::test]
                        async fn it_should_authenticate_a_peer_with_the_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker.generate_auth_key(Some(Duration::from_secs(100))).await.unwrap();

                            let result = tracker.authenticate(&peer_key.key()).await;

                            assert!(result.is_ok());
                        }

                        #[tokio::test]
                        async fn it_should_accept_an_expired_key_when_checking_expiration_is_disabled_in_configuration() {
                            let mut tracker = private_tracker();

                            tracker.config.private_mode = Some(PrivateMode {
                                check_keys_expiration: false,
                            });

                            let past_timestamp = Duration::ZERO;

                            let peer_key = tracker
                                .add_auth_key(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap(), Some(past_timestamp))
                                .await
                                .unwrap();

                            assert!(tracker.authenticate(&peer_key.key()).await.is_ok());
                        }
                    }

                    mod pre_generated_keys {
                        use std::time::Duration;

                        use torrust_tracker_clock::clock::Time;
                        use torrust_tracker_configuration::v2_0_0::core::PrivateMode;

                        use crate::core::auth::Key;
                        use crate::core::tests::the_tracker::private_tracker;
                        use crate::core::AddKeyRequest;
                        use crate::CurrentClock;

                        #[tokio::test]
                        async fn it_should_add_a_pre_generated_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker
                                .add_peer_key(AddKeyRequest {
                                    opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                                    opt_seconds_valid: Some(100),
                                })
                                .await
                                .unwrap();

                            assert_eq!(
                                peer_key.valid_until,
                                Some(CurrentClock::now_add(&Duration::from_secs(100)).unwrap())
                            );
                        }

                        #[tokio::test]
                        async fn it_should_authenticate_a_peer_with_the_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker
                                .add_peer_key(AddKeyRequest {
                                    opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                                    opt_seconds_valid: Some(100),
                                })
                                .await
                                .unwrap();

                            let result = tracker.authenticate(&peer_key.key()).await;

                            assert!(result.is_ok());
                        }

                        #[tokio::test]
                        async fn it_should_accept_an_expired_key_when_checking_expiration_is_disabled_in_configuration() {
                            let mut tracker = private_tracker();

                            tracker.config.private_mode = Some(PrivateMode {
                                check_keys_expiration: false,
                            });

                            let peer_key = tracker
                                .add_peer_key(AddKeyRequest {
                                    opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                                    opt_seconds_valid: Some(0),
                                })
                                .await
                                .unwrap();

                            assert!(tracker.authenticate(&peer_key.key()).await.is_ok());
                        }
                    }
                }

                mod with_permanent_and {

                    mod randomly_generated_keys {
                        use crate::core::tests::the_tracker::private_tracker;

                        #[tokio::test]
                        async fn it_should_generate_the_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker.generate_permanent_auth_key().await.unwrap();

                            assert_eq!(peer_key.valid_until, None);
                        }

                        #[tokio::test]
                        async fn it_should_authenticate_a_peer_with_the_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker.generate_permanent_auth_key().await.unwrap();

                            let result = tracker.authenticate(&peer_key.key()).await;

                            assert!(result.is_ok());
                        }
                    }

                    mod pre_generated_keys {
                        use crate::core::auth::Key;
                        use crate::core::tests::the_tracker::private_tracker;
                        use crate::core::AddKeyRequest;

                        #[tokio::test]
                        async fn it_should_add_a_pre_generated_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker
                                .add_peer_key(AddKeyRequest {
                                    opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                                    opt_seconds_valid: None,
                                })
                                .await
                                .unwrap();

                            assert_eq!(peer_key.valid_until, None);
                        }

                        #[tokio::test]
                        async fn it_should_authenticate_a_peer_with_the_key() {
                            let tracker = private_tracker();

                            let peer_key = tracker
                                .add_peer_key(AddKeyRequest {
                                    opt_key: Some(Key::new("YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ").unwrap().to_string()),
                                    opt_seconds_valid: None,
                                })
                                .await
                                .unwrap();

                            let result = tracker.authenticate(&peer_key.key()).await;

                            assert!(result.is_ok());
                        }
                    }
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
            use torrust_tracker_torrent_repository::entry::EntrySync;
            use torrust_tracker_torrent_repository::repository::Repository;

            use crate::core::tests::the_tracker::{sample_info_hash, sample_peer, tracker_persisting_torrents_in_database};

            #[tokio::test]
            async fn it_should_persist_the_number_of_completed_peers_for_all_torrents_into_the_database() {
                let tracker = tracker_persisting_torrents_in_database();

                let info_hash = sample_info_hash();

                let mut peer = sample_peer();

                peer.event = AnnounceEvent::Started;
                let swarm_stats = tracker.upsert_peer_and_get_stats(&info_hash, &peer);
                assert_eq!(swarm_stats.downloaded, 0);

                peer.event = AnnounceEvent::Completed;
                let swarm_stats = tracker.upsert_peer_and_get_stats(&info_hash, &peer);
                assert_eq!(swarm_stats.downloaded, 1);

                // Remove the newly updated torrent from memory
                tracker.torrents.remove(&info_hash);

                tracker.load_torrents_from_database().unwrap();

                let torrent_entry = tracker.torrents.get(&info_hash).expect("it should be able to get entry");

                // It persists the number of completed peers.
                assert_eq!(torrent_entry.get_swarm_metadata().downloaded, 1);

                // It does not persist the peers
                assert!(torrent_entry.peers_is_empty());
            }
        }
    }
}
