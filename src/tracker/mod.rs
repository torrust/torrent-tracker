pub mod auth;
pub mod error;
pub mod peer;
pub mod services;
pub mod statistics;
pub mod torrent;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::panic::Location;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::error::SendError;
use tokio::sync::{RwLock, RwLockReadGuard};
use torrust_tracker_configuration::Configuration;
use torrust_tracker_primitives::TrackerMode;

use self::auth::Key;
use self::error::Error;
use self::peer::Peer;
use self::torrent::{SwarmMetadata, SwarmStats};
use crate::databases::{self, Database};
use crate::protocol::info_hash::InfoHash;

pub struct Tracker {
    pub config: Arc<Configuration>,
    mode: TrackerMode,
    keys: RwLock<std::collections::HashMap<Key, auth::ExpiringKey>>,
    whitelist: RwLock<std::collections::HashSet<InfoHash>>,
    torrents: RwLock<std::collections::BTreeMap<InfoHash, torrent::Entry>>,
    stats_event_sender: Option<Box<dyn statistics::EventSender>>,
    stats_repository: statistics::Repo,
    pub database: Box<dyn Database>,
}

#[derive(Debug, PartialEq, Default)]
pub struct TorrentsMetrics {
    // code-review: consider using `SwarmStats` for
    // `seeders`, `completed`, and `leechers` attributes.
    // pub swarm_stats: SwarmStats;
    pub seeders: u64,
    pub completed: u64,
    pub leechers: u64,
    pub torrents: u64,
}

#[derive(Debug, PartialEq, Default)]
pub struct AnnounceData {
    pub peers: Vec<Peer>,
    pub swarm_stats: SwarmStats,
    pub interval: u32,
    pub interval_min: u32,
}

#[derive(Debug, PartialEq, Default)]
pub struct ScrapeData {
    pub files: HashMap<InfoHash, SwarmMetadata>,
}

impl ScrapeData {
    #[must_use]
    pub fn empty() -> Self {
        let files: HashMap<InfoHash, SwarmMetadata> = HashMap::new();
        Self { files }
    }

    #[must_use]
    pub fn zeroed(info_hashes: &Vec<InfoHash>) -> Self {
        let mut scrape_data = Self::empty();

        for info_hash in info_hashes {
            scrape_data.add_file(info_hash, SwarmMetadata::zeroed());
        }

        scrape_data
    }

    pub fn add_file(&mut self, info_hash: &InfoHash, swarm_metadata: SwarmMetadata) {
        self.files.insert(*info_hash, swarm_metadata);
    }

    pub fn add_file_with_zeroed_metadata(&mut self, info_hash: &InfoHash) {
        self.files.insert(*info_hash, SwarmMetadata::zeroed());
    }
}

impl Tracker {
    /// # Errors
    ///
    /// Will return a `databases::error::Error` if unable to connect to database.
    pub fn new(
        config: Arc<Configuration>,
        stats_event_sender: Option<Box<dyn statistics::EventSender>>,
        stats_repository: statistics::Repo,
    ) -> Result<Tracker, databases::error::Error> {
        let database = databases::driver::build(&config.db_driver, &config.db_path)?;

        let mode = config.mode;

        Ok(Tracker {
            config,
            mode,
            keys: RwLock::new(std::collections::HashMap::new()),
            whitelist: RwLock::new(std::collections::HashSet::new()),
            torrents: RwLock::new(std::collections::BTreeMap::new()),
            stats_event_sender,
            stats_repository,
            database,
        })
    }

    pub fn is_public(&self) -> bool {
        self.mode == TrackerMode::Public
    }

    pub fn is_private(&self) -> bool {
        self.mode == TrackerMode::Private || self.mode == TrackerMode::PrivateListed
    }

    pub fn is_whitelisted(&self) -> bool {
        self.mode == TrackerMode::Listed || self.mode == TrackerMode::PrivateListed
    }

    pub fn requires_authentication(&self) -> bool {
        self.is_private()
    }

    /// It handles an announce request.
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

        let peers = self.get_peers_for_peer(info_hash, peer).await;

        AnnounceData {
            peers,
            swarm_stats,
            interval: self.config.announce_interval,
            interval_min: self.config.min_announce_interval,
        }
    }

    /// It handles a scrape request.
    ///
    /// BEP 48: [Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html).
    pub async fn scrape(&self, info_hashes: &Vec<InfoHash>) -> ScrapeData {
        let mut scrape_data = ScrapeData::empty();

        for info_hash in info_hashes {
            let swarm_metadata = match self.authorize(info_hash).await {
                Ok(_) => self.get_swarm_metadata(info_hash).await,
                Err(_) => SwarmMetadata::zeroed(),
            };
            scrape_data.add_file(info_hash, swarm_metadata);
        }

        scrape_data
    }

    async fn get_swarm_metadata(&self, info_hash: &InfoHash) -> SwarmMetadata {
        let torrents = self.get_torrents().await;
        match torrents.get(info_hash) {
            Some(torrent_entry) => torrent_entry.get_swarm_metadata(),
            None => SwarmMetadata::default(),
        }
    }

    /// # Errors
    ///
    /// Will return a `database::Error` if unable to add the `auth_key` to the database.
    pub async fn generate_auth_key(&self, lifetime: Duration) -> Result<auth::ExpiringKey, databases::error::Error> {
        let auth_key = auth::generate(lifetime);
        self.database.add_key_to_keys(&auth_key).await?;
        self.keys.write().await.insert(auth_key.key.clone(), auth_key.clone());
        Ok(auth_key)
    }

    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `key` to the database.
    ///
    /// # Panics
    ///
    /// Will panic if key cannot be converted into a valid `Key`.
    pub async fn remove_auth_key(&self, key: &str) -> Result<(), databases::error::Error> {
        // todo: change argument `key: &str` to `key: &Key`
        self.database.remove_key_from_keys(key).await?;
        self.keys.write().await.remove(&key.parse::<Key>().unwrap());
        Ok(())
    }

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

    /// Adding torrents is not relevant to public trackers.
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

    /// Removing torrents is not relevant to public trackers.
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to remove the `info_hash` from the whitelist database.
    pub async fn remove_torrent_from_whitelist(&self, info_hash: &InfoHash) -> Result<(), databases::error::Error> {
        self.remove_torrent_from_database_whitelist(info_hash).await?;
        self.remove_torrent_from_memory_whitelist(info_hash).await;
        Ok(())
    }

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

    pub async fn remove_torrent_from_memory_whitelist(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.write().await.remove(info_hash)
    }

    pub async fn is_info_hash_whitelisted(&self, info_hash: &InfoHash) -> bool {
        self.whitelist.read().await.contains(info_hash)
    }

    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list whitelisted `info_hash`s from the database.
    pub async fn load_whitelist_from_database(&self) -> Result<(), databases::error::Error> {
        let whitelisted_torrents_from_database = self.database.load_whitelist().await?;
        let mut whitelist = self.whitelist.write().await;

        whitelist.clear();

        for info_hash in whitelisted_torrents_from_database {
            let _ = whitelist.insert(info_hash);
        }

        Ok(())
    }

    /// # Errors
    ///
    /// Will return a `torrent::Error::PeerKeyNotValid` if the `key` is not valid.
    ///
    /// Will return a `torrent::Error::PeerNotAuthenticated` if the `key` is `None`.
    ///
    /// Will return a `torrent::Error::TorrentNotWhitelisted` if the the Tracker is in listed mode and the `info_hash` is not whitelisted.
    pub async fn authenticate_request(&self, info_hash: &InfoHash, key: &Option<Key>) -> Result<(), Error> {
        // todo: this is a deprecated method.
        // We're splitting authentication and authorization responsibilities.
        // Use `authenticate` and `authorize` instead.

        // Authentication

        // no authentication needed in public mode
        if self.is_public() {
            return Ok(());
        }

        // check if auth_key is set and valid
        if self.is_private() {
            match key {
                Some(key) => {
                    if let Err(e) = self.verify_auth_key(key).await {
                        return Err(Error::PeerKeyNotValid {
                            key: key.clone(),
                            source: (Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>).into(),
                        });
                    }
                }
                None => {
                    return Err(Error::PeerNotAuthenticated {
                        location: Location::caller(),
                    });
                }
            }
        }

        // Authorization

        // check if info_hash is whitelisted
        if self.is_whitelisted() && !self.is_info_hash_whitelisted(info_hash).await {
            return Err(Error::TorrentNotWhitelisted {
                info_hash: *info_hash,
                location: Location::caller(),
            });
        }

        Ok(())
    }

    /// # Errors
    ///
    /// Will return an error if the the authentication key cannot be verified.
    pub async fn authenticate(&self, key: &Key) -> Result<(), auth::Error> {
        if self.is_private() {
            self.verify_auth_key(key).await
        } else {
            Ok(())
        }
    }

    /// The only authorization process is the whitelist.
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

        return Err(Error::TorrentNotWhitelisted {
            info_hash: *info_hash,
            location: Location::caller(),
        });
    }

    /// Loading the torrents from database into memory
    ///
    /// # Errors
    ///
    /// Will return a `database::Error` if unable to load the list of `persistent_torrents` from the database.
    pub async fn load_torrents_from_database(&self) -> Result<(), databases::error::Error> {
        let persistent_torrents = self.database.load_persistent_torrents().await?;

        let mut torrents = self.torrents.write().await;

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

    async fn get_peers_for_peer(&self, info_hash: &InfoHash, peer: &Peer) -> Vec<peer::Peer> {
        let read_lock = self.torrents.read().await;

        match read_lock.get(info_hash) {
            None => vec![],
            Some(entry) => entry.get_peers_for_peer(peer).into_iter().copied().collect(),
        }
    }

    /// Get all torrent peers for a given torrent
    pub async fn get_all_torrent_peers(&self, info_hash: &InfoHash) -> Vec<peer::Peer> {
        let read_lock = self.torrents.read().await;

        match read_lock.get(info_hash) {
            None => vec![],
            Some(entry) => entry.get_all_peers().into_iter().copied().collect(),
        }
    }

    pub async fn update_torrent_with_peer_and_get_stats(&self, info_hash: &InfoHash, peer: &peer::Peer) -> torrent::SwarmStats {
        // code-review: consider splitting the function in two (command and query segregation).
        // `update_torrent_with_peer` and `get_stats`

        let mut torrents = self.torrents.write().await;

        let torrent_entry = match torrents.entry(*info_hash) {
            Entry::Vacant(vacant) => vacant.insert(torrent::Entry::new()),
            Entry::Occupied(entry) => entry.into_mut(),
        };

        let stats_updated = torrent_entry.update_peer(peer);

        // todo: move this action to a separate worker
        if self.config.persistent_torrent_completed_stat && stats_updated {
            let _ = self
                .database
                .save_persistent_torrent(info_hash, torrent_entry.completed)
                .await;
        }

        let (seeders, completed, leechers) = torrent_entry.get_stats();

        torrent::SwarmStats {
            completed,
            seeders,
            leechers,
        }
    }

    pub async fn get_torrents(&self) -> RwLockReadGuard<'_, BTreeMap<InfoHash, torrent::Entry>> {
        self.torrents.read().await
    }

    pub async fn get_torrents_metrics(&self) -> TorrentsMetrics {
        let mut torrents_metrics = TorrentsMetrics {
            seeders: 0,
            completed: 0,
            leechers: 0,
            torrents: 0,
        };

        let db = self.get_torrents().await;

        db.values().for_each(|torrent_entry| {
            let (seeders, completed, leechers) = torrent_entry.get_stats();
            torrents_metrics.seeders += u64::from(seeders);
            torrents_metrics.completed += u64::from(completed);
            torrents_metrics.leechers += u64::from(leechers);
            torrents_metrics.torrents += 1;
        });

        torrents_metrics
    }

    pub async fn get_stats(&self) -> RwLockReadGuard<'_, statistics::Metrics> {
        self.stats_repository.get_stats().await
    }

    pub async fn send_stats_event(&self, event: statistics::Event) -> Option<Result<(), SendError<statistics::Event>>> {
        match &self.stats_event_sender {
            None => None,
            Some(stats_event_sender) => stats_event_sender.send_event(event).await,
        }
    }

    // Remove inactive peers and (optionally) peerless torrents
    pub async fn cleanup_torrents(&self) {
        let mut torrents_lock = self.torrents.write().await;

        // If we don't need to remove torrents we will use the faster iter
        if self.config.remove_peerless_torrents {
            torrents_lock.retain(|_, torrent_entry| {
                torrent_entry.remove_inactive_peers(self.config.max_peer_timeout);

                if self.config.persistent_torrent_completed_stat {
                    torrent_entry.completed > 0 || !torrent_entry.peers.is_empty()
                } else {
                    !torrent_entry.peers.is_empty()
                }
            });
        } else {
            for (_, torrent_entry) in torrents_lock.iter_mut() {
                torrent_entry.remove_inactive_peers(self.config.max_peer_timeout);
            }
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
        use torrust_tracker_configuration::Configuration;
        use torrust_tracker_primitives::TrackerMode;
        use torrust_tracker_test_helpers::configuration;

        use crate::protocol::clock::DurationSinceUnixEpoch;
        use crate::protocol::info_hash::InfoHash;
        use crate::tracker::peer::{self, Peer};
        use crate::tracker::statistics::Keeper;
        use crate::tracker::{TorrentsMetrics, Tracker};

        pub fn public_tracker() -> Tracker {
            let mut configuration = configuration::ephemeral();
            configuration.mode = TrackerMode::Public;
            tracker_factory(configuration)
        }

        pub fn private_tracker() -> Tracker {
            let mut configuration = configuration::ephemeral();
            configuration.mode = TrackerMode::Private;
            tracker_factory(configuration)
        }

        pub fn whitelisted_tracker() -> Tracker {
            let mut configuration = configuration::ephemeral();
            configuration.mode = TrackerMode::Listed;
            tracker_factory(configuration)
        }

        pub fn tracker_persisting_torrents_in_database() -> Tracker {
            let mut configuration = configuration::ephemeral();
            configuration.persistent_torrent_completed_stat = true;
            tracker_factory(configuration)
        }

        pub fn tracker_factory(configuration: Configuration) -> Tracker {
            // code-review: the tracker initialization is duplicated in many places. Consider make this function public.

            // Initialize stats tracker
            let (stats_event_sender, stats_repository) = Keeper::new_active_instance();

            // Initialize Torrust tracker
            match Tracker::new(Arc::new(configuration), Some(stats_event_sender), stats_repository) {
                Ok(tracker) => tracker,
                Err(error) => {
                    panic!("{}", error)
                }
            }
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

            let peers = tracker.get_all_torrent_peers(&info_hash).await;

            assert_eq!(peers, vec![peer]);
        }

        #[tokio::test]
        async fn it_should_return_all_the_peers_for_a_given_torrent_excluding_a_given_peer() {
            let tracker = public_tracker();

            let info_hash = sample_info_hash();
            let peer = sample_peer();

            tracker.update_torrent_with_peer_and_get_stats(&info_hash, &peer).await;

            let peers = tracker.get_peers_for_peer(&info_hash, &peer).await;

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

                use crate::tracker::tests::the_tracker::{
                    peer_ip, public_tracker, sample_info_hash, sample_peer, sample_peer_1, sample_peer_2,
                };

                mod should_assign_the_ip_to_the_peer {

                    use std::net::{IpAddr, Ipv4Addr};

                    use crate::tracker::assign_ip_address_to_peer;

                    #[test]
                    fn using_the_source_ip_instead_of_the_ip_in_the_announce_request() {
                        let remote_ip = IpAddr::V4(Ipv4Addr::new(126, 0, 0, 2));

                        let peer_ip = assign_ip_address_to_peer(&remote_ip, None);

                        assert_eq!(peer_ip, remote_ip);
                    }

                    mod and_when_the_client_ip_is_a_ipv4_loopback_ip {

                        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
                        use std::str::FromStr;

                        use crate::tracker::assign_ip_address_to_peer;

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

                        use crate::tracker::assign_ip_address_to_peer;

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

                    use crate::tracker::tests::the_tracker::{
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

                use crate::protocol::info_hash::InfoHash;
                use crate::tracker::tests::the_tracker::{complete_peer, incomplete_peer, public_tracker};
                use crate::tracker::{ScrapeData, SwarmMetadata};

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
                use crate::tracker::tests::the_tracker::{sample_info_hash, whitelisted_tracker};

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
                use crate::tracker::tests::the_tracker::{sample_info_hash, whitelisted_tracker};

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
                    use crate::tracker::tests::the_tracker::{sample_info_hash, whitelisted_tracker};

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

                use crate::protocol::info_hash::InfoHash;
                use crate::tracker::tests::the_tracker::{
                    complete_peer, incomplete_peer, peer_ip, sample_info_hash, whitelisted_tracker,
                };
                use crate::tracker::torrent::SwarmMetadata;
                use crate::tracker::ScrapeData;

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

                use crate::tracker::auth;
                use crate::tracker::tests::the_tracker::private_tracker;

                #[tokio::test]
                async fn it_should_generate_the_expiring_authentication_keys() {
                    let tracker = private_tracker();

                    let key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    assert_eq!(key.valid_until, Duration::from_secs(100));
                }

                #[tokio::test]
                async fn it_should_authenticate_a_peer_by_using_a_key() {
                    let tracker = private_tracker();

                    let key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    let result = tracker.authenticate(&key.id()).await;

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

                    let key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    assert!(tracker.verify_auth_key(&key.id()).await.is_ok());
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

                    let key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    let result = tracker.remove_auth_key(&key.id().to_string()).await;

                    assert!(result.is_ok());
                    assert!(tracker.verify_auth_key(&key.id()).await.is_err());
                }

                #[tokio::test]
                async fn it_should_load_authentication_keys_from_the_database() {
                    let tracker = private_tracker();

                    let key = tracker.generate_auth_key(Duration::from_secs(100)).await.unwrap();

                    // Remove the newly generated key in memory
                    tracker.keys.write().await.remove(&key.id());

                    let result = tracker.load_keys_from_database().await;

                    assert!(result.is_ok());
                    assert!(tracker.verify_auth_key(&key.id()).await.is_ok());
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

            use crate::tracker::tests::the_tracker::{sample_info_hash, sample_peer, tracker_persisting_torrents_in_database};

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
                tracker.torrents.write().await.remove(&info_hash);

                tracker.load_torrents_from_database().await.unwrap();

                let torrents = tracker.get_torrents().await;
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
