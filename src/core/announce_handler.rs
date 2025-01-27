use std::net::IpAddr;
use std::sync::Arc;

use bittorrent_primitives::info_hash::InfoHash;
use torrust_tracker_configuration::{Core, TORRENT_PEERS_LIMIT};
use torrust_tracker_primitives::core::AnnounceData;
use torrust_tracker_primitives::peer;
use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

use super::torrent::repository::in_memory::InMemoryTorrentRepository;
use super::torrent::repository::persisted::DatabasePersistentTorrentRepository;

pub struct AnnounceHandler {
    /// The tracker configuration.
    config: Core,

    /// The in-memory torrents repository.
    in_memory_torrent_repository: Arc<InMemoryTorrentRepository>,

    /// The persistent torrents repository.
    db_torrent_repository: Arc<DatabasePersistentTorrentRepository>,
}

impl AnnounceHandler {
    #[must_use]
    pub fn new(
        config: &Core,
        in_memory_torrent_repository: &Arc<InMemoryTorrentRepository>,
        db_torrent_repository: &Arc<DatabasePersistentTorrentRepository>,
    ) -> Self {
        Self {
            config: config.clone(),
            in_memory_torrent_repository: in_memory_torrent_repository.clone(),
            db_torrent_repository: db_torrent_repository.clone(),
        }
    }

    /// It handles an announce request.
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

        let peers = self
            .in_memory_torrent_repository
            .get_peers_for(info_hash, peer, peers_wanted.limit());

        AnnounceData {
            peers,
            stats,
            policy: self.config.announce_policy,
        }
    }

    /// It updates the torrent entry in memory, it also stores in the database
    /// the torrent info data which is persistent, and finally return the data
    /// needed for a `announce` request response.
    #[must_use]
    fn upsert_peer_and_get_stats(&self, info_hash: &InfoHash, peer: &peer::Peer) -> SwarmMetadata {
        let swarm_metadata_before = match self.in_memory_torrent_repository.get_opt_swarm_metadata(info_hash) {
            Some(swarm_metadata) => swarm_metadata,
            None => SwarmMetadata::zeroed(),
        };

        self.in_memory_torrent_repository.upsert_peer(info_hash, peer);

        let swarm_metadata_after = match self.in_memory_torrent_repository.get_opt_swarm_metadata(info_hash) {
            Some(swarm_metadata) => swarm_metadata,
            None => SwarmMetadata::zeroed(),
        };

        if swarm_metadata_before != swarm_metadata_after {
            self.persist_stats(info_hash, &swarm_metadata_after);
        }

        swarm_metadata_after
    }

    /// It stores the torrents stats into the database (if persistency is enabled).
    fn persist_stats(&self, info_hash: &InfoHash, swarm_metadata: &SwarmMetadata) {
        if self.config.tracker_policy.persistent_torrent_completed_stat {
            let completed = swarm_metadata.downloaded;
            let info_hash = *info_hash;

            drop(self.db_torrent_repository.save(&info_hash, completed));
        }
    }
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

#[must_use]
pub fn assign_ip_address_to_peer(remote_client_ip: &IpAddr, tracker_external_ip: Option<IpAddr>) -> IpAddr {
    if let Some(host_ip) = tracker_external_ip.filter(|_| remote_client_ip.is_loopback()) {
        host_ip
    } else {
        *remote_client_ip
    }
}
