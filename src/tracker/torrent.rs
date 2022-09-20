use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use aquatic_udp_protocol::AnnounceEvent;
use serde::{Deserialize, Serialize};

use crate::peer::TorrentPeer;
use crate::protocol::clock::clock::{DefaultClock, TimeNow};
use crate::{PeerId, MAX_SCRAPE_TORRENTS};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TorrentEntry {
    #[serde(skip)]
    pub peers: std::collections::BTreeMap<PeerId, TorrentPeer>,
    pub completed: u32,
}

impl TorrentEntry {
    pub fn new() -> TorrentEntry {
        TorrentEntry {
            peers: std::collections::BTreeMap::new(),
            completed: 0,
        }
    }

    // Update peer and return completed (times torrent has been downloaded)
    pub fn update_peer(&mut self, peer: &TorrentPeer) -> bool {
        let mut did_torrent_stats_change: bool = false;

        match peer.event {
            AnnounceEvent::Stopped => {
                let _ = self.peers.remove(&peer.peer_id);
            }
            AnnounceEvent::Completed => {
                let peer_old = self.peers.insert(peer.peer_id.clone(), peer.clone());
                // Don't count if peer was not previously known
                if peer_old.is_some() {
                    self.completed += 1;
                    did_torrent_stats_change = true;
                }
            }
            _ => {
                let _ = self.peers.insert(peer.peer_id.clone(), peer.clone());
            }
        }

        did_torrent_stats_change
    }

    pub fn get_peers(&self, client_addr: Option<&SocketAddr>) -> Vec<&TorrentPeer> {
        self.peers
            .values()
            .filter(|peer| match client_addr {
                // Don't filter on ip_version
                None => true,
                // Filter out different ip_version from remote_addr
                Some(remote_addr) => {
                    // Skip ip address of client
                    if peer.peer_addr.ip() == remote_addr.ip() {
                        return false;
                    }

                    match peer.peer_addr.ip() {
                        IpAddr::V4(_) => remote_addr.is_ipv4(),
                        IpAddr::V6(_) => remote_addr.is_ipv6(),
                    }
                }
            })
            .take(MAX_SCRAPE_TORRENTS as usize)
            .collect()
    }

    pub fn get_stats(&self) -> (u32, u32, u32) {
        let seeders: u32 = self.peers.values().filter(|peer| peer.is_seeder()).count() as u32;
        let leechers: u32 = self.peers.len() as u32 - seeders;
        (seeders, self.completed, leechers)
    }

    pub fn remove_inactive_peers(&mut self, max_peer_timeout: u32) {
        let current_cutoff = DefaultClock::sub(&Duration::from_secs(max_peer_timeout as u64)).unwrap_or_default();
        self.peers.retain(|_, peer| peer.updated > current_cutoff);
    }
}

#[derive(Debug)]
pub struct TorrentStats {
    pub completed: u32,
    pub seeders: u32,
    pub leechers: u32,
}

#[derive(Debug)]
pub enum TorrentError {
    TorrentNotWhitelisted,
    PeerNotAuthenticated,
    PeerKeyNotValid,
    NoPeersFound,
    CouldNotSendResponse,
    InvalidInfoHash,
}
