//! `Torrent` and `ListItem` API resources.
//!
//! - `Torrent` is the full torrent resource.
//! - `ListItem` is a list item resource on a torrent list. `ListItem` does
//!   include a `peers` field but it is always `None` in the struct and `null` in
//!   the JSON response.
use bittorrent_tracker_core::torrent::services::{BasicInfo, Info};
use serde::{Deserialize, Serialize};

/// `Torrent` API resource.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Torrent {
    /// The torrent's info hash v1.
    pub info_hash: String,
    /// The torrent's seeders counter. Active peers with a full copy of the
    /// torrent.
    pub seeders: u64,
    /// The torrent's completed counter. Peers that have ever completed the
    /// download.
    pub completed: u64,
    /// The torrent's leechers counter. Active peers that are downloading the
    /// torrent.
    pub leechers: u64,
    /// The torrent's peers. See [`Peer`](crate::servers::apis::v1::context::torrent::resources::peer::Peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<super::peer::Peer>>,
}

/// `ListItem` API resource. A list item on a torrent list.
/// `ListItem` does include a `peers` field but it is always `None` in the
///  struct and `null` in the JSON response.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ListItem {
    /// The torrent's info hash v1.
    pub info_hash: String,
    /// The torrent's seeders counter. Active peers with a full copy of the
    /// torrent.
    pub seeders: u64,
    /// The torrent's completed counter. Peers that have ever completed the
    /// download.
    pub completed: u64,
    /// The torrent's leechers counter. Active peers that are downloading the
    /// torrent.
    pub leechers: u64,
}

impl ListItem {
    #[must_use]
    pub fn new_vec(basic_info_vec: &[BasicInfo]) -> Vec<Self> {
        basic_info_vec
            .iter()
            .map(|basic_info| ListItem::from((*basic_info).clone()))
            .collect()
    }
}

/// Maps an array of the domain type [`BasicInfo`]
/// to the API resource type [`ListItem`].
#[must_use]
pub fn to_resource(basic_info_vec: &[BasicInfo]) -> Vec<ListItem> {
    basic_info_vec
        .iter()
        .map(|basic_info| ListItem::from((*basic_info).clone()))
        .collect()
}

impl From<Info> for Torrent {
    fn from(info: Info) -> Self {
        let peers: Option<super::peer::Vector> = info.peers.map(|peers| peers.into_iter().collect());

        let peers: Option<Vec<super::peer::Peer>> = peers.map(|peers| peers.0);

        Self {
            info_hash: info.info_hash.to_string(),
            seeders: info.seeders,
            completed: info.completed,
            leechers: info.leechers,
            peers,
        }
    }
}

impl From<BasicInfo> for ListItem {
    fn from(basic_info: BasicInfo) -> Self {
        Self {
            info_hash: basic_info.info_hash.to_string(),
            seeders: basic_info.seeders,
            completed: basic_info.completed,
            leechers: basic_info.leechers,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::str::FromStr;

    use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
    use bittorrent_primitives::info_hash::InfoHash;
    use bittorrent_tracker_core::torrent::services::{BasicInfo, Info};
    use torrust_tracker_primitives::{peer, DurationSinceUnixEpoch};

    use super::Torrent;
    use crate::servers::apis::v1::context::torrent::resources::peer::Peer;
    use crate::servers::apis::v1::context::torrent::resources::torrent::ListItem;

    fn sample_peer() -> peer::Peer {
        peer::Peer {
            peer_id: PeerId(*b"-qB00000000000000000"),
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
            updated: DurationSinceUnixEpoch::new(1_669_397_478_934, 0),
            uploaded: NumberOfBytes::new(0),
            downloaded: NumberOfBytes::new(0),
            left: NumberOfBytes::new(0),
            event: AnnounceEvent::Started,
        }
    }

    #[test]
    fn torrent_resource_should_be_converted_from_torrent_info() {
        assert_eq!(
            Torrent::from(Info {
                info_hash: InfoHash::from_str("9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d").unwrap(), // DevSkim: ignore DS173237
                seeders: 1,
                completed: 2,
                leechers: 3,
                peers: Some(vec![sample_peer()]),
            }),
            Torrent {
                info_hash: "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_string(), // DevSkim: ignore DS173237
                seeders: 1,
                completed: 2,
                leechers: 3,
                peers: Some(vec![Peer::from(sample_peer())]),
            }
        );
    }

    #[test]
    fn torrent_resource_list_item_should_be_converted_from_the_basic_torrent_info() {
        assert_eq!(
            ListItem::from(BasicInfo {
                info_hash: InfoHash::from_str("9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d").unwrap(), // DevSkim: ignore DS173237
                seeders: 1,
                completed: 2,
                leechers: 3,
            }),
            ListItem {
                info_hash: "9e0217d0fa71c87332cd8bf9dbeabcb2c2cf3c4d".to_string(), // DevSkim: ignore DS173237
                seeders: 1,
                completed: 2,
                leechers: 3,
            }
        );
    }
}
