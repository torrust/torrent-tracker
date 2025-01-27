//! `Announce` response for the HTTP tracker [`announce`](crate::v1::requests::announce::Announce) request.
//!
//! Data structures and logic to build the `announce` response.
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use derive_more::{AsRef, Constructor, From};
use torrust_tracker_contrib_bencode::{ben_bytes, ben_int, ben_list, ben_map, BMutAccess, BencodeMut};
use torrust_tracker_primitives::core::AnnounceData;
use torrust_tracker_primitives::peer;

/// An [`Announce`] response, that can be anything that is convertible from [`AnnounceData`].
///
/// The [`Announce`] can built from any data that implements: [`From<AnnounceData>`] and [`Into<Vec<u8>>`].
///
/// The two standard forms of an announce response are: [`Normal`] and [`Compact`].
///
///
/// _"To reduce the size of tracker responses and to reduce memory and
/// computational requirements in trackers, trackers may return peers as a
/// packed string rather than as a bencoded list."_
///
/// Refer to the official BEPs for more information:
///
/// - [BEP 03: The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
/// - [BEP 23: Tracker Returns Compact Peer Lists](https://www.bittorrent.org/beps/bep_0023.html)
/// - [BEP 07: IPv6 Tracker Extension](https://www.bittorrent.org/beps/bep_0007.html)

#[derive(Debug, AsRef, PartialEq, Constructor)]
pub struct Announce<E>
where
    E: From<AnnounceData> + Into<Vec<u8>>,
{
    pub data: E,
}

/// Build any [`Announce`] from an [`AnnounceData`].
impl<E: From<AnnounceData> + Into<Vec<u8>>> From<AnnounceData> for Announce<E> {
    fn from(data: AnnounceData) -> Self {
        Self::new(data.into())
    }
}

/// Format of the [`Normal`] (Non-Compact) Encoding
pub struct Normal {
    complete: i64,
    incomplete: i64,
    interval: i64,
    min_interval: i64,
    peers: Vec<NormalPeer>,
}

impl From<AnnounceData> for Normal {
    fn from(data: AnnounceData) -> Self {
        Self {
            complete: data.stats.complete.into(),
            incomplete: data.stats.incomplete.into(),
            interval: data.policy.interval.into(),
            min_interval: data.policy.interval_min.into(),
            peers: data.peers.iter().map(AsRef::as_ref).copied().collect(),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Normal {
    fn into(self) -> Vec<u8> {
        let mut peers_list = ben_list!();
        let peers_list_mut = peers_list.list_mut().unwrap();
        for peer in &self.peers {
            peers_list_mut.push(peer.into());
        }

        (ben_map! {
            "complete" => ben_int!(self.complete),
            "incomplete" => ben_int!(self.incomplete),
            "interval" => ben_int!(self.interval),
            "min interval" => ben_int!(self.min_interval),
            "peers" => peers_list.clone()
        })
        .encode()
    }
}

/// Format of the [`Compact`] Encoding
pub struct Compact {
    complete: i64,
    incomplete: i64,
    interval: i64,
    min_interval: i64,
    peers: Vec<u8>,
    peers6: Vec<u8>,
}

impl From<AnnounceData> for Compact {
    fn from(data: AnnounceData) -> Self {
        let compact_peers: Vec<CompactPeer> = data.peers.iter().map(AsRef::as_ref).copied().collect();

        let (peers, peers6): (Vec<CompactPeerData<Ipv4Addr>>, Vec<CompactPeerData<Ipv6Addr>>) =
            compact_peers.into_iter().collect();

        let peers_encoded: CompactPeersEncoded = peers.into_iter().collect();
        let peers_encoded_6: CompactPeersEncoded = peers6.into_iter().collect();

        Self {
            complete: data.stats.complete.into(),
            incomplete: data.stats.incomplete.into(),
            interval: data.policy.interval.into(),
            min_interval: data.policy.interval_min.into(),
            peers: peers_encoded.0,
            peers6: peers_encoded_6.0,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Compact {
    fn into(self) -> Vec<u8> {
        (ben_map! {
            "complete" => ben_int!(self.complete),
            "incomplete" => ben_int!(self.incomplete),
            "interval" => ben_int!(self.interval),
            "min interval" => ben_int!(self.min_interval),
            "peers" => ben_bytes!(self.peers),
            "peers6" => ben_bytes!(self.peers6)
        })
        .encode()
    }
}

/// A [`NormalPeer`], for the [`Normal`] form.
///
/// ```rust
/// use std::net::{IpAddr, Ipv4Addr};
/// use bittorrent_http_protocol::v1::responses::announce::{Normal, NormalPeer};
///
/// let peer = NormalPeer {
///     peer_id: *b"-qB00000000000000001",
///     ip: IpAddr::V4(Ipv4Addr::new(0x69, 0x69, 0x69, 0x69)), // 105.105.105.105
///     port: 0x7070,                                          // 28784
/// };
///
///  ```
#[derive(Debug, PartialEq)]
pub struct NormalPeer {
    /// The peer's ID.
    pub peer_id: [u8; 20],
    /// The peer's IP address.
    pub ip: IpAddr,
    /// The peer's port number.
    pub port: u16,
}

impl peer::Encoding for NormalPeer {}

impl From<peer::Peer> for NormalPeer {
    fn from(peer: peer::Peer) -> Self {
        NormalPeer {
            peer_id: peer.peer_id.0,
            ip: peer.peer_addr.ip(),
            port: peer.peer_addr.port(),
        }
    }
}

impl From<&NormalPeer> for BencodeMut<'_> {
    fn from(value: &NormalPeer) -> Self {
        ben_map! {
            "peer id" => ben_bytes!(value.peer_id.clone().to_vec()),
            "ip" => ben_bytes!(value.ip.to_string()),
            "port" => ben_int!(i64::from(value.port))
        }
    }
}

/// A [`CompactPeer`], for the [`Compact`] form.
///
///  _"To reduce the size of tracker responses and to reduce memory and
/// computational requirements in trackers, trackers may return peers as a
/// packed string rather than as a bencoded list."_
///
/// A part from reducing the size of the response, this format does not contain
/// the peer's ID.
///
/// ```rust
///  use std::net::{IpAddr, Ipv4Addr};
///  use bittorrent_http_protocol::v1::responses::announce::{Compact, CompactPeer, CompactPeerData};
///
///  let peer = CompactPeer::V4(CompactPeerData {
///     ip: Ipv4Addr::new(0x69, 0x69, 0x69, 0x69), // 105.105.105.105
///     port: 0x7070, // 28784
/// });
///
///  ```
///
/// Refer to [BEP 23: Tracker Returns Compact Peer Lists](https://www.bittorrent.org/beps/bep_0023.html)
/// for more information.
#[derive(Clone, Debug, PartialEq)]
pub enum CompactPeer {
    /// The peer's IP address.
    V4(CompactPeerData<Ipv4Addr>),
    /// The peer's port number.
    V6(CompactPeerData<Ipv6Addr>),
}

impl peer::Encoding for CompactPeer {}

impl From<peer::Peer> for CompactPeer {
    fn from(peer: peer::Peer) -> Self {
        match (peer.peer_addr.ip(), peer.peer_addr.port()) {
            (IpAddr::V4(ip), port) => Self::V4(CompactPeerData { ip, port }),
            (IpAddr::V6(ip), port) => Self::V6(CompactPeerData { ip, port }),
        }
    }
}

/// The [`CompactPeerData`], that made with either a [`Ipv4Addr`], or [`Ipv6Addr`] along with a `port`.
///
#[derive(Clone, Debug, PartialEq)]
pub struct CompactPeerData<V> {
    /// The peer's IP address.
    pub ip: V,
    /// The peer's port number.
    pub port: u16,
}

impl FromIterator<CompactPeer> for (Vec<CompactPeerData<Ipv4Addr>>, Vec<CompactPeerData<Ipv6Addr>>) {
    fn from_iter<T: IntoIterator<Item = CompactPeer>>(iter: T) -> Self {
        let mut peers_v4: Vec<CompactPeerData<Ipv4Addr>> = vec![];
        let mut peers_v6: Vec<CompactPeerData<Ipv6Addr>> = vec![];

        for peer in iter {
            match peer {
                CompactPeer::V4(peer) => peers_v4.push(peer),
                CompactPeer::V6(peer6) => peers_v6.push(peer6),
            }
        }

        (peers_v4, peers_v6)
    }
}

#[derive(From, PartialEq)]
struct CompactPeersEncoded(Vec<u8>);

impl FromIterator<CompactPeerData<Ipv4Addr>> for CompactPeersEncoded {
    fn from_iter<T: IntoIterator<Item = CompactPeerData<Ipv4Addr>>>(iter: T) -> Self {
        let mut bytes: Vec<u8> = vec![];

        for peer in iter {
            bytes
                .write_all(&u32::from(peer.ip).to_be_bytes())
                .expect("it should write peer ip");
            bytes.write_all(&peer.port.to_be_bytes()).expect("it should write peer port");
        }

        bytes.into()
    }
}

impl FromIterator<CompactPeerData<Ipv6Addr>> for CompactPeersEncoded {
    fn from_iter<T: IntoIterator<Item = CompactPeerData<Ipv6Addr>>>(iter: T) -> Self {
        let mut bytes: Vec<u8> = Vec::new();

        for peer in iter {
            bytes
                .write_all(&u128::from(peer.ip).to_be_bytes())
                .expect("it should write peer ip");
            bytes.write_all(&peer.port.to_be_bytes()).expect("it should write peer port");
        }
        bytes.into()
    }
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;

    use aquatic_udp_protocol::PeerId;
    use torrust_tracker_configuration::AnnouncePolicy;
    use torrust_tracker_primitives::core::AnnounceData;
    use torrust_tracker_primitives::peer::fixture::PeerBuilder;
    use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

    use crate::v1::responses::announce::{Announce, Compact, Normal};

    // Some ascii values used in tests:
    //
    // +-----------------+
    // | Dec | Hex | Chr |
    // +-----------------+
    // | 105 | 69  | i   |
    // | 112 | 70  | p   |
    // +-----------------+
    //
    // IP addresses and port numbers used in tests are chosen so that their bencoded representation
    // is also a valid string which makes asserts more readable.

    fn setup_announce_data() -> AnnounceData {
        let policy = AnnouncePolicy::new(111, 222);

        let peer_ipv4 = PeerBuilder::default()
            .with_peer_id(&PeerId(*b"-qB00000000000000001"))
            .with_peer_addr(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0x69, 0x69, 0x69, 0x69)), 0x7070))
            .build();

        let peer_ipv6 = PeerBuilder::default()
            .with_peer_id(&PeerId(*b"-qB00000000000000002"))
            .with_peer_addr(&SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969, 0x6969)),
                0x7070,
            ))
            .build();

        let peers = vec![Arc::new(peer_ipv4), Arc::new(peer_ipv6)];
        let stats = SwarmMetadata::new(333, 333, 444);

        AnnounceData::new(peers, stats, policy)
    }

    #[test]
    fn non_compact_announce_response_can_be_bencoded() {
        let response: Announce<Normal> = setup_announce_data().into();
        let bytes = response.data.into();

        // cspell:disable-next-line
        let expected_bytes = b"d8:completei333e10:incompletei444e8:intervali111e12:min intervali222e5:peersld2:ip15:105.105.105.1057:peer id20:-qB000000000000000014:porti28784eed2:ip39:6969:6969:6969:6969:6969:6969:6969:69697:peer id20:-qB000000000000000024:porti28784eeee";

        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            String::from_utf8(expected_bytes.to_vec()).unwrap()
        );
    }

    #[test]
    fn compact_announce_response_can_be_bencoded() {
        let response: Announce<Compact> = setup_announce_data().into();
        let bytes = response.data.into();

        let expected_bytes =
            // cspell:disable-next-line
            b"d8:completei333e10:incompletei444e8:intervali111e12:min intervali222e5:peers6:iiiipp6:peers618:iiiiiiiiiiiiiiiippe";

        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            String::from_utf8(expected_bytes.to_vec()).unwrap()
        );
    }
}
