#![cfg(test)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aquatic_udp_protocol::{AnnounceEvent, NumberOfBytes, PeerId};
use torrust_tracker_clock::clock::stopped::Stopped as _;
use torrust_tracker_clock::clock::{self, Time};
use torrust_tracker_primitives::peer;

use crate::CurrentClock;

#[test]
fn it_should_be_serializable() {
    clock::Stopped::local_set_to_unix_epoch();

    let torrent_peer = peer::Peer {
        peer_id: PeerId(*b"-qB0000-000000000000"),
        peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 8080),
        updated: CurrentClock::now(),
        uploaded: NumberOfBytes::new(0),
        downloaded: NumberOfBytes::new(0),
        left: NumberOfBytes::new(0),
        event: AnnounceEvent::Started,
    };

    let raw_json = serde_json::to_string(&torrent_peer).unwrap();

    let expected_raw_json = r#"
            {
                "peer_id": {
                    "id": "0x2d7142303030302d303030303030303030303030",
                    "client": "qBittorrent"
                },
                "peer_addr":"126.0.0.1:8080",
                "updated":0,
                "uploaded":0,
                "downloaded":0,
                "left":0,
                "event":"Started"
            }
        "#;

    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw_json).unwrap(),
        serde_json::from_str::<serde_json::Value>(expected_raw_json).unwrap()
    );
}
