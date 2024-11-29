//! HTTP Tracker.
//!
//! This module contains the HTTP tracker implementation.
//!
//! The HTTP tracker is a simple HTTP server that responds to two `GET` requests:
//!
//! - `Announce`: used to announce the presence of a peer to the tracker.
//! - `Scrape`: used to get information about a torrent.
//!
//! Refer to the [`bit_torrent`](crate::shared::bit_torrent) module for more
//! information about the `BitTorrent` protocol.
//!
//! ## Table of Contents
//!
//! - [Requests](#requests)
//!     - [Announce](#announce)
//!     - [Scrape](#scrape)
//! - [Versioning](#versioning)
//! - [Links](#links)
//!
//! ## Requests
//!
//! ### Announce
//!
//! `Announce` requests are used to announce the presence of a peer to the
//! tracker. The tracker responds with a list of peers that are also downloading
//! the same torrent. A "swarm" is a group of peers that are downloading the
//! same torrent.
//!
//! `Announce` responses are encoded in [bencoded](https://en.wikipedia.org/wiki/Bencode)
//! format.
//!
//! There are two types of `Announce` responses: `compact` and `non-compact`. In
//! a compact response, the peers are encoded in a single string. In a
//! non-compact response, the peers are encoded in a list of dictionaries. The
//! compact response is more efficient than the non-compact response and it does
//! not contain the peer's IDs.
//!
//! **Query parameters**
//!
//! > **NOTICE**: you can click on the parameter name to see a full description
//! > after extracting and parsing the parameter from the URL query component.
//!
//! Parameter | Type | Description | Required |  Default | Example
//! ---|---|---|---|---|---
//! [`info_hash`](crate::servers::http::v1::requests::announce::Announce::info_hash) | percent encoded of 20-byte array | The `Info Hash` of the torrent. | Yes | No | `%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00`
//! `peer_addr` | string |The IP address of the peer. | No | No | `2.137.87.41`
//! [`downloaded`](crate::servers::http::v1::requests::announce::Announce::downloaded) | positive integer |The number of bytes downloaded by the peer. | No | `0` | `0`
//! [`uploaded`](crate::servers::http::v1::requests::announce::Announce::uploaded) | positive integer | The number of bytes uploaded by the peer. | No | `0` | `0`
//! [`peer_id`](crate::servers::http::v1::requests::announce::Announce::peer_id) | percent encoded of 20-byte array  | The ID of the peer. | Yes | No | `-qB00000000000000001`
//! [`port`](crate::servers::http::v1::requests::announce::Announce::port) | positive integer | The port used by the peer. | Yes | No | `17548`
//! [`left`](crate::servers::http::v1::requests::announce::Announce::left) | positive integer | The number of bytes pending to download. | No | `0` | `0`
//! [`event`](crate::servers::http::v1::requests::announce::Announce::event) | positive integer | The event that triggered the `Announce` request: `started`, `completed`, `stopped` | No | `None` | `completed`
//! [`compact`](crate::servers::http::v1::requests::announce::Announce::compact) | `0` or `1` | Whether the tracker should return a compact peer list. | No | `None` | `0`
//! `numwant` | positive integer | **Not implemented**. The maximum number of peers you want in the reply. | No | `50` | `50`
//!
//! Refer to the [`Announce`](crate::servers::http::v1::requests::announce::Announce)
//! request for more information about the parameters.
//!
//! > **NOTICE**: the [BEP 03](https://www.bittorrent.org/beps/bep_0003.html)
//! > defines only the `ip` and `event` parameters as optional. However, the
//! > tracker assigns default values to the optional parameters if they are not
//! > provided.
//!
//! > **NOTICE**: the `peer_addr` parameter is not part of the original
//! > specification. But the peer IP was added in the
//! > [UDP Tracker protocol](https://www.bittorrent.org/beps/bep_0015.html). It is
//! > used to provide the peer's IP address to the tracker, but it is ignored by
//! > the tracker. The tracker uses the IP address of the peer that sent the
//! > request or the right-most-ip in the `X-Forwarded-For` header if the tracker
//! > is behind a reverse proxy.
//!
//! > **NOTICE**: the maximum number of peers that the tracker can return is
//! > `74`. Defined with a hardcoded const [`TORRENT_PEERS_LIMIT`](torrust_tracker_configuration::TORRENT_PEERS_LIMIT).
//! > Refer to [issue 262](https://github.com/torrust/torrust-tracker/issues/262)
//! > for more information about this limitation.
//!
//! > **NOTICE**: the `info_hash` parameter is NOT a `URL` encoded string param.
//! > It is percent encode of the raw `info_hash` bytes (40 bytes). URL `GET` params
//! > can contain any bytes, not only well-formed UTF-8. The `info_hash` is a
//! > 20-byte SHA1. Check the [`percent_encoding`]
//! > module to know more about the encoding.
//!
//! > **NOTICE**: the `peer_id` parameter is NOT a `URL` encoded string param.
//! > It is percent encode of the raw peer ID bytes (20 bytes). URL `GET` params
//! > can contain any bytes, not only well-formed UTF-8. The `info_hash` is a
//! > 20-byte SHA1. Check the [`percent_encoding`]
//! > module to know more about the encoding.
//!
//! > **NOTICE**: by default, the tracker returns the non-compact peer list when
//! > no `compact` parameter is provided or is empty. The
//! > [BEP 23](https://www.bittorrent.org/beps/bep_0023.html) suggests to do the
//! > opposite. The tracker should return the compact peer list by default and
//! > return the non-compact peer list if the `compact` parameter is `0`.
//!
//! **Sample announce URL**
//!
//! A sample `GET` `announce` request:
//!
//! <http://0.0.0.0:7070/announce?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00&peer_addr=2.137.87.41&downloaded=0&uploaded=0&peer_id=-qB00000000000000001&port=17548&left=0&event=completed&compact=0>
//!
//! **Sample non-compact response**
//!
//! In [bencoded](https://en.wikipedia.org/wiki/Bencode) format:
//!
//! ```text
//! d8:completei333e10:incompletei444e8:intervali111e12:min intervali222e5:peersld2:ip15:105.105.105.1057:peer id20:-qB000000000000000014:porti28784eed2:ip39:6969:6969:6969:6969:6969:6969:6969:69697:peer id20:-qB000000000000000024:porti28784eeee
//! ```
//!
//! And represented as a json:
//!
//! ```json
//! {
//!     "complete": 333,
//!     "incomplete": 444,
//!     "interval": 111,
//!     "min interval": 222,
//!     "peers": [
//!        {
//!           "ip": "105.105.105.105",
//!           "peer id": "-qB00000000000000001",
//!           "port": 28784
//!        },
//!        {
//!           "ip": "6969:6969:6969:6969:6969:6969:6969:6969",
//!           "peer id": "-qB00000000000000002",
//!           "port": 28784
//!        }
//!     ]
//! }
//! ```
//!
//! If you save the response as a file and you open it with a program that can
//! handle binary data you would see:
//!
//! ```text
//! 00000000: 6438 3a63 6f6d 706c 6574 6569 3333 3365  d8:completei333e
//! 00000010: 3130 3a69 6e63 6f6d 706c 6574 6569 3434  10:incompletei44
//! 00000020: 3465 383a 696e 7465 7276 616c 6931 3131  4e8:intervali111
//! 00000030: 6531 323a 6d69 6e20 696e 7465 7276 616c  e12:min interval
//! 00000040: 6932 3232 6535 3a70 6565 7273 6c64 323a  i222e5:peersld2:
//! 00000050: 6970 3135 3a31 3035 2e31 3035 2e31 3035  ip15:105.105.105
//! 00000060: 2e31 3035 373a 7065 6572 2069 6432 303a  .1057:peer id20:
//! 00000070: 2d71 4230 3030 3030 3030 3030 3030 3030  -qB0000000000000
//! 00000080: 3030 3031 343a 706f 7274 6932 3837 3834  00014:porti28784
//! 00000090: 6565 6432 3a69 7033 393a 3639 3639 3a36  eed2:ip39:6969:6
//! 000000a0: 3936 393a 3639 3639 3a36 3936 393a 3639  969:6969:6969:69
//! 000000b0: 3639 3a36 3936 393a 3639 3639 3a36 3936  69:6969:6969:696
//! 000000c0: 3937 3a70 6565 7220 6964 3230 3a2d 7142  97:peer id20:-qB
//! 000000d0: 3030 3030 3030 3030 3030 3030 3030 3030  0000000000000000
//! 000000e0: 3234 3a70 6f72 7469 3238 3738 3465 6565  24:porti28784eee
//! 000000f0: 65                                       e
//! ```
//!
//! Refer to the [`Normal`](crate::servers::http::v1::responses::announce::Normal), i.e. `Non-Compact`
//! response for more information about the response.
//!
//! **Sample compact response**
//!
//! In [bencoded](https://en.wikipedia.org/wiki/Bencode) format:
//!
//! ```text
//! d8:completei333e10:incompletei444e8:intervali111e12:min intervali222e5:peers6:iiiipp6:peers618:iiiiiiiiiiiiiiiippe
//! ```
//!
//! And represented as a json:
//!
//! ```json
//! {
//!     "complete": 333,
//!     "incomplete": 444,
//!     "interval": 111,
//!     "min interval": 222,
//!     "peers": "iiiipp",
//!     "peers6": "iiiiiiiiiiiiiiiipp"
//! }
//! ```
//!
//! If you save the response as a file and you open it with a program that can
//! handle binary data you would see:
//!
//! ```text
//! 0000000: 6438 3a63 6f6d 706c 6574 6569 3333 3365  d8:completei333e
//! 0000010: 3130 3a69 6e63 6f6d 706c 6574 6569 3434  10:incompletei44
//! 0000020: 3465 383a 696e 7465 7276 616c 6931 3131  4e8:intervali111
//! 0000030: 6531 323a 6d69 6e20 696e 7465 7276 616c  e12:min interval
//! 0000040: 6932 3232 6535 3a70 6565 7273 363a 6969  i222e5:peers6:ii
//! 0000050: 6969 7070 363a 7065 6572 7336 3138 3a69  iipp6:peers618:i
//! 0000060: 6969 6969 6969 6969 6969 6969 6969 6970  iiiiiiiiiiiiiiip
//! 0000070: 7065                                     pe
//! ```
//!
//! Refer to the [`Compact`](crate::servers::http::v1::responses::announce::Compact)
//! response for more information about the response.
//!
//! **Protocol**
//!
//! Original specification in [BEP 03. The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html).
//!
//! If you want to know more about the `announce` request:
//!
//! - [BEP 03. The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
//! - [BEP 23. Tracker Returns Compact Peer Lists](https://www.bittorrent.org/beps/bep_0023.html)
//! - [Vuze announce docs](https://wiki.vuze.com/w/Announce)
//! - [wiki.theory.org - Announce](https://wiki.theory.org/BitTorrent_Tracker_Protocol#Basic_Tracker_Announce_Request)
//!
//! ### Scrape
//!
//! The `scrape` request allows a peer to get [swarm metadata](torrust_tracker_primitives::swarm_metadata::SwarmMetadata)
//! for multiple torrents at the same time.
//!
//! The response contains the [swarm metadata](torrust_tracker_primitives::swarm_metadata::SwarmMetadata)
//! for that torrent:
//!
//! - [complete](torrust_tracker_primitives::swarm_metadata::SwarmMetadata::complete)
//! - [downloaded](torrust_tracker_primitives::swarm_metadata::SwarmMetadata::downloaded)
//! - [incomplete](torrust_tracker_primitives::swarm_metadata::SwarmMetadata::incomplete)
//!
//! **Query parameters**
//!
//! Parameter | Type | Description | Required |  Default | Example
//! ---|---|---|---|---|---
//! [`info_hash`](crate::servers::http::v1::requests::scrape::Scrape::info_hashes) | percent encoded of 20-byte array | The `Info Hash` of the torrent. | Yes | No | `%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00`
//!
//! > **NOTICE**: you can scrape multiple torrents at the same time by passing
//! > multiple `info_hash` parameters.
//!
//! Refer to the [`Scrape`](crate::servers::http::v1::requests::scrape::Scrape)
//! request for more information about the parameters.
//!
//! **Sample scrape URL**
//!
//! A sample `scrape` request for only one torrent:
//!
//! <http://0.0.0.0:7070/scrape?info_hash=%81%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00>
//!
//! In order to scrape multiple torrents at the same time you can pass multiple
//! `info_hash` parameters: `info_hash=%81%00%0...00%00%00&info_hash=%82%00%0...00%00%00`
//!
//! > **NOTICE**: the maximum number of torrents you can scrape at the same time
//! > is `74`. Defined with a hardcoded const [`MAX_SCRAPE_TORRENTS`](crate::shared::bit_torrent::common::MAX_SCRAPE_TORRENTS).
//!
//! **Sample response**
//!
//! The `scrape` response is a [bencoded](https://en.wikipedia.org/wiki/Bencode)
//! byte array like the following:
//!
//! ```text
//! d5:filesd20:iiiiiiiiiiiiiiiiiiiid8:completei1e10:downloadedi2e10:incompletei3eeee
//! ```
//!
//! And represented as a json:
//!
//! ```json
//! {
//!     "files": {
//!        "iiiiiiiiiiiiiiiiiiii": {
//!           "complete": 1,
//!           "downloaded": 2,
//!           "incomplete": 3
//!        }
//!     }
//! }
//! ```
//!
//! Where the `files` key contains a dictionary of dictionaries. The first
//! dictionary key is the `info_hash` of the torrent (`iiiiiiiiiiiiiiiiiiii` in
//! the example). The second level dictionary contains the
//! [swarm metadata](torrust_tracker_primitives::swarm_metadata::SwarmMetadata) for that torrent.
//!
//! If you save the response as a file and you open it with a program that
//! can handle binary data you would see:
//!
//! ```text
//! 00000000: 6435 3a66 696c 6573 6432 303a 6969 6969  d5:filesd20:iiii
//! 00000010: 6969 6969 6969 6969 6969 6969 6969 6969  iiiiiiiiiiiiiiii
//! 00000020: 6438 3a63 6f6d 706c 6574 6569 3165 3130  d8:completei1e10
//! 00000030: 3a64 6f77 6e6c 6f61 6465 6469 3265 3130  :downloadedi2e10
//! 00000040: 3a69 6e63 6f6d 706c 6574 6569 3365 6565  :incompletei3eee
//! 00000050: 65                                       e
//! ```
//!
//! **Protocol**
//!
//! If you want to know more about the `scrape` request:
//!
//! - [BEP 48. Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html)
//! - [Vuze scrape docs](https://wiki.vuze.com/w/Scrape)
//!
//! ## Versioning
//!
//! Right not there is only version `v1`. The HTTP tracker implements BEPS:
//!
//! - [BEP 03. The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
//! - [BEP 07. IPv6 Tracker Extension](https://www.bittorrent.org/beps/bep_0007.html)
//! - [BEP 23. Tracker Returns Compact Peer Lists](https://www.bittorrent.org/beps/bep_0023.html)
//! - [BEP 48. Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html)
//!
//! In the future there could be a `v2` that implements new BEPS with breaking
//! changes.
//!
//! ## Links
//!
//! - [Bencode](https://en.wikipedia.org/wiki/Bencode).
//! - [Bencode to Json Online converter](https://chocobo1.github.io/bencode_online).
use serde::{Deserialize, Serialize};

pub mod server;
pub mod v1;

pub const HTTP_TRACKER_LOG_TARGET: &str = "HTTP TRACKER";

/// The version of the HTTP tracker.
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
pub enum Version {
    /// The `v1` version of the HTTP tracker.
    V1,
}
