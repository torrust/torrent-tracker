//! Common code for the `BitTorrent` protocol.
//!
//! # Glossary
//!
//! - [Announce](#announce)
//! - [Info Hash](#info-hash)
//! - [Leecher](#leechers)
//! - [Peer ID](#peer-id)
//! - [Peer List](#peer-list)
//! - [Peer](#peer)
//! - [Scrape](#scrape)
//! - [Seeders](#seeders)
//! - [Swarm](#swarm)
//! - [Tracker](#tracker)
//!
//! Glossary of `BitTorrent` terms.
//!
//! # Announce
//!
//! A request to the tracker to announce the presence of a peer.
//!
//! ## Info Hash
//!
//! A unique identifier for a torrent.
//!
//! ## Leecher
//!
//! Peers that are only downloading data.
//!
//! ## Peer ID
//!
//! A unique identifier for a peer.
//!
//! ## Peer List
//!
//! A list of peers that are downloading a torrent.
//!
//! ## Peer
//!
//! A client that is downloading or uploading a torrent.
//!
//! ## Scrape
//!
//! A request to the tracker to get information about a torrent.
//!
//! ## Seeder
//!
//! Peers that are only uploading data.
//!
//! ## Swarm
//!
//! A group of peers that are downloading the same torrent.
//!
//! ## Tracker
//!
//! A server that keeps track of peers that are downloading a torrent.
//!
//! # Links
//!
//! Description | Link
//! ---|---
//! `BitTorrent.org`. A forum for developers to exchange ideas about the direction of the `BitTorrent` protocol | <https://www.bittorrent.org>
//! Wikipedia entry for Glossary of `BitTorrent` term | <https://en.wikipedia.org/wiki/Glossary_of_BitTorrent_terms>
//! `BitTorrent` Specification Wiki | <https://wiki.theory.org/BitTorrentSpecification>
//! Vuze Wiki. A `BitTorrent` client implementation | <https://wiki.vuze.com>
//! `libtorrent`. Complete C++ bittorrent implementation| <https://www.rasterbar.com/products/libtorrent/index.html>
//! UDP Tracker Protocol docs by `libtorrent` | <https://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html>
//! Percent Encoding spec | <https://datatracker.ietf.org/doc/html/rfc3986#section-2.1>
//!Bencode & bdecode in your browser | <https://github.com/Chocobo1/bencode_online>
pub mod common;
pub mod tracker;
