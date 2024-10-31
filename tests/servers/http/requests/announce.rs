use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use aquatic_udp_protocol::PeerId;
use bittorrent_primitives::info_hash::InfoHash;
use serde_repr::Serialize_repr;

use crate::servers::http::{percent_encode_byte_array, ByteArray20};

pub struct Query {
    pub info_hash: ByteArray20,
    pub peer_addr: IpAddr,
    pub downloaded: BaseTenASCII,
    pub uploaded: BaseTenASCII,
    pub peer_id: ByteArray20,
    pub port: PortNumber,
    pub left: BaseTenASCII,
    pub event: Option<Event>,
    pub compact: Option<Compact>,
    pub numwant: Option<u32>,
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.build())
    }
}

/// HTTP Tracker Announce Request:
///
/// <https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol>
///
/// Some parameters in the specification are not implemented in this tracker yet.
impl Query {
    /// It builds the URL query component for the announce request.
    ///
    /// This custom URL query params encoding is needed because `reqwest` does not allow
    /// bytes arrays in query parameters. More info on this issue:
    ///
    /// <https://github.com/seanmonstar/reqwest/issues/1613>
    pub fn build(&self) -> String {
        self.params().to_string()
    }

    pub fn params(&self) -> QueryParams {
        QueryParams::from(self)
    }
}

pub type BaseTenASCII = u64;
pub type PortNumber = u16;

pub enum Event {
    //Started,
    //Stopped,
    Completed,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            //Event::Started => write!(f, "started"),
            //Event::Stopped => write!(f, "stopped"),
            Event::Completed => write!(f, "completed"),
        }
    }
}

#[derive(Serialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum Compact {
    Accepted = 1,
    NotAccepted = 0,
}

impl fmt::Display for Compact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Compact::Accepted => write!(f, "1"),
            Compact::NotAccepted => write!(f, "0"),
        }
    }
}

pub struct QueryBuilder {
    announce_query: Query,
}

impl QueryBuilder {
    pub fn default() -> QueryBuilder {
        let default_announce_query = Query {
            info_hash: InfoHash::from_str("9c38422213e30bff212b30c360d26f9a02136422").unwrap().0,
            peer_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 88)),
            downloaded: 0,
            uploaded: 0,
            peer_id: PeerId(*b"-qB00000000000000001").0,
            port: 17548,
            left: 0,
            event: Some(Event::Completed),
            compact: Some(Compact::NotAccepted),
            numwant: None,
        };
        Self {
            announce_query: default_announce_query,
        }
    }

    pub fn with_info_hash(mut self, info_hash: &InfoHash) -> Self {
        self.announce_query.info_hash = info_hash.0;
        self
    }

    pub fn with_peer_id(mut self, peer_id: &PeerId) -> Self {
        self.announce_query.peer_id = peer_id.0;
        self
    }

    pub fn with_compact(mut self, compact: Compact) -> Self {
        self.announce_query.compact = Some(compact);
        self
    }

    pub fn with_peer_addr(mut self, peer_addr: &IpAddr) -> Self {
        self.announce_query.peer_addr = *peer_addr;
        self
    }

    pub fn without_compact(mut self) -> Self {
        self.announce_query.compact = None;
        self
    }

    pub fn query(self) -> Query {
        self.announce_query
    }
}

/// It contains all the GET parameters that can be used in a HTTP Announce request.
///
/// Sample Announce URL with all the GET parameters (mandatory and optional):
///
/// ```text
/// http://127.0.0.1:7070/announce?
///     info_hash=%9C8B%22%13%E3%0B%FF%21%2B0%C3%60%D2o%9A%02%13d%22 (mandatory)
///     peer_addr=192.168.1.88
///     downloaded=0
///     uploaded=0
///     peer_id=%2DqB00000000000000000 (mandatory)
///     port=17548 (mandatory)
///     left=0
///     event=completed
///     compact=0
///     numwant=50
/// ```
#[derive(Debug)]
pub struct QueryParams {
    pub info_hash: Option<String>,
    pub peer_addr: Option<String>,
    pub downloaded: Option<String>,
    pub uploaded: Option<String>,
    pub peer_id: Option<String>,
    pub port: Option<String>,
    pub left: Option<String>,
    pub event: Option<String>,
    pub compact: Option<String>,
    pub numwant: Option<String>,
}

impl std::fmt::Display for QueryParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut params = vec![];

        if let Some(info_hash) = &self.info_hash {
            params.push(("info_hash", info_hash));
        }
        if let Some(peer_addr) = &self.peer_addr {
            params.push(("peer_addr", peer_addr));
        }
        if let Some(downloaded) = &self.downloaded {
            params.push(("downloaded", downloaded));
        }
        if let Some(uploaded) = &self.uploaded {
            params.push(("uploaded", uploaded));
        }
        if let Some(peer_id) = &self.peer_id {
            params.push(("peer_id", peer_id));
        }
        if let Some(port) = &self.port {
            params.push(("port", port));
        }
        if let Some(left) = &self.left {
            params.push(("left", left));
        }
        if let Some(event) = &self.event {
            params.push(("event", event));
        }
        if let Some(compact) = &self.compact {
            params.push(("compact", compact));
        }
        if let Some(numwant) = &self.numwant {
            params.push(("numwant", numwant));
        }

        let query = params
            .iter()
            .map(|param| format!("{}={}", param.0, param.1))
            .collect::<Vec<String>>()
            .join("&");

        write!(f, "{query}")
    }
}

impl QueryParams {
    pub fn from(announce_query: &Query) -> Self {
        let event = announce_query.event.as_ref().map(std::string::ToString::to_string);
        let compact = announce_query.compact.as_ref().map(std::string::ToString::to_string);
        let numwant = announce_query.numwant.map(|numwant| numwant.to_string());

        Self {
            info_hash: Some(percent_encode_byte_array(&announce_query.info_hash)),
            peer_addr: Some(announce_query.peer_addr.to_string()),
            downloaded: Some(announce_query.downloaded.to_string()),
            uploaded: Some(announce_query.uploaded.to_string()),
            peer_id: Some(percent_encode_byte_array(&announce_query.peer_id)),
            port: Some(announce_query.port.to_string()),
            left: Some(announce_query.left.to_string()),
            event,
            compact,
            numwant,
        }
    }

    pub fn remove_optional_params(&mut self) {
        // todo: make them optional with the Option<...> in the AnnounceQuery struct
        // if they are really optional. So that we can crete a minimal AnnounceQuery
        // instead of removing the optional params afterwards.
        //
        // The original specification on:
        // <https://www.bittorrent.org/beps/bep_0003.html>
        // says only `ip` and `event` are optional.
        //
        // On <https://wiki.theory.org/BitTorrentSpecification#Tracker_Request_Parameters>
        // says only `ip`, `numwant`, `key` and `trackerid` are optional.
        //
        // but the server is responding if all these params are not included.
        self.peer_addr = None;
        self.downloaded = None;
        self.uploaded = None;
        self.left = None;
        self.event = None;
        self.compact = None;
        self.numwant = None;
    }

    pub fn set(&mut self, param_name: &str, param_value: &str) {
        match param_name {
            "info_hash" => self.info_hash = Some(param_value.to_string()),
            "peer_addr" => self.peer_addr = Some(param_value.to_string()),
            "downloaded" => self.downloaded = Some(param_value.to_string()),
            "uploaded" => self.uploaded = Some(param_value.to_string()),
            "peer_id" => self.peer_id = Some(param_value.to_string()),
            "port" => self.port = Some(param_value.to_string()),
            "left" => self.left = Some(param_value.to_string()),
            "event" => self.event = Some(param_value.to_string()),
            "compact" => self.compact = Some(param_value.to_string()),
            "numwant" => self.numwant = Some(param_value.to_string()),
            &_ => panic!("Invalid param name for announce query"),
        }
    }
}
