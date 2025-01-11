//! `Announce` request for the HTTP tracker.
//!
//! Data structures and logic for parsing the `announce` request.
use std::fmt;
use std::panic::Location;
use std::str::FromStr;

use aquatic_udp_protocol::{NumberOfBytes, PeerId};
use bittorrent_primitives::info_hash::{self, InfoHash};
use thiserror::Error;
use torrust_tracker_located_error::{Located, LocatedError};
use torrust_tracker_primitives::peer;

use crate::percent_encoding::{percent_decode_info_hash, percent_decode_peer_id};
use crate::v1::query::{ParseQueryError, Query};
use crate::v1::responses;

// Query param names
const INFO_HASH: &str = "info_hash";
const PEER_ID: &str = "peer_id";
const PORT: &str = "port";
const DOWNLOADED: &str = "downloaded";
const UPLOADED: &str = "uploaded";
const LEFT: &str = "left";
const EVENT: &str = "event";
const COMPACT: &str = "compact";
const NUMWANT: &str = "numwant";

/// The `Announce` request. Fields use the domain types after parsing the
/// query params of the request.
///
/// ```text
/// use aquatic_udp_protocol::{NumberOfBytes, PeerId};
/// use torrust_tracker_lib::servers::http::v1::requests::announce::{Announce, Compact, Event};
/// use bittorrent_primitives::info_hash::InfoHash;
///
/// let request = Announce {
///     // Mandatory params
///     info_hash: "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap(),
///     peer_id: PeerId(*b"-qB00000000000000001"),
///     port: 17548,
///     // Optional params
///     downloaded: Some(NumberOfBytes::new(1)),
///     uploaded: Some(NumberOfBytes::new(1)),
///     left: Some(NumberOfBytes::new(1)),
///     event: Some(Event::Started),
///     compact: Some(Compact::NotAccepted),
///     numwant: Some(50)
/// };
/// ```
///
/// > **NOTICE**: The [BEP 03. The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
/// > specifies that only the peer `IP` and `event`are optional. However, the
/// > tracker defines default values for some of the mandatory params.
///
/// > **NOTICE**: The struct does not contain the `IP` of the peer. It's not
/// > mandatory and it's not used by the tracker. The `IP` is obtained from the
/// > request itself.
#[derive(Debug, PartialEq)]
pub struct Announce {
    // Mandatory params
    /// The `InfoHash` of the torrent.
    pub info_hash: InfoHash,

    /// The `PeerId` of the peer.
    pub peer_id: PeerId,

    /// The port of the peer.
    pub port: u16,

    // Optional params
    /// The number of bytes downloaded by the peer.
    pub downloaded: Option<NumberOfBytes>,

    /// The number of bytes uploaded by the peer.
    pub uploaded: Option<NumberOfBytes>,

    /// The number of bytes left to download by the peer.
    pub left: Option<NumberOfBytes>,

    /// The event that the peer is reporting. It can be `Started`, `Stopped` or
    /// `Completed`.
    pub event: Option<Event>,

    /// Whether the response should be in compact mode or not.
    pub compact: Option<Compact>,

    /// Number of peers that the client would receive from the tracker. The
    /// value is permitted to be zero.
    pub numwant: Option<u32>,
}

/// Errors that can occur when parsing the `Announce` request.
///
/// The `info_hash` and `peer_id` query params are special because they contain
/// binary data. The `info_hash` is a 20-byte SHA1 hash and the `peer_id` is a
/// 20-byte array.
#[derive(Error, Debug)]
pub enum ParseAnnounceQueryError {
    /// A mandatory param is missing.
    #[error("missing query params for announce request in {location}")]
    MissingParams { location: &'static Location<'static> },
    #[error("missing param {param_name} in {location}")]
    MissingParam {
        location: &'static Location<'static>,
        param_name: String,
    },
    /// The param cannot be parsed into the domain type.
    #[error("invalid param value {param_value} for {param_name} in {location}")]
    InvalidParam {
        param_name: String,
        param_value: String,
        location: &'static Location<'static>,
    },
    /// The param value is out of range.
    #[error("param value overflow {param_value} for {param_name} in {location}")]
    NumberOfBytesOverflow {
        param_name: String,
        param_value: String,
        location: &'static Location<'static>,
    },
    /// The `info_hash` is invalid.
    #[error("invalid param value {param_value} for {param_name} in {source}")]
    InvalidInfoHashParam {
        param_name: String,
        param_value: String,
        source: LocatedError<'static, info_hash::ConversionError>,
    },
    /// The `peer_id` is invalid.
    #[error("invalid param value {param_value} for {param_name} in {source}")]
    InvalidPeerIdParam {
        param_name: String,
        param_value: String,
        source: LocatedError<'static, peer::IdConversionError>,
    },
}

/// The event that the peer is reporting: `started`, `completed` or `stopped`.
///
/// If the event is not present or empty that means that the peer is just
/// updating its status. It's one of the announcements done at regular intervals.
///
/// Refer to [BEP 03. The `BitTorrent Protocol` Specification](https://www.bittorrent.org/beps/bep_0003.html)
/// for more information.
#[derive(PartialEq, Debug)]
pub enum Event {
    /// Event sent when a download first begins.
    Started,
    /// Event sent when the downloader cease downloading.
    Stopped,
    /// Event sent when the download is complete.
    /// No `completed` is sent if the file was complete when started
    Completed,
}

impl FromStr for Event {
    type Err = ParseAnnounceQueryError;

    fn from_str(raw_param: &str) -> Result<Self, Self::Err> {
        match raw_param {
            "started" => Ok(Self::Started),
            "stopped" => Ok(Self::Stopped),
            "completed" => Ok(Self::Completed),
            _ => Err(ParseAnnounceQueryError::InvalidParam {
                param_name: EVENT.to_owned(),
                param_value: raw_param.to_owned(),
                location: Location::caller(),
            }),
        }
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Started => write!(f, "started"),
            Event::Stopped => write!(f, "stopped"),
            Event::Completed => write!(f, "completed"),
        }
    }
}

/// Whether the `announce` response should be in compact mode or not.
///
/// Depending on the value of this param, the tracker will return a different
/// response:
///
/// - [`Normal`](crate::servers::http::v1::responses::announce::Normal), i.e. a `non-compact` response.
/// - [`Compact`](crate::servers::http::v1::responses::announce::Compact) response.
///
/// Refer to [BEP 23. Tracker Returns Compact Peer Lists](https://www.bittorrent.org/beps/bep_0023.html)
#[derive(PartialEq, Debug)]
pub enum Compact {
    /// The client advises the tracker that the client prefers compact format.
    Accepted = 1,
    /// The client advises the tracker that is prefers the original format
    /// described in [BEP 03. The BitTorrent Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)
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

impl FromStr for Compact {
    type Err = ParseAnnounceQueryError;

    fn from_str(raw_param: &str) -> Result<Self, Self::Err> {
        match raw_param {
            "1" => Ok(Self::Accepted),
            "0" => Ok(Self::NotAccepted),
            _ => Err(ParseAnnounceQueryError::InvalidParam {
                param_name: COMPACT.to_owned(),
                param_value: raw_param.to_owned(),
                location: Location::caller(),
            }),
        }
    }
}

impl From<ParseQueryError> for responses::error::Error {
    fn from(err: ParseQueryError) -> Self {
        responses::error::Error {
            failure_reason: format!("Bad request. Cannot parse query params: {err}"),
        }
    }
}

impl From<ParseAnnounceQueryError> for responses::error::Error {
    fn from(err: ParseAnnounceQueryError) -> Self {
        responses::error::Error {
            failure_reason: format!("Bad request. Cannot parse query params for announce request: {err}"),
        }
    }
}

impl TryFrom<Query> for Announce {
    type Error = ParseAnnounceQueryError;

    fn try_from(query: Query) -> Result<Self, Self::Error> {
        Ok(Self {
            info_hash: extract_info_hash(&query)?,
            peer_id: extract_peer_id(&query)?,
            port: extract_port(&query)?,
            downloaded: extract_downloaded(&query)?,
            uploaded: extract_uploaded(&query)?,
            left: extract_left(&query)?,
            event: extract_event(&query)?,
            compact: extract_compact(&query)?,
            numwant: extract_numwant(&query)?,
        })
    }
}

// Mandatory params

fn extract_info_hash(query: &Query) -> Result<InfoHash, ParseAnnounceQueryError> {
    match query.get_param(INFO_HASH) {
        Some(raw_param) => {
            Ok(
                percent_decode_info_hash(&raw_param).map_err(|err| ParseAnnounceQueryError::InvalidInfoHashParam {
                    param_name: INFO_HASH.to_owned(),
                    param_value: raw_param.clone(),
                    source: Located(err).into(),
                })?,
            )
        }
        None => Err(ParseAnnounceQueryError::MissingParam {
            location: Location::caller(),
            param_name: INFO_HASH.to_owned(),
        }),
    }
}

fn extract_peer_id(query: &Query) -> Result<PeerId, ParseAnnounceQueryError> {
    match query.get_param(PEER_ID) {
        Some(raw_param) => Ok(
            percent_decode_peer_id(&raw_param).map_err(|err| ParseAnnounceQueryError::InvalidPeerIdParam {
                param_name: PEER_ID.to_owned(),
                param_value: raw_param.clone(),
                source: Located(err).into(),
            })?,
        ),
        None => Err(ParseAnnounceQueryError::MissingParam {
            location: Location::caller(),
            param_name: PEER_ID.to_owned(),
        }),
    }
}

fn extract_port(query: &Query) -> Result<u16, ParseAnnounceQueryError> {
    match query.get_param(PORT) {
        Some(raw_param) => Ok(u16::from_str(&raw_param).map_err(|_e| ParseAnnounceQueryError::InvalidParam {
            param_name: PORT.to_owned(),
            param_value: raw_param.clone(),
            location: Location::caller(),
        })?),
        None => Err(ParseAnnounceQueryError::MissingParam {
            location: Location::caller(),
            param_name: PORT.to_owned(),
        }),
    }
}

// Optional params

fn extract_downloaded(query: &Query) -> Result<Option<NumberOfBytes>, ParseAnnounceQueryError> {
    extract_number_of_bytes_from_param(DOWNLOADED, query)
}

fn extract_uploaded(query: &Query) -> Result<Option<NumberOfBytes>, ParseAnnounceQueryError> {
    extract_number_of_bytes_from_param(UPLOADED, query)
}

fn extract_left(query: &Query) -> Result<Option<NumberOfBytes>, ParseAnnounceQueryError> {
    extract_number_of_bytes_from_param(LEFT, query)
}

fn extract_number_of_bytes_from_param(param_name: &str, query: &Query) -> Result<Option<NumberOfBytes>, ParseAnnounceQueryError> {
    match query.get_param(param_name) {
        Some(raw_param) => {
            let number_of_bytes = u64::from_str(&raw_param).map_err(|_e| ParseAnnounceQueryError::InvalidParam {
                param_name: param_name.to_owned(),
                param_value: raw_param.clone(),
                location: Location::caller(),
            })?;

            let number_of_bytes =
                i64::try_from(number_of_bytes).map_err(|_e| ParseAnnounceQueryError::NumberOfBytesOverflow {
                    param_name: param_name.to_owned(),
                    param_value: raw_param.clone(),
                    location: Location::caller(),
                })?;

            let number_of_bytes = NumberOfBytes::new(number_of_bytes);

            Ok(Some(number_of_bytes))
        }
        None => Ok(None),
    }
}

fn extract_event(query: &Query) -> Result<Option<Event>, ParseAnnounceQueryError> {
    match query.get_param(EVENT) {
        Some(raw_param) => Ok(Some(Event::from_str(&raw_param)?)),
        None => Ok(None),
    }
}

fn extract_compact(query: &Query) -> Result<Option<Compact>, ParseAnnounceQueryError> {
    match query.get_param(COMPACT) {
        Some(raw_param) => Ok(Some(Compact::from_str(&raw_param)?)),
        None => Ok(None),
    }
}

fn extract_numwant(query: &Query) -> Result<Option<u32>, ParseAnnounceQueryError> {
    match query.get_param(NUMWANT) {
        Some(raw_param) => match u32::from_str(&raw_param) {
            Ok(numwant) => Ok(Some(numwant)),
            Err(_) => Err(ParseAnnounceQueryError::InvalidParam {
                param_name: NUMWANT.to_owned(),
                param_value: raw_param.clone(),
                location: Location::caller(),
            }),
        },
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {

    mod announce_request {

        use aquatic_udp_protocol::{NumberOfBytes, PeerId};
        use bittorrent_primitives::info_hash::InfoHash;

        use crate::v1::query::Query;
        use crate::v1::requests::announce::{
            Announce, Compact, Event, COMPACT, DOWNLOADED, EVENT, INFO_HASH, LEFT, NUMWANT, PEER_ID, PORT, UPLOADED,
        };

        #[test]
        fn should_be_instantiated_from_the_url_query_with_only_the_mandatory_params() {
            let raw_query = Query::from(vec![
                (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                (PEER_ID, "-qB00000000000000001"),
                (PORT, "17548"),
            ])
            .to_string();

            let query = raw_query.parse::<Query>().unwrap();

            let announce_request = Announce::try_from(query).unwrap();

            assert_eq!(
                announce_request,
                Announce {
                    info_hash: "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap(),
                    peer_id: PeerId(*b"-qB00000000000000001"),
                    port: 17548,
                    downloaded: None,
                    uploaded: None,
                    left: None,
                    event: None,
                    compact: None,
                    numwant: None,
                }
            );
        }

        #[test]
        fn should_be_instantiated_from_the_url_query_params() {
            let raw_query = Query::from(vec![
                (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                (PEER_ID, "-qB00000000000000001"),
                (PORT, "17548"),
                (DOWNLOADED, "1"),
                (UPLOADED, "2"),
                (LEFT, "3"),
                (EVENT, "started"),
                (COMPACT, "0"),
                (NUMWANT, "50"),
            ])
            .to_string();

            let query = raw_query.parse::<Query>().unwrap();

            let announce_request = Announce::try_from(query).unwrap();

            assert_eq!(
                announce_request,
                Announce {
                    info_hash: "3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0".parse::<InfoHash>().unwrap(),
                    peer_id: PeerId(*b"-qB00000000000000001"),
                    port: 17548,
                    downloaded: Some(NumberOfBytes::new(1)),
                    uploaded: Some(NumberOfBytes::new(2)),
                    left: Some(NumberOfBytes::new(3)),
                    event: Some(Event::Started),
                    compact: Some(Compact::NotAccepted),
                    numwant: Some(50),
                }
            );
        }

        mod when_it_is_instantiated_from_the_url_query_params {

            use crate::v1::query::Query;
            use crate::v1::requests::announce::{
                Announce, COMPACT, DOWNLOADED, EVENT, INFO_HASH, LEFT, NUMWANT, PEER_ID, PORT, UPLOADED,
            };

            #[test]
            fn it_should_fail_if_the_query_does_not_include_all_the_mandatory_params() {
                let raw_query_without_info_hash = "peer_id=-qB00000000000000001&port=17548";

                assert!(Announce::try_from(raw_query_without_info_hash.parse::<Query>().unwrap()).is_err());

                let raw_query_without_peer_id = "info_hash=%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0&port=17548";

                assert!(Announce::try_from(raw_query_without_peer_id.parse::<Query>().unwrap()).is_err());

                let raw_query_without_port =
                    "info_hash=%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0&peer_id=-qB00000000000000001";

                assert!(Announce::try_from(raw_query_without_port.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_info_hash_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "INVALID_INFO_HASH_VALUE"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "17548"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_peer_id_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "INVALID_PEER_ID_VALUE"),
                    (PORT, "17548"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_port_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "INVALID_PORT_VALUE"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_downloaded_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "17548"),
                    (DOWNLOADED, "INVALID_DOWNLOADED_VALUE"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_uploaded_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "17548"),
                    (UPLOADED, "INVALID_UPLOADED_VALUE"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_left_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "17548"),
                    (LEFT, "INVALID_LEFT_VALUE"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_event_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "17548"),
                    (EVENT, "INVALID_EVENT_VALUE"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_compact_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "17548"),
                    (COMPACT, "INVALID_COMPACT_VALUE"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }

            #[test]
            fn it_should_fail_if_the_numwant_param_is_invalid() {
                let raw_query = Query::from(vec![
                    (INFO_HASH, "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"),
                    (PEER_ID, "-qB00000000000000001"),
                    (PORT, "17548"),
                    (NUMWANT, "-1"),
                ])
                .to_string();

                assert!(Announce::try_from(raw_query.parse::<Query>().unwrap()).is_err());
            }
        }
    }
}
