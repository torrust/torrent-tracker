//! This module contains functions for percent decoding infohashes and peer IDs.
//!
//! Percent encoding is an encoding format used to encode arbitrary data in a
//! format that is safe to use in URLs. It is used by the HTTP tracker protocol
//! to encode infohashes and peer ids in the URLs of requests.
//!
//! `BitTorrent` infohashes and peer ids are percent encoded like any other
//! arbitrary URL parameter. But they are encoded from binary data (byte arrays)
//! which may not be valid UTF-8. That makes hard to use the `percent_encoding`
//! crate to decode them because all of them expect a well-formed UTF-8 string.
//! However, percent encoding is not limited to UTF-8 strings.
//!
//! More information about "Percent Encoding" can be found here:
//!
//! - <https://datatracker.ietf.org/doc/html/rfc3986#section-2.1>
//! - <https://en.wikipedia.org/wiki/URL_encoding>
//! - <https://developer.mozilla.org/en-US/docs/Glossary/percent-encoding>
use crate::core::peer::{self, IdConversionError};
use crate::shared::bit_torrent::info_hash::{ConversionError, InfoHash};

/// Percent decodes a percent encoded infohash. Internally an
/// [`InfoHash`] is a 20-byte array.
///
/// For example, given the infohash `3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0`,
/// it's percent encoded representation is `%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0`.
///
/// ```rust
/// use std::str::FromStr;
/// use torrust_tracker::servers::http::percent_encoding::percent_decode_info_hash;
/// use torrust_tracker::shared::bit_torrent::info_hash::InfoHash;
/// use torrust_tracker::core::peer;
///
/// let encoded_infohash = "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0";
///
/// let info_hash = percent_decode_info_hash(encoded_infohash).unwrap();
///
/// assert_eq!(
///     info_hash,
///     InfoHash::from_str("3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0").unwrap()
/// );
/// ```
///
/// # Errors
///
/// Will return `Err` if the decoded bytes do not represent a valid
/// [`InfoHash`].
pub fn percent_decode_info_hash(raw_info_hash: &str) -> Result<InfoHash, ConversionError> {
    let bytes = percent_encoding::percent_decode_str(raw_info_hash).collect::<Vec<u8>>();
    InfoHash::try_from(bytes)
}

/// Percent decodes a percent encoded peer id. Internally a peer [`Id`](crate::core::peer::Id)
/// is a 20-byte array.
///
/// For example, given the peer id `*b"-qB00000000000000000"`,
/// it's percent encoded representation is `%2DqB00000000000000000`.
///
/// ```rust
/// use std::str::FromStr;
/// use torrust_tracker::servers::http::percent_encoding::percent_decode_peer_id;
/// use torrust_tracker::shared::bit_torrent::info_hash::InfoHash;
/// use torrust_tracker::core::peer;
///
/// let encoded_peer_id = "%2DqB00000000000000000";
///
/// let peer_id = percent_decode_peer_id(encoded_peer_id).unwrap();
///
/// assert_eq!(peer_id, peer::Id(*b"-qB00000000000000000"));
/// ```
///
/// # Errors
///
/// Will return `Err` if if the decoded bytes do not represent a valid [`peer::Id`].
pub fn percent_decode_peer_id(raw_peer_id: &str) -> Result<peer::Id, IdConversionError> {
    let bytes = percent_encoding::percent_decode_str(raw_peer_id).collect::<Vec<u8>>();
    peer::Id::try_from(bytes)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::core::peer;
    use crate::servers::http::percent_encoding::{percent_decode_info_hash, percent_decode_peer_id};
    use crate::shared::bit_torrent::info_hash::InfoHash;

    #[test]
    fn it_should_decode_a_percent_encoded_info_hash() {
        let encoded_infohash = "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0";

        let info_hash = percent_decode_info_hash(encoded_infohash).unwrap();

        assert_eq!(
            info_hash,
            InfoHash::from_str("3b245504cf5f11bbdbe1201cea6a6bf45aee1bc0").unwrap()
        );
    }

    #[test]
    fn it_should_fail_decoding_an_invalid_percent_encoded_info_hash() {
        let invalid_encoded_infohash = "invalid percent-encoded infohash";

        let info_hash = percent_decode_info_hash(invalid_encoded_infohash);

        assert!(info_hash.is_err());
    }

    #[test]
    fn it_should_decode_a_percent_encoded_peer_id() {
        let encoded_peer_id = "%2DqB00000000000000000";

        let peer_id = percent_decode_peer_id(encoded_peer_id).unwrap();

        assert_eq!(peer_id, peer::Id(*b"-qB00000000000000000"));
    }

    #[test]
    fn it_should_fail_decoding_an_invalid_percent_encoded_peer_id() {
        let invalid_encoded_peer_id = "invalid percent-encoded peer id";

        let peer_id = percent_decode_peer_id(invalid_encoded_peer_id);

        assert!(peer_id.is_err());
    }
}
