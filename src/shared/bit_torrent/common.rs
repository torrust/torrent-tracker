//! `BitTorrent` protocol primitive types
//!
//! [BEP 3. The `BitTorrent` Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)

/// The maximum number of torrents that can be returned in an `scrape` response.
///
/// The [BEP 15. UDP Tracker Protocol for `BitTorrent`](https://www.bittorrent.org/beps/bep_0015.html)
/// defines this limit:
///
/// "Up to about 74 torrents can be scraped at once. A full scrape can't be done
/// with this protocol."
///
/// The [BEP 48. Tracker Protocol Extension: Scrape](https://www.bittorrent.org/beps/bep_0048.html)
/// does not specifically mention this limit, but the limit is being used for
/// both the UDP and HTTP trackers since it's applied at the domain level.
pub const MAX_SCRAPE_TORRENTS: u8 = 74;

/// HTTP tracker authentication key length.
///
/// For more information see function [`generate_key`](crate::core::authentication::generate_key) to generate the
/// [`PeerKey`](crate::core::authentication::PeerKey).
pub const AUTH_KEY_LENGTH: usize = 32;
