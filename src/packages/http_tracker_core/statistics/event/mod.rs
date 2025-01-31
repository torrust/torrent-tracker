pub mod handler;
pub mod listener;
pub mod sender;

/// An statistics event. It is used to collect tracker metrics.
///
/// - `Tcp` prefix means the event was triggered by the HTTP tracker
/// - `Udp` prefix means the event was triggered by the UDP tracker
/// - `4` or `6` prefixes means the IP version used by the peer
/// - Finally the event suffix is the type of request: `announce`, `scrape` or `connection`
///
/// > NOTE: HTTP trackers do not use `connection` requests.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    // code-review: consider one single event for request type with data: Event::Announce { scheme: HTTPorUDP, ip_version: V4orV6 }
    // Attributes are enums too.
    Tcp4Announce,
    Tcp4Scrape,
    Tcp6Announce,
    Tcp6Scrape,
}
