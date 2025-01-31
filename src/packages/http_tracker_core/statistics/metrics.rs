/// Metrics collected by the tracker.
///
/// - Number of connections handled
/// - Number of `announce` requests handled
/// - Number of `scrape` request handled
///
/// These metrics are collected for each connection type: UDP and HTTP
/// and also for each IP version used by the peers: IPv4 and IPv6.
#[derive(Debug, PartialEq, Default)]
pub struct Metrics {
    /// Total number of TCP (HTTP tracker) connections from IPv4 peers.
    /// Since the HTTP tracker spec does not require a handshake, this metric
    /// increases for every HTTP request.
    pub tcp4_connections_handled: u64,

    /// Total number of TCP (HTTP tracker) `announce` requests from IPv4 peers.
    pub tcp4_announces_handled: u64,

    /// Total number of TCP (HTTP tracker) `scrape` requests from IPv4 peers.
    pub tcp4_scrapes_handled: u64,

    /// Total number of TCP (HTTP tracker) connections from IPv6 peers.
    pub tcp6_connections_handled: u64,

    /// Total number of TCP (HTTP tracker) `announce` requests from IPv6 peers.
    pub tcp6_announces_handled: u64,

    /// Total number of TCP (HTTP tracker) `scrape` requests from IPv6 peers.
    pub tcp6_scrapes_handled: u64,
}
