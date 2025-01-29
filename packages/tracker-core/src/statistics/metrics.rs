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

    // UDP
    /// Total number of UDP (UDP tracker) requests aborted.
    pub udp_requests_aborted: u64,

    /// Total number of UDP (UDP tracker) requests banned.
    pub udp_requests_banned: u64,

    /// Total number of banned IPs.
    pub udp_banned_ips_total: u64,

    /// Average rounded time spent processing UDP connect requests.
    pub udp_avg_connect_processing_time_ns: u64,

    /// Average rounded time spent processing UDP announce requests.
    pub udp_avg_announce_processing_time_ns: u64,

    /// Average rounded time spent processing UDP scrape requests.
    pub udp_avg_scrape_processing_time_ns: u64,

    // UDPv4
    /// Total number of UDP (UDP tracker) requests from IPv4 peers.
    pub udp4_requests: u64,

    /// Total number of UDP (UDP tracker) connections from IPv4 peers.
    pub udp4_connections_handled: u64,

    /// Total number of UDP (UDP tracker) `announce` requests from IPv4 peers.
    pub udp4_announces_handled: u64,

    /// Total number of UDP (UDP tracker) `scrape` requests from IPv4 peers.
    pub udp4_scrapes_handled: u64,

    /// Total number of UDP (UDP tracker) responses from IPv4 peers.
    pub udp4_responses: u64,

    /// Total number of UDP (UDP tracker) `error` requests from IPv4 peers.
    pub udp4_errors_handled: u64,

    // UDPv6
    /// Total number of UDP (UDP tracker) requests from IPv6 peers.
    pub udp6_requests: u64,

    /// Total number of UDP (UDP tracker) `connection` requests from IPv6 peers.
    pub udp6_connections_handled: u64,

    /// Total number of UDP (UDP tracker) `announce` requests from IPv6 peers.
    pub udp6_announces_handled: u64,

    /// Total number of UDP (UDP tracker) `scrape` requests from IPv6 peers.
    pub udp6_scrapes_handled: u64,

    /// Total number of UDP (UDP tracker) responses from IPv6 peers.
    pub udp6_responses: u64,

    /// Total number of UDP (UDP tracker) `error` requests from IPv6 peers.
    pub udp6_errors_handled: u64,
}
