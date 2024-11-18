use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct UdpTracker {
    /// The address the tracker will bind to.
    /// The format is `ip:port`, for example `0.0.0.0:6969`. If you want to
    /// listen to all interfaces, use `0.0.0.0`. If you want the operating
    /// system to choose a random port, use port `0`.
    #[serde(default = "UdpTracker::default_bind_address")]
    pub bind_address: SocketAddr,

    /// The lifetime of the server-generated connection cookie, that is passed
    /// the client as the `ConnectionId`.
    #[serde(default = "UdpTracker::default_cookie_lifetime")]
    pub cookie_lifetime: Duration,
}
impl Default for UdpTracker {
    fn default() -> Self {
        Self {
            bind_address: Self::default_bind_address(),
            cookie_lifetime: Self::default_cookie_lifetime(),
        }
    }
}

impl UdpTracker {
    fn default_bind_address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 6969)
    }

    fn default_cookie_lifetime() -> Duration {
        Duration::from_secs(120)
    }
}
