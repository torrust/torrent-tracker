//! Tracker configuration factories for testing.
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use torrust_tracker_configuration::{Configuration, HttpApi, HttpTracker, Threshold, UdpTracker};

use crate::random;

/// This configuration is used for testing. It generates random config values
/// so they do not collide if you run more than one tracker at the same time.
///
/// > **NOTICE**: This configuration is not meant to be used in production.
///
/// > **NOTICE**: Port 0 is used for ephemeral ports, which means that the OS
/// > will assign a random free port for the tracker to use.
///
/// > **NOTICE**: You can change the log threshold to `debug` to see the logs of the
/// > tracker while running the tests. That can be particularly useful when
/// > debugging tests.
///
/// # Panics
///
/// Will panic if it can't convert the temp file path to string
#[must_use]
pub fn ephemeral() -> Configuration {
    // todo: disable services that are not needed.
    // For example: a test for the UDP tracker should disable the API and HTTP tracker.

    let mut config = Configuration::default();

    config.logging.threshold = Threshold::Error;

    // Ephemeral socket address for API
    let api_port = 0u16;
    let mut http_api = HttpApi {
        bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), api_port),
        ..Default::default()
    };
    http_api.add_token("admin", "MyAccessToken");
    config.http_api = Some(http_api);

    // Ephemeral socket address for Health Check API
    let health_check_api_port = 0u16;
    config.health_check_api.bind_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), health_check_api_port);

    // Ephemeral socket address for UDP tracker
    let udp_port = 0u16;
    config.udp_trackers = Some(vec![UdpTracker {
        bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), udp_port),
        cookie_lifetime: Duration::from_secs(120),
    }]);

    // Ephemeral socket address for HTTP tracker
    let http_port = 0u16;
    config.http_trackers = Some(vec![HttpTracker {
        bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), http_port),
        tsl_config: None,
    }]);

    // Ephemeral sqlite database
    let temp_directory = env::temp_dir();
    let random_db_id = random::string(16);
    let temp_file = temp_directory.join(format!("data_{random_db_id}.db"));
    temp_file.to_str().unwrap().clone_into(&mut config.core.database.path);

    config
}

/// Ephemeral configuration with reverse proxy enabled.
#[must_use]
pub fn ephemeral_with_reverse_proxy() -> Configuration {
    let mut cfg = ephemeral();

    cfg.core.net.on_reverse_proxy = true;

    cfg
}

/// Ephemeral configuration with reverse proxy disabled.
#[must_use]
pub fn ephemeral_without_reverse_proxy() -> Configuration {
    let mut cfg = ephemeral();

    cfg.core.net.on_reverse_proxy = false;

    cfg
}

/// Ephemeral configuration with `public` mode.
#[must_use]
pub fn ephemeral_public() -> Configuration {
    let mut cfg = ephemeral();

    cfg.core.private = false;

    cfg
}

/// Ephemeral configuration with `private` mode.
#[must_use]
pub fn ephemeral_private() -> Configuration {
    let mut cfg = ephemeral();

    cfg.core.private = true;

    cfg
}

/// Ephemeral configuration with `listed` mode.
#[must_use]
pub fn ephemeral_listed() -> Configuration {
    let mut cfg = ephemeral();

    cfg.core.listed = true;

    cfg
}

/// Ephemeral configuration with `private_listed` mode.
#[must_use]
pub fn ephemeral_private_and_listed() -> Configuration {
    let mut cfg = ephemeral();

    cfg.core.private = true;
    cfg.core.listed = true;

    cfg
}

/// Ephemeral configuration with a custom external (public) IP for the tracker.
#[must_use]
pub fn ephemeral_with_external_ip(ip: IpAddr) -> Configuration {
    let mut cfg = ephemeral();

    cfg.core.net.external_ip = Some(ip);

    cfg
}

/// Ephemeral configuration using a wildcard IPv6 for the UDP, HTTP and API
/// services.
#[must_use]
pub fn ephemeral_ipv6() -> Configuration {
    let mut cfg = ephemeral();

    let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0);

    if let Some(ref mut http_api) = cfg.http_api {
        http_api.bind_address.clone_from(&ipv6);
    };

    if let Some(ref mut http_trackers) = cfg.http_trackers {
        http_trackers[0].bind_address.clone_from(&ipv6);
    }

    if let Some(ref mut udp_trackers) = cfg.udp_trackers {
        udp_trackers[0].bind_address.clone_from(&ipv6);
    }

    cfg
}

/// Ephemeral without running any services.
#[must_use]
pub fn ephemeral_with_no_services() -> Configuration {
    let mut cfg = ephemeral();

    cfg.http_api = None;
    cfg.http_trackers = None;
    cfg.udp_trackers = None;

    cfg
}
