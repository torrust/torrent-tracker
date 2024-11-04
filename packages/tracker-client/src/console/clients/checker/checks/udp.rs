use std::net::SocketAddr;
use std::time::Duration;

use aquatic_udp_protocol::TransactionId;
use hex_literal::hex;
use serde::Serialize;
use url::Url;

use crate::console::clients::udp::checker::Client;
use crate::console::clients::udp::Error;

#[derive(Debug, Clone, Serialize)]
pub struct Checks {
    remote_addr: SocketAddr,
    results: Vec<(Check, Result<(), Error>)>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Check {
    Setup,
    Connect,
    Announce,
    Scrape,
}

#[allow(clippy::missing_panics_doc)]
pub async fn run(udp_trackers: Vec<Url>, timeout: Duration) -> Vec<Result<Checks, Checks>> {
    let mut results = Vec::default();

    tracing::debug!("UDP trackers ...");

    let info_hash = aquatic_udp_protocol::InfoHash(hex!("9c38422213e30bff212b30c360d26f9a02136422")); // # DevSkim: ignore DS173237

    for remote_url in udp_trackers {
        let remote_addr = resolve_socket_addr(&remote_url);

        let mut checks = Checks {
            remote_addr,
            results: Vec::default(),
        };

        tracing::debug!("UDP tracker: {:?}", remote_url);

        // Setup
        let client = match Client::new(remote_addr, timeout).await {
            Ok(client) => {
                checks.results.push((Check::Setup, Ok(())));
                client
            }
            Err(err) => {
                checks.results.push((Check::Setup, Err(err)));
                results.push(Err(checks));
                continue;
            }
        };

        let transaction_id = TransactionId::new(1);

        // Connect Remote
        let connection_id = match client.send_connection_request(transaction_id).await {
            Ok(connection_id) => {
                checks.results.push((Check::Connect, Ok(())));
                connection_id
            }
            Err(err) => {
                checks.results.push((Check::Connect, Err(err)));
                results.push(Err(checks));
                continue;
            }
        };

        // Announce
        {
            let check = client
                .send_announce_request(transaction_id, connection_id, info_hash.into())
                .await
                .map(|_| ());

            checks.results.push((Check::Announce, check));
        }

        // Scrape
        {
            let check = client
                .send_scrape_request(connection_id, transaction_id, &[info_hash.into()])
                .await
                .map(|_| ());

            checks.results.push((Check::Scrape, check));
        }

        if checks.results.iter().any(|f| f.1.is_err()) {
            results.push(Err(checks));
        } else {
            results.push(Ok(checks));
        }
    }

    results
}

fn resolve_socket_addr(url: &Url) -> SocketAddr {
    let socket_addr = url.socket_addrs(|| None).unwrap();
    *socket_addr.first().unwrap()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use url::Url;

    use crate::console::clients::checker::checks::udp::resolve_socket_addr;

    #[test]
    fn it_should_resolve_the_socket_address_for_udp_scheme_urls_containing_a_domain() {
        let socket_addr = resolve_socket_addr(&Url::parse("udp://localhost:8080").unwrap());

        assert!(
            socket_addr == SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
                || socket_addr == SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
        );
    }

    #[test]
    fn it_should_resolve_the_socket_address_for_udp_scheme_urls_containing_an_ip() {
        let socket_addr = resolve_socket_addr(&Url::parse("udp://localhost:8080").unwrap());

        assert!(
            socket_addr == SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
                || socket_addr == SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080)
        );
    }
}
