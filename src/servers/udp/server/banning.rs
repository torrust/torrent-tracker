//! Banning service for UDP tracker.
//!
//! It bans clients that send invalid connection id's.
//!
//! It uses two levels of filtering:
//!
//! 1. First, tt uses a Counting Bloom Filter to keep track of the number of
//!    connection ID errors per ip. That means there can be false positives, but
//!    not false negatives. 1 out of 100000 requests will be a false positive
//!    and the client will be banned and not receive a response.
//! 2. Since we want to avoid false positives (banning a client that is not
//!    sending invalid connection id's), we use a `HashMap` to keep track of the
//!    exact number of connection ID errors per ip.
//!
//! This two level filtering is to avoid false positives. It has the advantage
//! of being fast by using a Counting Bloom Filter and not having false
//! negatives at the cost of increasing the memory usage.
use std::collections::HashMap;
use std::net::IpAddr;

use bloom::{CountingBloomFilter, ASMS};
use tokio::time::Instant;

use crate::servers::udp::UDP_TRACKER_LOG_TARGET;

pub struct BanService {
    max_connection_id_errors_per_ip: u32,
    fuzzy_error_counter: CountingBloomFilter,
    accurate_error_counter: HashMap<IpAddr, u32>,
    last_connection_id_errors_reset: Instant,
}

impl BanService {
    #[must_use]
    pub fn new(max_connection_id_errors_per_ip: u32) -> Self {
        Self {
            max_connection_id_errors_per_ip,
            fuzzy_error_counter: CountingBloomFilter::with_rate(4, 0.01, 100),
            accurate_error_counter: HashMap::new(),
            last_connection_id_errors_reset: tokio::time::Instant::now(),
        }
    }

    pub fn increase_counter(&mut self, ip: &IpAddr) {
        self.fuzzy_error_counter.insert(&ip.to_string());
        *self.accurate_error_counter.entry(*ip).or_insert(0) += 1;
    }

    #[must_use]
    pub fn get_count(&self, ip: &IpAddr) -> Option<u32> {
        self.accurate_error_counter.get(ip).copied()
    }

    #[must_use]
    pub fn get_banned_ips_total(&self) -> usize {
        self.accurate_error_counter.len()
    }

    #[must_use]
    pub fn get_estimate_count(&self, ip: &IpAddr) -> u32 {
        self.fuzzy_error_counter.estimate_count(&ip.to_string())
    }

    /// Returns true if the given ip address is banned.
    #[must_use]
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        // First check if the ip is in the bloom filter (fast check)
        if self.fuzzy_error_counter.estimate_count(&ip.to_string()) <= self.max_connection_id_errors_per_ip {
            return false;
        }

        // Check with the exact counter (to avoid false positives)
        match self.get_count(ip) {
            Some(count) => count > self.max_connection_id_errors_per_ip,
            None => false,
        }
    }

    /// Resets the filters and updates the reset timestamp.
    pub fn reset_bans(&mut self) {
        self.fuzzy_error_counter.clear();

        self.accurate_error_counter.clear();

        self.last_connection_id_errors_reset = Instant::now();

        tracing::info!(target: UDP_TRACKER_LOG_TARGET, "Udp::run_udp_server::loop (connection id errors filter cleared)");
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::BanService;

    /// Sample service with one day ban duration.
    fn ban_service(counter_limit: u32) -> BanService {
        BanService::new(counter_limit)
    }

    #[test]
    fn it_should_increase_the_errors_counter_for_a_given_ip() {
        let mut ban_service = ban_service(1);

        let ip: IpAddr = "127.0.0.2".parse().unwrap();

        ban_service.increase_counter(&ip);

        assert_eq!(ban_service.get_count(&ip), Some(1));
    }

    #[test]
    fn it_should_ban_ips_with_counters_exceeding_a_predefined_limit() {
        let mut ban_service = ban_service(1);

        let ip: IpAddr = "127.0.0.2".parse().unwrap();

        ban_service.increase_counter(&ip); // Counter = 1
        ban_service.increase_counter(&ip); // Counter = 2

        println!("Counter: {}", ban_service.get_count(&ip).unwrap());

        assert!(ban_service.is_banned(&ip));
    }

    #[test]
    fn it_should_not_ban_ips_whose_counters_do_not_exceed_the_predefined_limit() {
        let mut ban_service = ban_service(1);

        let ip: IpAddr = "127.0.0.2".parse().unwrap();

        ban_service.increase_counter(&ip);

        assert!(!ban_service.is_banned(&ip));
    }

    #[test]
    fn it_should_allow_resetting_all_the_counters() {
        let mut ban_service = ban_service(1);

        let ip: IpAddr = "127.0.0.2".parse().unwrap();

        ban_service.increase_counter(&ip); // Counter = 1

        ban_service.reset_bans();

        assert_eq!(ban_service.get_estimate_count(&ip), 0);
    }
}
