//! Utilities to parse Torrust Tracker logs.
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::servers::health_check_api::HEALTH_CHECK_API_LOG_TARGET;
use crate::servers::http::HTTP_TRACKER_LOG_TARGET;
use crate::servers::logging::STARTED_ON;
use crate::servers::udp::UDP_TRACKER_LOG_TARGET;

const INFO_THRESHOLD: &str = "INFO";

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RunningServices {
    pub udp_trackers: Vec<String>,
    pub http_trackers: Vec<String>,
    pub health_checks: Vec<String>,
}

impl RunningServices {
    /// It parses the tracker logs to extract the running services.
    ///
    /// For example, from this logs:
    ///
    /// ```text
    /// Loading configuration from default configuration file: `./share/default/config/tracker.development.sqlite3.toml` ...
    /// 2024-06-10T16:07:39.989540Z  INFO torrust_tracker::bootstrap::logging: Logging initialized
    /// 2024-06-10T16:07:39.990205Z  INFO UDP TRACKER: Starting on: udp://0.0.0.0:6868
    /// 2024-06-10T16:07:39.990215Z  INFO UDP TRACKER: Started on: udp://0.0.0.0:6868
    /// 2024-06-10T16:07:39.990244Z  INFO UDP TRACKER: Starting on: udp://0.0.0.0:6969
    /// 2024-06-10T16:07:39.990255Z  INFO UDP TRACKER: Started on: udp://0.0.0.0:6969
    /// 2024-06-10T16:07:39.990261Z  INFO torrust_tracker::bootstrap::jobs: TLS not enabled
    /// 2024-06-10T16:07:39.990303Z  INFO HTTP TRACKER: Starting on: http://0.0.0.0:7070
    /// 2024-06-10T16:07:39.990439Z  INFO HTTP TRACKER: Started on: http://0.0.0.0:7070
    /// 2024-06-10T16:07:39.990448Z  INFO torrust_tracker::bootstrap::jobs: TLS not enabled
    /// 2024-06-10T16:07:39.990563Z  INFO API: Starting on http://127.0.0.1:1212
    /// 2024-06-10T16:07:39.990565Z  INFO API: Started on http://127.0.0.1:1212
    /// 2024-06-10T16:07:39.990577Z  INFO HEALTH CHECK API: Starting on: http://127.0.0.1:1313
    /// 2024-06-10T16:07:39.990638Z  INFO HEALTH CHECK API: Started on: http://127.0.0.1:1313
    /// ```
    ///
    /// It would extract these services:
    ///
    /// ```json
    /// {
    ///   "udp_trackers": [
    ///     "127.0.0.1:6969"
    ///    ],
    ///    "http_trackers": [
    ///      "http://127.0.0.1:7070"
    ///    ],
    ///    "health_checks": [
    ///      "http://127.0.0.1:1313/health_check"
    ///    ]
    /// }
    /// ```
    ///
    /// NOTICE: Using colors in the console output could affect this method
    /// due to the hidden control chars.
    ///
    /// # Panics
    ///
    /// Will panic is the regular expression to parse the services can't be compiled.
    #[must_use]
    pub fn parse_from_logs(logs: &str) -> Self {
        let mut udp_trackers: Vec<String> = Vec::new();
        let mut http_trackers: Vec<String> = Vec::new();
        let mut health_checks: Vec<String> = Vec::new();

        let udp_re = Regex::new(&format!("{STARTED_ON}: {}", r"udp://([0-9.]+:[0-9]+)")).unwrap();
        let http_re = Regex::new(&format!("{STARTED_ON}: {}", r"(https?://[0-9.]+:[0-9]+)")).unwrap(); // DevSkim: ignore DS137138
        let health_re = Regex::new(&format!("{STARTED_ON}: {}", r"(https?://[0-9.]+:[0-9]+)")).unwrap(); // DevSkim: ignore DS137138
        let ansi_escape_re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();

        for line in logs.lines() {
            let clean_line = ansi_escape_re.replace_all(line, "");

            if !line.contains(INFO_THRESHOLD) {
                continue;
            }

            if line.contains(UDP_TRACKER_LOG_TARGET) {
                if let Some(captures) = udp_re.captures(&clean_line) {
                    let address = Self::replace_wildcard_ip_with_localhost(&captures[1]);
                    udp_trackers.push(address);
                }
            } else if line.contains(HTTP_TRACKER_LOG_TARGET) {
                if let Some(captures) = http_re.captures(&clean_line) {
                    let address = Self::replace_wildcard_ip_with_localhost(&captures[1]);
                    http_trackers.push(address);
                }
            } else if line.contains(HEALTH_CHECK_API_LOG_TARGET) {
                if let Some(captures) = health_re.captures(&clean_line) {
                    let address = format!("{}/health_check", Self::replace_wildcard_ip_with_localhost(&captures[1]));
                    health_checks.push(address);
                }
            }
        }

        Self {
            udp_trackers,
            http_trackers,
            health_checks,
        }
    }

    fn replace_wildcard_ip_with_localhost(address: &str) -> String {
        address.replace("0.0.0.0", "127.0.0.1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_parse_from_logs_with_valid_logs() {
        let logs = r"
            Loading configuration from default configuration file: `./share/default/config/tracker.development.sqlite3.toml` ...
            2024-06-10T16:07:39.989540Z  INFO torrust_tracker::bootstrap::logging: Logging initialized
            2024-06-10T16:07:39.990244Z  INFO UDP TRACKER: Starting on: udp://0.0.0.0:6969
            2024-06-10T16:07:39.990255Z  INFO UDP TRACKER: Started on: udp://0.0.0.0:6969
            2024-06-10T16:07:39.990261Z  INFO torrust_tracker::bootstrap::jobs: TLS not enabled
            2024-06-10T16:07:39.990303Z  INFO HTTP TRACKER: Starting on: http://0.0.0.0:7070
            2024-06-10T16:07:39.990439Z  INFO HTTP TRACKER: Started on: http://0.0.0.0:7070
            2024-06-10T16:07:39.990448Z  INFO torrust_tracker::bootstrap::jobs: TLS not enabled
            2024-06-10T16:07:39.990563Z  INFO API: Starting on http://127.0.0.1:1212
            2024-06-10T16:07:39.990565Z  INFO API: Started on http://127.0.0.1:1212
            2024-06-10T16:07:39.990577Z  INFO HEALTH CHECK API: Starting on: http://127.0.0.1:1313
            2024-06-10T16:07:39.990638Z  INFO HEALTH CHECK API: Started on: http://127.0.0.1:1313
            ";

        let running_services = RunningServices::parse_from_logs(logs);

        assert_eq!(running_services.udp_trackers, vec!["127.0.0.1:6969"]);
        assert_eq!(running_services.http_trackers, vec!["http://127.0.0.1:7070"]);
        assert_eq!(running_services.health_checks, vec!["http://127.0.0.1:1313/health_check"]);
    }

    #[test]
    fn it_should_support_colored_output() {
        let logs = "\x1b[2m2024-06-14T14:40:13.028824Z\x1b[0m  \x1b[33mINFO\x1b[0m \x1b[2mUDP TRACKER\x1b[0m: \x1b[37mStarted on: udp://0.0.0.0:6969\x1b[0m";

        let running_services = RunningServices::parse_from_logs(logs);

        assert_eq!(running_services.udp_trackers, vec!["127.0.0.1:6969"]);
    }

    #[test]
    fn it_should_ignore_logs_with_no_matching_lines() {
        let logs = "[Other Service][INFO] Started on: 0.0.0.0:7070";

        let running_services = RunningServices::parse_from_logs(logs);

        assert!(running_services.udp_trackers.is_empty());
        assert!(running_services.http_trackers.is_empty());
        assert!(running_services.health_checks.is_empty());
    }

    #[test]
    fn it_should_parse_multiple_services() {
        let logs = "
            2024-06-10T16:07:39.990205Z  INFO UDP TRACKER: Starting on: udp://0.0.0.0:6868
            2024-06-10T16:07:39.990215Z  INFO UDP TRACKER: Started on: udp://0.0.0.0:6868

            2024-06-10T16:07:39.990244Z  INFO UDP TRACKER: Starting on: udp://0.0.0.0:6969
            2024-06-10T16:07:39.990255Z  INFO UDP TRACKER: Started on: udp://0.0.0.0:6969
        ";

        let running_services = RunningServices::parse_from_logs(logs);

        assert_eq!(running_services.udp_trackers, vec!["127.0.0.1:6868", "127.0.0.1:6969"]);
    }

    #[test]
    fn it_should_replace_wildcard_ip_with_localhost() {
        let address = "0.0.0.0:8080";
        assert_eq!(RunningServices::replace_wildcard_ip_with_localhost(address), "127.0.0.1:8080");
    }
}
