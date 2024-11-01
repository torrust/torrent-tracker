use std::error::Error;
use std::fmt;

use reqwest::Url as ServiceUrl;
use serde::Deserialize;

/// It parses the configuration from a JSON format.
///
/// # Errors
///
/// Will return an error if the configuration is not valid.
///
/// # Panics
///
/// Will panic if unable to read the configuration file.
pub fn parse_from_json(json: &str) -> Result<Configuration, ConfigurationError> {
    let plain_config: PlainConfiguration = serde_json::from_str(json).map_err(ConfigurationError::JsonParseError)?;
    Configuration::try_from(plain_config)
}

/// DTO for the configuration to serialize/deserialize configuration.
///
/// Configuration does not need to be valid.
#[derive(Deserialize)]
struct PlainConfiguration {
    pub udp_trackers: Vec<String>,
    pub http_trackers: Vec<String>,
    pub health_checks: Vec<String>,
}

/// Validated configuration
pub struct Configuration {
    pub udp_trackers: Vec<ServiceUrl>,
    pub http_trackers: Vec<ServiceUrl>,
    pub health_checks: Vec<ServiceUrl>,
}

#[derive(Debug)]
pub enum ConfigurationError {
    JsonParseError(serde_json::Error),
    InvalidUdpAddress(std::net::AddrParseError),
    InvalidUrl(url::ParseError),
}

impl Error for ConfigurationError {}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigurationError::JsonParseError(e) => write!(f, "JSON parse error: {e}"),
            ConfigurationError::InvalidUdpAddress(e) => write!(f, "Invalid UDP address: {e}"),
            ConfigurationError::InvalidUrl(e) => write!(f, "Invalid URL: {e}"),
        }
    }
}

impl TryFrom<PlainConfiguration> for Configuration {
    type Error = ConfigurationError;

    fn try_from(plain_config: PlainConfiguration) -> Result<Self, Self::Error> {
        let udp_trackers = plain_config
            .udp_trackers
            .into_iter()
            .map(|s| if s.starts_with("udp://") { s } else { format!("udp://{s}") })
            .map(|s| s.parse::<ServiceUrl>().map_err(ConfigurationError::InvalidUrl))
            .collect::<Result<Vec<_>, _>>()?;

        let http_trackers = plain_config
            .http_trackers
            .into_iter()
            .map(|s| s.parse::<ServiceUrl>().map_err(ConfigurationError::InvalidUrl))
            .collect::<Result<Vec<_>, _>>()?;

        let health_checks = plain_config
            .health_checks
            .into_iter()
            .map(|s| s.parse::<ServiceUrl>().map_err(ConfigurationError::InvalidUrl))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Configuration {
            udp_trackers,
            http_trackers,
            health_checks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_should_be_build_from_plain_serializable_configuration() {
        let dto = PlainConfiguration {
            udp_trackers: vec!["udp://127.0.0.1:8080".to_string()],
            http_trackers: vec!["http://127.0.0.1:8080".to_string()],
            health_checks: vec!["http://127.0.0.1:8080/health".to_string()],
        };

        let config = Configuration::try_from(dto).expect("A valid configuration");

        assert_eq!(config.udp_trackers, vec![ServiceUrl::parse("udp://127.0.0.1:8080").unwrap()]);

        assert_eq!(
            config.http_trackers,
            vec![ServiceUrl::parse("http://127.0.0.1:8080").unwrap()]
        );

        assert_eq!(
            config.health_checks,
            vec![ServiceUrl::parse("http://127.0.0.1:8080/health").unwrap()]
        );
    }

    mod building_configuration_from_plain_configuration_for {

        mod udp_trackers {
            use crate::console::clients::checker::config::{Configuration, PlainConfiguration, ServiceUrl};

            /* The plain configuration should allow UDP URLs with:

            - IP or domain.
            - With or without scheme.
            - With or without `announce` suffix.
            - With or without `/` at the end of the authority section (with empty path).

            For example:

            127.0.0.1:6969
            127.0.0.1:6969/
            127.0.0.1:6969/announce

            localhost:6969
            localhost:6969/
            localhost:6969/announce

            udp://127.0.0.1:6969
            udp://127.0.0.1:6969/
            udp://127.0.0.1:6969/announce

            udp://localhost:6969
            udp://localhost:6969/
            udp://localhost:6969/announce

            */

            #[test]
            fn it_should_fail_when_a_tracker_udp_url_is_invalid() {
                let plain_config = PlainConfiguration {
                    udp_trackers: vec!["invalid URL".to_string()],
                    http_trackers: vec![],
                    health_checks: vec![],
                };

                assert!(Configuration::try_from(plain_config).is_err());
            }

            #[test]
            fn it_should_add_the_udp_scheme_to_the_udp_url_when_it_is_missing() {
                let plain_config = PlainConfiguration {
                    udp_trackers: vec!["127.0.0.1:6969".to_string()],
                    http_trackers: vec![],
                    health_checks: vec![],
                };

                let config = Configuration::try_from(plain_config).expect("Invalid plain configuration");

                assert_eq!(config.udp_trackers[0], "udp://127.0.0.1:6969".parse::<ServiceUrl>().unwrap());
            }

            #[test]
            fn it_should_allow_using_domains() {
                let plain_config = PlainConfiguration {
                    udp_trackers: vec!["udp://localhost:6969".to_string()],
                    http_trackers: vec![],
                    health_checks: vec![],
                };

                let config = Configuration::try_from(plain_config).expect("Invalid plain configuration");

                assert_eq!(config.udp_trackers[0], "udp://localhost:6969".parse::<ServiceUrl>().unwrap());
            }

            #[test]
            fn it_should_allow_the_url_to_have_an_empty_path() {
                let plain_config = PlainConfiguration {
                    udp_trackers: vec!["127.0.0.1:6969/".to_string()],
                    http_trackers: vec![],
                    health_checks: vec![],
                };

                let config = Configuration::try_from(plain_config).expect("Invalid plain configuration");

                assert_eq!(config.udp_trackers[0], "udp://127.0.0.1:6969/".parse::<ServiceUrl>().unwrap());
            }

            #[test]
            fn it_should_allow_the_url_to_contain_a_path() {
                // This is the common format for UDP tracker URLs:
                // udp://domain.com:6969/announce

                let plain_config = PlainConfiguration {
                    udp_trackers: vec!["127.0.0.1:6969/announce".to_string()],
                    http_trackers: vec![],
                    health_checks: vec![],
                };

                let config = Configuration::try_from(plain_config).expect("Invalid plain configuration");

                assert_eq!(
                    config.udp_trackers[0],
                    "udp://127.0.0.1:6969/announce".parse::<ServiceUrl>().unwrap()
                );
            }
        }

        mod http_trackers {
            use crate::console::clients::checker::config::{Configuration, PlainConfiguration, ServiceUrl};

            #[test]
            fn it_should_fail_when_a_tracker_http_url_is_invalid() {
                let plain_config = PlainConfiguration {
                    udp_trackers: vec![],
                    http_trackers: vec!["invalid URL".to_string()],
                    health_checks: vec![],
                };

                assert!(Configuration::try_from(plain_config).is_err());
            }

            #[test]
            fn it_should_allow_the_url_to_contain_a_path() {
                // This is the common format for HTTP tracker URLs:
                // http://domain.com:7070/announce

                let plain_config = PlainConfiguration {
                    udp_trackers: vec![],
                    http_trackers: vec!["http://127.0.0.1:7070/announce".to_string()],
                    health_checks: vec![],
                };

                let config = Configuration::try_from(plain_config).expect("Invalid plain configuration");

                assert_eq!(
                    config.http_trackers[0],
                    "http://127.0.0.1:7070/announce".parse::<ServiceUrl>().unwrap()
                );
            }

            #[test]
            fn it_should_allow_the_url_to_contain_an_empty_path() {
                let plain_config = PlainConfiguration {
                    udp_trackers: vec![],
                    http_trackers: vec!["http://127.0.0.1:7070/".to_string()],
                    health_checks: vec![],
                };

                let config = Configuration::try_from(plain_config).expect("Invalid plain configuration");

                assert_eq!(
                    config.http_trackers[0],
                    "http://127.0.0.1:7070/".parse::<ServiceUrl>().unwrap()
                );
            }
        }

        mod health_checks {
            use crate::console::clients::checker::config::{Configuration, PlainConfiguration};

            #[test]
            fn it_should_fail_when_a_health_check_http_url_is_invalid() {
                let plain_config = PlainConfiguration {
                    udp_trackers: vec![],
                    http_trackers: vec![],
                    health_checks: vec!["invalid URL".to_string()],
                };

                assert!(Configuration::try_from(plain_config).is_err());
            }
        }
    }
}
