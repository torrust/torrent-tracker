use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::panic::Location;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, fs};

use config::{Config, ConfigError, File, FileFormat};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, NoneAsEmptyString};
use thiserror::Error;
use torrust_tracker_located_error::{Located, LocatedError};
use torrust_tracker_primitives::{DatabaseDriver, TrackerMode};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct UdpTracker {
    pub enabled: bool,
    pub bind_address: String,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct HttpTracker {
    pub enabled: bool,
    pub bind_address: String,
    pub ssl_enabled: bool,
    #[serde_as(as = "NoneAsEmptyString")]
    pub ssl_cert_path: Option<String>,
    #[serde_as(as = "NoneAsEmptyString")]
    pub ssl_key_path: Option<String>,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct HttpApi {
    pub enabled: bool,
    pub bind_address: String,
    pub ssl_enabled: bool,
    #[serde_as(as = "NoneAsEmptyString")]
    pub ssl_cert_path: Option<String>,
    #[serde_as(as = "NoneAsEmptyString")]
    pub ssl_key_path: Option<String>,
    pub access_tokens: HashMap<String, String>,
}

impl HttpApi {
    #[must_use]
    pub fn contains_token(&self, token: &str) -> bool {
        let tokens: HashMap<String, String> = self.access_tokens.clone();
        let tokens: HashSet<String> = tokens.into_values().collect();
        tokens.contains(token)
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Configuration {
    pub log_level: Option<String>,
    pub mode: TrackerMode,
    pub db_driver: DatabaseDriver,
    pub db_path: String,
    pub announce_interval: u32,
    pub min_announce_interval: u32,
    pub max_peer_timeout: u32,
    pub on_reverse_proxy: bool,
    pub external_ip: Option<String>,
    pub tracker_usage_statistics: bool,
    pub persistent_torrent_completed_stat: bool,
    pub inactive_peer_cleanup_interval: u64,
    pub remove_peerless_torrents: bool,
    pub udp_trackers: Vec<UdpTracker>,
    pub http_trackers: Vec<HttpTracker>,
    pub http_api: HttpApi,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unable to load from Environmental Variable: {source}")]
    UnableToLoadFromEnvironmentVariable {
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },

    #[error("Default configuration created at: `{path}`, please review and reload tracker, {location}")]
    CreatedNewConfigHalt {
        location: &'static Location<'static>,
        path: String,
    },

    #[error("Failed processing the configuration: {source}")]
    ConfigError { source: LocatedError<'static, ConfigError> },
}

impl From<ConfigError> for Error {
    #[track_caller]
    fn from(err: ConfigError) -> Self {
        Self::ConfigError {
            source: Located(err).into(),
        }
    }
}

/// This configuration is used for testing. It generates random config values so they do not collide
/// if you run more than one tracker at the same time.
///
/// # Panics
///
/// Will panic if it can't convert the temp file path to string
#[must_use]
pub fn ephemeral_configuration() -> Configuration {
    // todo: disable services that are not needed.
    // For example: a test for the UDP tracker should disable the API and HTTP tracker.

    let mut config = Configuration {
        log_level: Some("off".to_owned()), // Change to `debug` for tests debugging
        ..Default::default()
    };

    // Ephemeral socket address for API
    let api_port = 0u16;
    config.http_api.enabled = true;
    config.http_api.bind_address = format!("127.0.0.1:{}", &api_port);

    // Ephemeral socket address for UDP tracker
    let udp_port = 0u16;
    config.udp_trackers[0].enabled = true;
    config.udp_trackers[0].bind_address = format!("127.0.0.1:{}", &udp_port);

    // Ephemeral socket address for HTTP tracker
    let http_port = 0u16;
    config.http_trackers[0].enabled = true;
    config.http_trackers[0].bind_address = format!("127.0.0.1:{}", &http_port);

    // Ephemeral sqlite database
    let temp_directory = env::temp_dir();
    let temp_file = temp_directory.join(format!("data_{}_{}_{}.db", &api_port, &udp_port, &http_port));
    config.db_path = temp_file.to_str().unwrap().to_owned();

    config
}

impl Default for Configuration {
    fn default() -> Self {
        let mut configuration = Configuration {
            log_level: Option::from(String::from("info")),
            mode: TrackerMode::Public,
            db_driver: DatabaseDriver::Sqlite3,
            db_path: String::from("./storage/database/data.db"),
            announce_interval: 120,
            min_announce_interval: 120,
            max_peer_timeout: 900,
            on_reverse_proxy: false,
            external_ip: Some(String::from("0.0.0.0")),
            tracker_usage_statistics: true,
            persistent_torrent_completed_stat: false,
            inactive_peer_cleanup_interval: 600,
            remove_peerless_torrents: true,
            udp_trackers: Vec::new(),
            http_trackers: Vec::new(),
            http_api: HttpApi {
                enabled: true,
                bind_address: String::from("127.0.0.1:1212"),
                ssl_enabled: false,
                ssl_cert_path: None,
                ssl_key_path: None,
                access_tokens: [(String::from("admin"), String::from("MyAccessToken"))]
                    .iter()
                    .cloned()
                    .collect(),
            },
        };
        configuration.udp_trackers.push(UdpTracker {
            enabled: false,
            bind_address: String::from("0.0.0.0:6969"),
        });
        configuration.http_trackers.push(HttpTracker {
            enabled: false,
            bind_address: String::from("0.0.0.0:7070"),
            ssl_enabled: false,
            ssl_cert_path: None,
            ssl_key_path: None,
        });
        configuration
    }
}

impl Configuration {
    #[must_use]
    pub fn get_ext_ip(&self) -> Option<IpAddr> {
        match &self.external_ip {
            None => None,
            Some(external_ip) => match IpAddr::from_str(external_ip) {
                Ok(external_ip) => Some(external_ip),
                Err(_) => None,
            },
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if `path` does not exist or has a bad configuration.
    pub fn load_from_file(path: &str) -> Result<Configuration, Error> {
        let config_builder = Config::builder();

        #[allow(unused_assignments)]
        let mut config = Config::default();

        if Path::new(path).exists() {
            config = config_builder.add_source(File::with_name(path)).build()?;
        } else {
            warn!("No config file found.");
            warn!("Creating config file..");
            let config = Configuration::default();
            config.save_to_file(path)?;
            return Err(Error::CreatedNewConfigHalt {
                location: Location::caller(),
                path: path.to_string(),
            });
        }

        let torrust_config: Configuration = config.try_deserialize()?;

        Ok(torrust_config)
    }

    /// # Errors
    ///
    /// Will return `Err` if the environment variable does not exist or has a bad configuration.
    pub fn load_from_env_var(config_env_var_name: &str) -> Result<Configuration, Error> {
        match env::var(config_env_var_name) {
            Ok(config_toml) => {
                let config_builder = Config::builder()
                    .add_source(File::from_str(&config_toml, FileFormat::Toml))
                    .build()?;
                let config = config_builder.try_deserialize()?;
                Ok(config)
            }
            Err(e) => Err(Error::UnableToLoadFromEnvironmentVariable {
                source: (Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>).into(),
            }),
        }
    }

    /// # Errors
    ///
    /// Will return `Err` if `filename` does not exist or the user does not have
    /// permission to read it.
    pub fn save_to_file(&self, path: &str) -> Result<(), Error> {
        let toml_string = toml::to_string(self).expect("Could not encode TOML value");
        fs::write(path, toml_string).expect("Could not write to file!");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Configuration;

    #[cfg(test)]
    fn default_config_toml() -> String {
        let config = r#"log_level = "info"
                                mode = "public"
                                db_driver = "Sqlite3"
                                db_path = "./storage/database/data.db"
                                announce_interval = 120
                                min_announce_interval = 120
                                max_peer_timeout = 900
                                on_reverse_proxy = false
                                external_ip = "0.0.0.0"
                                tracker_usage_statistics = true
                                persistent_torrent_completed_stat = false
                                inactive_peer_cleanup_interval = 600
                                remove_peerless_torrents = true

                                [[udp_trackers]]
                                enabled = false
                                bind_address = "0.0.0.0:6969"

                                [[http_trackers]]
                                enabled = false
                                bind_address = "0.0.0.0:7070"
                                ssl_enabled = false
                                ssl_cert_path = ""
                                ssl_key_path = ""

                                [http_api]
                                enabled = true
                                bind_address = "127.0.0.1:1212"
                                ssl_enabled = false
                                ssl_cert_path = ""
                                ssl_key_path = ""

                                [http_api.access_tokens]
                                admin = "MyAccessToken"
        "#
        .lines()
        .map(str::trim_start)
        .collect::<Vec<&str>>()
        .join("\n");
        config
    }

    #[test]
    fn configuration_should_have_default_values() {
        let configuration = Configuration::default();

        let toml = toml::to_string(&configuration).expect("Could not encode TOML value");

        assert_eq!(toml, default_config_toml());
    }

    #[test]
    fn configuration_should_contain_the_external_ip() {
        let configuration = Configuration::default();

        assert_eq!(configuration.external_ip, Some(String::from("0.0.0.0")));
    }

    #[test]
    fn configuration_should_be_saved_in_a_toml_config_file() {
        use std::{env, fs};

        use uuid::Uuid;

        // Build temp config file path
        let temp_directory = env::temp_dir();
        let temp_file = temp_directory.join(format!("test_config_{}.toml", Uuid::new_v4()));

        // Convert to argument type for Configuration::save_to_file
        let config_file_path = temp_file;
        let path = config_file_path.to_string_lossy().to_string();

        let default_configuration = Configuration::default();

        default_configuration
            .save_to_file(&path)
            .expect("Could not save configuration to file");

        let contents = fs::read_to_string(&path).expect("Something went wrong reading the file");

        assert_eq!(contents, default_config_toml());
    }

    #[cfg(test)]
    fn create_temp_config_file_with_default_config() -> String {
        use std::env;
        use std::fs::File;
        use std::io::Write;

        use uuid::Uuid;

        // Build temp config file path
        let temp_directory = env::temp_dir();
        let temp_file = temp_directory.join(format!("test_config_{}.toml", Uuid::new_v4()));

        // Convert to argument type for Configuration::load_from_file
        let config_file_path = temp_file.clone();
        let path = config_file_path.to_string_lossy().to_string();

        // Write file contents
        let mut file = File::create(temp_file).unwrap();
        writeln!(&mut file, "{}", default_config_toml()).unwrap();

        path
    }

    #[test]
    fn configuration_should_be_loaded_from_a_toml_config_file() {
        let config_file_path = create_temp_config_file_with_default_config();

        let configuration = Configuration::load_from_file(&config_file_path).expect("Could not load configuration from file");

        assert_eq!(configuration, Configuration::default());
    }

    #[test]
    fn http_api_configuration_should_check_if_it_contains_a_token() {
        let configuration = Configuration::default();

        assert!(configuration.http_api.contains_token("MyAccessToken"));
        assert!(!configuration.http_api.contains_token("NonExistingToken"));
    }
}
