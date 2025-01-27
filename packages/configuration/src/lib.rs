//! Configuration data structures for [Torrust Tracker](https://docs.rs/torrust-tracker).
//!
//! This module contains the configuration data structures for the
//! Torrust Tracker, which is a `BitTorrent` tracker server.
//!
//! The current version for configuration is [`v2_0_0`].
pub mod v2_0_0;
pub mod validator;

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;

use camino::Utf8PathBuf;
use derive_more::{Constructor, Display};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;
use torrust_tracker_located_error::{DynError, LocatedError};

/// The maximum number of returned peers for a torrent.
pub const TORRENT_PEERS_LIMIT: usize = 74;

/// Default timeout for sending and receiving packets. And waiting for sockets
/// to be readable and writable.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

// Environment variables

/// The whole `tracker.toml` file content. It has priority over the config file.
/// Even if the file is not on the default path.
const ENV_VAR_CONFIG_TOML: &str = "TORRUST_TRACKER_CONFIG_TOML";

/// The `tracker.toml` file location.
pub const ENV_VAR_CONFIG_TOML_PATH: &str = "TORRUST_TRACKER_CONFIG_TOML_PATH";

pub type Configuration = v2_0_0::Configuration;
pub type Core = v2_0_0::core::Core;
pub type HealthCheckApi = v2_0_0::health_check_api::HealthCheckApi;
pub type HttpApi = v2_0_0::tracker_api::HttpApi;
pub type HttpTracker = v2_0_0::http_tracker::HttpTracker;
pub type UdpTracker = v2_0_0::udp_tracker::UdpTracker;
pub type Database = v2_0_0::database::Database;
pub type Driver = v2_0_0::database::Driver;
pub type Threshold = v2_0_0::logging::Threshold;

pub type AccessTokens = HashMap<String, String>;

pub const LATEST_VERSION: &str = "2.0.0";

/// Info about the configuration specification.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Display, Clone)]
#[display("Metadata(app: {app}, purpose: {purpose}, schema_version: {schema_version})")]
pub struct Metadata {
    /// The application this configuration is valid for.
    #[serde(default = "Metadata::default_app")]
    app: App,

    /// The purpose of this parsed file.
    #[serde(default = "Metadata::default_purpose")]
    purpose: Purpose,

    /// The schema version for the configuration.
    #[serde(default = "Metadata::default_schema_version")]
    #[serde(flatten)]
    schema_version: Version,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            app: Self::default_app(),
            purpose: Self::default_purpose(),
            schema_version: Self::default_schema_version(),
        }
    }
}

impl Metadata {
    fn default_app() -> App {
        App::TorrustTracker
    }

    fn default_purpose() -> Purpose {
        Purpose::Configuration
    }

    fn default_schema_version() -> Version {
        Version::latest()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Display, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum App {
    TorrustTracker,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Display, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    Configuration,
}

/// The configuration version.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Display, Clone)]
#[serde(rename_all = "lowercase")]
pub struct Version {
    #[serde(default = "Version::default_semver")]
    schema_version: String,
}

impl Default for Version {
    fn default() -> Self {
        Self {
            schema_version: Self::default_semver(),
        }
    }
}

impl Version {
    fn new(semver: &str) -> Self {
        Self {
            schema_version: semver.to_owned(),
        }
    }

    fn latest() -> Self {
        Self {
            schema_version: LATEST_VERSION.to_string(),
        }
    }

    fn default_semver() -> String {
        LATEST_VERSION.to_string()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Constructor)]
pub struct TrackerPolicy {
    // Cleanup job configuration
    /// Maximum time in seconds that a peer can be inactive before being
    /// considered an inactive peer. If a peer is inactive for more than this
    /// time, it will be removed from the torrent peer list.
    #[serde(default = "TrackerPolicy::default_max_peer_timeout")]
    pub max_peer_timeout: u32,

    /// If enabled the tracker will persist the number of completed downloads.
    /// That's how many times a torrent has been downloaded completely.
    #[serde(default = "TrackerPolicy::default_persistent_torrent_completed_stat")]
    pub persistent_torrent_completed_stat: bool,

    /// If enabled, the tracker will remove torrents that have no peers.
    /// The clean up torrent job runs every `inactive_peer_cleanup_interval`
    /// seconds and it removes inactive peers. Eventually, the peer list of a
    /// torrent could be empty and the torrent will be removed if this option is
    /// enabled.
    #[serde(default = "TrackerPolicy::default_remove_peerless_torrents")]
    pub remove_peerless_torrents: bool,
}

impl Default for TrackerPolicy {
    fn default() -> Self {
        Self {
            max_peer_timeout: Self::default_max_peer_timeout(),
            persistent_torrent_completed_stat: Self::default_persistent_torrent_completed_stat(),
            remove_peerless_torrents: Self::default_remove_peerless_torrents(),
        }
    }
}

impl TrackerPolicy {
    fn default_max_peer_timeout() -> u32 {
        900
    }

    fn default_persistent_torrent_completed_stat() -> bool {
        false
    }

    fn default_remove_peerless_torrents() -> bool {
        true
    }
}

/// Information required for loading config
#[derive(Debug, Default, Clone)]
pub struct Info {
    config_toml: Option<String>,
    config_toml_path: String,
}

impl Info {
    /// Build Configuration Info
    ///
    /// # Errors
    ///
    /// Will return `Err` if unable to obtain a configuration.
    ///
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(default_config_toml_path: String) -> Result<Self, Error> {
        let env_var_config_toml = ENV_VAR_CONFIG_TOML.to_string();
        let env_var_config_toml_path = ENV_VAR_CONFIG_TOML_PATH.to_string();

        let config_toml = if let Ok(config_toml) = env::var(env_var_config_toml) {
            println!("Loading extra configuration from environment variable:\n {config_toml}");
            Some(config_toml)
        } else {
            None
        };

        let config_toml_path = if let Ok(config_toml_path) = env::var(env_var_config_toml_path) {
            println!("Loading extra configuration from file: `{config_toml_path}` ...");
            config_toml_path
        } else {
            println!("Loading extra configuration from default configuration file: `{default_config_toml_path}` ...");
            default_config_toml_path
        };

        Ok(Self {
            config_toml,
            config_toml_path,
        })
    }
}

/// Announce policy
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy, Constructor)]
pub struct AnnouncePolicy {
    /// Interval in seconds that the client should wait between sending regular
    /// announce requests to the tracker.
    ///
    /// It's a **recommended** wait time between announcements.
    ///
    /// This is the standard amount of time that clients should wait between
    /// sending consecutive announcements to the tracker. This value is set by
    /// the tracker and is typically provided in the tracker's response to a
    /// client's initial request. It serves as a guideline for clients to know
    /// how often they should contact the tracker for updates on the peer list,
    /// while ensuring that the tracker is not overwhelmed with requests.
    #[serde(default = "AnnouncePolicy::default_interval")]
    pub interval: u32,

    /// Minimum announce interval. Clients must not reannounce more frequently
    /// than this.
    ///
    /// It establishes the shortest allowed wait time.
    ///
    /// This is an optional parameter in the protocol that the tracker may
    /// provide in its response. It sets a lower limit on the frequency at which
    /// clients are allowed to send announcements. Clients should respect this
    /// value to prevent sending too many requests in a short period, which
    /// could lead to excessive load on the tracker or even getting banned by
    /// the tracker for not adhering to the rules.
    #[serde(default = "AnnouncePolicy::default_interval_min")]
    pub interval_min: u32,
}

impl Default for AnnouncePolicy {
    fn default() -> Self {
        Self {
            interval: Self::default_interval(),
            interval_min: Self::default_interval_min(),
        }
    }
}

impl AnnouncePolicy {
    fn default_interval() -> u32 {
        120
    }

    fn default_interval_min() -> u32 {
        120
    }
}

/// Errors that can occur when loading the configuration.
#[derive(Error, Debug)]
pub enum Error {
    /// Unable to load the configuration from the environment variable.
    /// This error only occurs if there is no configuration file and the
    /// `TORRUST_TRACKER_CONFIG_TOML` environment variable is not set.
    #[error("Unable to load from Environmental Variable: {source}")]
    UnableToLoadFromEnvironmentVariable {
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },

    #[error("Unable to load from Config File: {source}")]
    UnableToLoadFromConfigFile {
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },

    /// Unable to load the configuration from the configuration file.
    #[error("Failed processing the configuration: {source}")]
    ConfigError {
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },

    #[error("The error for errors that can never happen.")]
    Infallible,

    #[error("Unsupported configuration version: {version}")]
    UnsupportedVersion { version: Version },

    #[error("Missing mandatory configuration option. Option path: {path}")]
    MissingMandatoryOption { path: String },
}

impl From<figment::Error> for Error {
    #[track_caller]
    fn from(err: figment::Error) -> Self {
        Self::ConfigError {
            source: (Arc::new(err) as DynError).into(),
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct TslConfig {
    /// Path to the SSL certificate file.
    #[serde(default = "TslConfig::default_ssl_cert_path")]
    pub ssl_cert_path: Utf8PathBuf,

    /// Path to the SSL key file.
    #[serde(default = "TslConfig::default_ssl_key_path")]
    pub ssl_key_path: Utf8PathBuf,
}

impl TslConfig {
    #[allow(clippy::unnecessary_wraps)]
    fn default_ssl_cert_path() -> Utf8PathBuf {
        Utf8PathBuf::new()
    }

    #[allow(clippy::unnecessary_wraps)]
    fn default_ssl_key_path() -> Utf8PathBuf {
        Utf8PathBuf::new()
    }
}
