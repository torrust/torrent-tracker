//! Version `1` for [Torrust Tracker](https://docs.rs/torrust-tracker)
//! configuration data structures.
//!
//! This module contains the configuration data structures for the
//! Torrust Tracker, which is a `BitTorrent` tracker server.
//!
//! The configuration is loaded from a [TOML](https://toml.io/en/) file
//! `tracker.toml` in the project root folder or from an environment variable
//! with the same content as the file.
//!
//! Configuration can not only be loaded from a file, but also from an
//! environment variable `TORRUST_TRACKER_CONFIG_TOML`. This is useful when running
//! the tracker in a Docker container or environments where you do not have a
//! persistent storage or you cannot inject a configuration file. Refer to
//! [`Torrust Tracker documentation`](https://docs.rs/torrust-tracker) for more
//! information about how to pass configuration to the tracker.
//!
//! When you run the tracker without providing the configuration via a file or
//! env var, the default configuration is used.
//!
//! # Table of contents
//!
//! - [Sections](#sections)
//! - [Port binding](#port-binding)
//! - [TSL support](#tsl-support)
//!     - [Generating self-signed certificates](#generating-self-signed-certificates)
//! - [Default configuration](#default-configuration)
//!
//! ## Sections
//!
//! Each section in the toml structure is mapped to a data structure. For
//! example, the `[http_api]` section (configuration for the tracker HTTP API)
//! is mapped to the [`HttpApi`] structure.
//!
//! > **NOTICE**: some sections are arrays of structures. For example, the
//! > `[[udp_trackers]]` section is an array of [`UdpTracker`] since
//! > you can have multiple running UDP trackers bound to different ports.
//!
//! Please refer to the documentation of each structure for more information
//! about each section.
//!
//! - [`Core configuration`](crate::v2_0_0::Configuration)
//! - [`HTTP API configuration`](crate::v2_0_0::tracker_api::HttpApi)
//! - [`HTTP Tracker configuration`](crate::v2_0_0::http_tracker::HttpTracker)
//! - [`UDP Tracker configuration`](crate::v2_0_0::udp_tracker::UdpTracker)
//! - [`Health Check API configuration`](crate::v2_0_0::health_check_api::HealthCheckApi)
//!
//! ## Port binding
//!
//! For the API, HTTP and UDP trackers you can bind to a random port by using
//! port `0`. For example, if you want to bind to a random port on all
//! interfaces, use `0.0.0.0:0`. The OS will choose a random free port.
//!
//! ## TSL support
//!
//! For the API and HTTP tracker you can enable TSL by setting `ssl_enabled` to
//! `true` and setting the paths to the certificate and key files.
//!
//! Typically, you will have a `storage` directory like the following:
//!
//! ```text
//! storage/
//! ├── config.toml
//! └── tracker
//!     ├── etc
//!     │   └── tracker.toml
//!     ├── lib
//!     │   ├── database
//!     │   │   ├── sqlite3.db
//!     │   │   └── sqlite.db
//!     │   └── tls
//!     │       ├── localhost.crt
//!     │       └── localhost.key
//!     └── log
//! ```
//!
//! where the application stores all the persistent data.
//!
//! Alternatively, you could setup a reverse proxy like Nginx or Apache to
//! handle the SSL/TLS part and forward the requests to the tracker. If you do
//! that, you should set [`on_reverse_proxy`](crate::v2_0_0::network::Network::on_reverse_proxy)
//! to `true` in the configuration file. It's out of scope for this
//! documentation to explain in detail how to setup a reverse proxy, but the
//! configuration file should be something like this:
//!
//! For [NGINX](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/):
//!
//! ```text
//! # HTTPS only (with SSL - force redirect to HTTPS)
//!
//! server {
//!     listen 80;
//!     server_name tracker.torrust.com;
//!
//!     return 301 https://$host$request_uri;
//! }
//!
//! server {
//!     listen 443;
//!     server_name tracker.torrust.com;
//!
//!     ssl_certificate CERT_PATH
//!     ssl_certificate_key CERT_KEY_PATH;
//!
//!     location / {
//!         proxy_set_header X-Forwarded-For $remote_addr;
//!         proxy_pass http://127.0.0.1:6969;
//!     }
//! }
//! ```
//!
//! For [Apache](https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html):
//!
//! ```text
//! # HTTPS only (with SSL - force redirect to HTTPS)
//!
//! <VirtualHost *:80>
//!     ServerAdmin webmaster@tracker.torrust.com
//!     ServerName tracker.torrust.com
//!
//!     <IfModule mod_rewrite.c>
//!         RewriteEngine on
//!         RewriteCond %{HTTPS} off
//!         RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
//!     </IfModule>
//! </VirtualHost>
//!
//! <IfModule mod_ssl.c>
//!     <VirtualHost *:443>
//!         ServerAdmin webmaster@tracker.torrust.com
//!         ServerName tracker.torrust.com
//!
//!         <Proxy *>
//!             Order allow,deny
//!             Allow from all
//!         </Proxy>
//!
//!         ProxyPreserveHost On
//!         ProxyRequests Off
//!         AllowEncodedSlashes NoDecode
//!
//!         ProxyPass / http://localhost:3000/
//!         ProxyPassReverse / http://localhost:3000/
//!         ProxyPassReverse / http://tracker.torrust.com/
//!
//!         RequestHeader set X-Forwarded-Proto "https"
//!         RequestHeader set X-Forwarded-Port "443"
//!
//!         ErrorLog ${APACHE_LOG_DIR}/tracker.torrust.com-error.log
//!         CustomLog ${APACHE_LOG_DIR}/tracker.torrust.com-access.log combined
//!
//!         SSLCertificateFile CERT_PATH
//!         SSLCertificateKeyFile CERT_KEY_PATH
//!     </VirtualHost>
//! </IfModule>
//! ```
//!
//! ## Generating self-signed certificates
//!
//! For testing purposes, you can use self-signed certificates.
//!
//! Refer to [Let's Encrypt - Certificates for localhost](https://letsencrypt.org/docs/certificates-for-localhost/)
//! for more information.
//!
//! Running the following command will generate a certificate (`localhost.crt`)
//! and key (`localhost.key`) file in your current directory:
//!
//! ```s
//! openssl req -x509 -out localhost.crt -keyout localhost.key \
//!   -newkey rsa:2048 -nodes -sha256 \
//!   -subj '/CN=localhost' -extensions EXT -config <( \
//!    printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
//! ```
//!
//! You can then use the generated files in the configuration file:
//!
//! ```s
//! [[http_trackers]]
//! ...
//!
//! [http_trackers.tsl_config]
//! ssl_cert_path = "./storage/tracker/lib/tls/localhost.crt"
//! ssl_key_path = "./storage/tracker/lib/tls/localhost.key"
//!
//! [http_api]
//! ...
//!
//! [http_api.tsl_config]
//! ssl_cert_path = "./storage/tracker/lib/tls/localhost.crt"
//! ssl_key_path = "./storage/tracker/lib/tls/localhost.key"
//! ```
//!
//! ## Default configuration
//!
//! The default configuration is:
//!
//! ```toml
//! [logging]
//! threshold = "info"
//!
//! [core]
//! inactive_peer_cleanup_interval = 600
//! listed = false
//! private = false
//! tracker_usage_statistics = true
//!
//! [core.announce_policy]
//! interval = 120
//! interval_min = 120
//!
//! [core.database]
//! driver = "sqlite3"
//! path = "./storage/tracker/lib/database/sqlite3.db"
//!
//! [core.net]
//! external_ip = "0.0.0.0"
//! on_reverse_proxy = false
//!
//! [core.tracker_policy]
//! max_peer_timeout = 900
//! persistent_torrent_completed_stat = false
//! remove_peerless_torrents = true
//!
//! [http_api]
//! bind_address = "127.0.0.1:1212"
//!
//! [http_api.access_tokens]
//! admin = "MyAccessToken"
//! [health_check_api]
//! bind_address = "127.0.0.1:1313"
//!```
pub mod core;
pub mod database;
pub mod health_check_api;
pub mod http_tracker;
pub mod logging;
pub mod network;
pub mod tracker_api;
pub mod udp_tracker;

use std::fs;
use std::net::IpAddr;

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use logging::Logging;
use serde::{Deserialize, Serialize};

use self::core::Core;
use self::health_check_api::HealthCheckApi;
use self::http_tracker::HttpTracker;
use self::tracker_api::HttpApi;
use self::udp_tracker::UdpTracker;
use crate::validator::{SemanticValidationError, Validator};
use crate::{Error, Info, Metadata, Version};

/// This configuration version
const VERSION_2_0_0: &str = "2.0.0";

/// Prefix for env vars that overwrite configuration options.
const CONFIG_OVERRIDE_PREFIX: &str = "TORRUST_TRACKER_CONFIG_OVERRIDE_";

/// Path separator in env var names for nested values in configuration.
const CONFIG_OVERRIDE_SEPARATOR: &str = "__";

/// Core configuration for the tracker.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Default, Clone)]
pub struct Configuration {
    /// Configuration metadata.
    pub metadata: Metadata,

    /// Logging configuration
    pub logging: Logging,

    /// Core configuration.
    pub core: Core,

    /// The list of UDP trackers the tracker is running. Each UDP tracker
    /// represents a UDP server that the tracker is running and it has its own
    /// configuration.
    pub udp_trackers: Option<Vec<UdpTracker>>,

    /// The list of HTTP trackers the tracker is running. Each HTTP tracker
    /// represents a HTTP server that the tracker is running and it has its own
    /// configuration.
    pub http_trackers: Option<Vec<HttpTracker>>,

    /// The HTTP API configuration.
    pub http_api: Option<HttpApi>,

    /// The Health Check API configuration.
    pub health_check_api: HealthCheckApi,
}

impl Configuration {
    /// Returns the tracker public IP address id defined in the configuration,
    /// and `None` otherwise.
    #[must_use]
    pub fn get_ext_ip(&self) -> Option<IpAddr> {
        self.core.net.external_ip.as_ref().map(|external_ip| *external_ip)
    }

    /// Saves the default configuration at the given path.
    ///
    /// # Errors
    ///
    /// Will return `Err` if `path` is not a valid path or the configuration
    /// file cannot be created.
    pub fn create_default_configuration_file(path: &str) -> Result<Configuration, Error> {
        let config = Configuration::default();
        config.save_to_file(path)?;
        Ok(config)
    }

    /// Loads the configuration from the `Info` struct. The whole
    /// configuration in toml format is included in the `info.tracker_toml`
    /// string.
    ///
    /// Configuration provided via env var has priority over config file path.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the environment variable does not exist or has a bad configuration.
    pub fn load(info: &Info) -> Result<Configuration, Error> {
        // Load configuration provided by the user, prioritizing env vars
        let figment = if let Some(config_toml) = &info.config_toml {
            Figment::from(Toml::string(config_toml)).merge(Env::prefixed(CONFIG_OVERRIDE_PREFIX).split(CONFIG_OVERRIDE_SEPARATOR))
        } else {
            Figment::from(Toml::file(&info.config_toml_path))
                .merge(Env::prefixed(CONFIG_OVERRIDE_PREFIX).split(CONFIG_OVERRIDE_SEPARATOR))
        };

        // Make sure user has provided the mandatory options.
        Self::check_mandatory_options(&figment)?;

        // Fill missing options with default values.
        let figment = figment.join(Serialized::defaults(Configuration::default()));

        // Build final configuration.
        let config: Configuration = figment.extract()?;

        // Make sure the provided schema version matches this version.
        if config.metadata.schema_version != Version::new(VERSION_2_0_0) {
            return Err(Error::UnsupportedVersion {
                version: config.metadata.schema_version,
            });
        }

        Ok(config)
    }

    /// Some configuration options are mandatory. The tracker will panic if
    /// the user doesn't provide an explicit value for them from one of the
    /// configuration sources: TOML or ENV VARS.
    ///
    /// # Errors
    ///
    /// Will return an error if a mandatory configuration option is only
    /// obtained by default value (code), meaning the user hasn't overridden it.
    fn check_mandatory_options(figment: &Figment) -> Result<(), Error> {
        let mandatory_options = ["metadata.schema_version", "logging.threshold", "core.private", "core.listed"];

        for mandatory_option in mandatory_options {
            figment
                .find_value(mandatory_option)
                .map_err(|_err| Error::MissingMandatoryOption {
                    path: mandatory_option.to_owned(),
                })?;
        }

        Ok(())
    }

    /// Saves the configuration to the configuration file.
    ///
    /// # Errors
    ///
    /// Will return `Err` if `filename` does not exist or the user does not have
    /// permission to read it. Will also return `Err` if the configuration is
    /// not valid or cannot be encoded to TOML.
    ///
    /// # Panics
    ///
    /// Will panic if the configuration cannot be written into the file.
    pub fn save_to_file(&self, path: &str) -> Result<(), Error> {
        fs::write(path, self.to_toml()).expect("Could not write to file!");
        Ok(())
    }

    /// Encodes the configuration to TOML.
    ///
    /// # Panics
    ///
    /// Will panic if it can't be converted to TOML.
    #[must_use]
    fn to_toml(&self) -> String {
        // code-review: do we need to use Figment also to serialize into toml?
        toml::to_string(self).expect("Could not encode TOML value")
    }

    /// Encodes the configuration to JSON.
    ///
    /// # Panics
    ///
    /// Will panic if it can't be converted to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        // code-review: do we need to use Figment also to serialize into json?
        serde_json::to_string_pretty(self).expect("Could not encode JSON value")
    }

    /// Masks secrets in the configuration.
    #[must_use]
    pub fn mask_secrets(mut self) -> Self {
        self.core.database.mask_secrets();

        if let Some(ref mut api) = self.http_api {
            api.mask_secrets();
        }

        self
    }
}

impl Validator for Configuration {
    fn validate(&self) -> Result<(), SemanticValidationError> {
        self.core.validate()
    }
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr};

    use crate::v2_0_0::Configuration;
    use crate::Info;

    #[cfg(test)]
    fn default_config_toml() -> String {
        let config = r#"[metadata]
                                app = "torrust-tracker"
                                purpose = "configuration"
                                schema_version = "2.0.0"

                                [logging]
                                threshold = "info"

                                [core]
                                inactive_peer_cleanup_interval = 600
                                listed = false
                                private = false
                                tracker_usage_statistics = true

                                [core.announce_policy]
                                interval = 120
                                interval_min = 120

                                [core.database]
                                driver = "sqlite3"
                                path = "./storage/tracker/lib/database/sqlite3.db"

                                [core.net]
                                external_ip = "0.0.0.0"
                                on_reverse_proxy = false

                                [core.tracker_policy]
                                max_peer_timeout = 900
                                persistent_torrent_completed_stat = false
                                remove_peerless_torrents = true

                                [health_check_api]
                                bind_address = "127.0.0.1:1313"
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

        assert_eq!(
            configuration.core.net.external_ip,
            Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
        );
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

    #[test]
    fn configuration_should_use_the_default_values_when_only_the_mandatory_options_are_provided_by_the_user_via_toml_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "tracker.toml",
                r#"
                [metadata]
                schema_version = "2.0.0"

                [logging]
                threshold = "info"

                [core]
                listed = false
                private = false
            "#,
            )?;

            let info = Info {
                config_toml: None,
                config_toml_path: "tracker.toml".to_string(),
            };

            let configuration = Configuration::load(&info).expect("Could not load configuration from file");

            assert_eq!(configuration, Configuration::default());

            Ok(())
        });
    }

    #[test]
    fn configuration_should_use_the_default_values_when_only_the_mandatory_options_are_provided_by_the_user_via_toml_content() {
        figment::Jail::expect_with(|_jail| {
            let config_toml = r#"
                [metadata]
                schema_version = "2.0.0"

                [logging]
                threshold = "info"

                [core]
                listed = false
                private = false
            "#
            .to_string();

            let info = Info {
                config_toml: Some(config_toml),
                config_toml_path: String::new(),
            };

            let configuration = Configuration::load(&info).expect("Could not load configuration from file");

            assert_eq!(configuration, Configuration::default());

            Ok(())
        });
    }

    #[test]
    fn default_configuration_could_be_overwritten_from_a_single_env_var_with_toml_contents() {
        figment::Jail::expect_with(|_jail| {
            let config_toml = r#"
                [metadata]
                schema_version = "2.0.0"

                [logging]
                threshold = "info"

                [core]
                listed = false
                private = false

                [core.database]
                path = "OVERWRITTEN DEFAULT DB PATH"
            "#
            .to_string();

            let info = Info {
                config_toml: Some(config_toml),
                config_toml_path: String::new(),
            };

            let configuration = Configuration::load(&info).expect("Could not load configuration from file");

            assert_eq!(configuration.core.database.path, "OVERWRITTEN DEFAULT DB PATH".to_string());

            Ok(())
        });
    }

    #[test]
    fn default_configuration_could_be_overwritten_from_a_toml_config_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "tracker.toml",
                r#"
                [metadata]
                schema_version = "2.0.0"

                [logging]
                threshold = "info"

                [core]
                listed = false
                private = false

                [core.database]
                path = "OVERWRITTEN DEFAULT DB PATH"
            "#,
            )?;

            let info = Info {
                config_toml: None,
                config_toml_path: "tracker.toml".to_string(),
            };

            let configuration = Configuration::load(&info).expect("Could not load configuration from file");

            assert_eq!(configuration.core.database.path, "OVERWRITTEN DEFAULT DB PATH".to_string());

            Ok(())
        });
    }

    #[test]
    fn configuration_should_allow_to_overwrite_the_default_tracker_api_token_for_admin_with_an_env_var() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("TORRUST_TRACKER_CONFIG_OVERRIDE_HTTP_API__ACCESS_TOKENS__ADMIN", "NewToken");

            let info = Info {
                config_toml: Some(default_config_toml()),
                config_toml_path: String::new(),
            };

            let configuration = Configuration::load(&info).expect("Could not load configuration from file");

            assert_eq!(
                configuration.http_api.unwrap().access_tokens.get("admin"),
                Some("NewToken".to_owned()).as_ref()
            );

            Ok(())
        });
    }
}
