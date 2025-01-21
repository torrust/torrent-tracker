//! API resources for the [`auth_key`](crate::servers::apis::v1::context::auth_key) API context.

use serde::{Deserialize, Serialize};
use torrust_tracker_clock::conv::convert_from_iso_8601_to_timestamp;

use crate::core::authentication::{self, Key};

/// A resource that represents an authentication key.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AuthKey {
    /// The authentication key.
    pub key: String,
    /// The timestamp when the key will expire.
    #[deprecated(since = "3.0.0", note = "please use `expiry_time` instead")]
    pub valid_until: Option<u64>, // todo: remove when the torrust-index-backend starts using the `expiry_time` attribute.
    /// The ISO 8601 timestamp when the key will expire.
    pub expiry_time: Option<String>,
}

impl From<AuthKey> for authentication::PeerKey {
    fn from(auth_key_resource: AuthKey) -> Self {
        authentication::PeerKey {
            key: auth_key_resource.key.parse::<Key>().unwrap(),
            valid_until: auth_key_resource
                .expiry_time
                .map(|expiry_time| convert_from_iso_8601_to_timestamp(&expiry_time)),
        }
    }
}

#[allow(deprecated)]
impl From<authentication::PeerKey> for AuthKey {
    fn from(auth_key: authentication::PeerKey) -> Self {
        match (auth_key.valid_until, auth_key.expiry_time()) {
            (Some(valid_until), Some(expiry_time)) => AuthKey {
                key: auth_key.key.to_string(),
                valid_until: Some(valid_until.as_secs()),
                expiry_time: Some(expiry_time.to_string()),
            },
            _ => AuthKey {
                key: auth_key.key.to_string(),
                valid_until: None,
                expiry_time: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use torrust_tracker_clock::clock::stopped::Stopped as _;
    use torrust_tracker_clock::clock::{self, Time};

    use super::AuthKey;
    use crate::core::authentication::{self, Key};
    use crate::CurrentClock;

    struct TestTime {
        pub timestamp: u64,
        pub iso_8601_v1: String,
        pub iso_8601_v2: String,
    }

    fn one_hour_after_unix_epoch() -> TestTime {
        let timestamp = 60_u64;
        let iso_8601_v1 = "1970-01-01T00:01:00.000Z".to_string();
        let iso_8601_v2 = "1970-01-01 00:01:00 UTC".to_string();
        TestTime {
            timestamp,
            iso_8601_v1,
            iso_8601_v2,
        }
    }

    #[test]
    #[allow(deprecated)]
    fn it_should_be_convertible_into_an_auth_key() {
        clock::Stopped::local_set_to_unix_epoch();

        let auth_key_resource = AuthKey {
            key: "IaWDneuFNZi8IB4MPA3qW1CD0M30EZSM".to_string(), // cspell:disable-line
            valid_until: Some(one_hour_after_unix_epoch().timestamp),
            expiry_time: Some(one_hour_after_unix_epoch().iso_8601_v1),
        };

        assert_eq!(
            authentication::PeerKey::from(auth_key_resource),
            authentication::PeerKey {
                key: "IaWDneuFNZi8IB4MPA3qW1CD0M30EZSM".parse::<Key>().unwrap(), // cspell:disable-line
                valid_until: Some(CurrentClock::now_add(&Duration::new(one_hour_after_unix_epoch().timestamp, 0)).unwrap())
            }
        );
    }

    #[test]
    #[allow(deprecated)]
    fn it_should_be_convertible_from_an_auth_key() {
        clock::Stopped::local_set_to_unix_epoch();

        let auth_key = authentication::PeerKey {
            key: "IaWDneuFNZi8IB4MPA3qW1CD0M30EZSM".parse::<Key>().unwrap(), // cspell:disable-line
            valid_until: Some(CurrentClock::now_add(&Duration::new(one_hour_after_unix_epoch().timestamp, 0)).unwrap()),
        };

        assert_eq!(
            AuthKey::from(auth_key),
            AuthKey {
                key: "IaWDneuFNZi8IB4MPA3qW1CD0M30EZSM".to_string(), // cspell:disable-line
                valid_until: Some(one_hour_after_unix_epoch().timestamp),
                expiry_time: Some(one_hour_after_unix_epoch().iso_8601_v2),
            }
        );
    }

    #[test]
    #[allow(deprecated)]
    fn it_should_be_convertible_into_json() {
        assert_eq!(
            serde_json::to_string(&AuthKey {
                key: "IaWDneuFNZi8IB4MPA3qW1CD0M30EZSM".to_string(), // cspell:disable-line
                valid_until: Some(one_hour_after_unix_epoch().timestamp),
                expiry_time: Some(one_hour_after_unix_epoch().iso_8601_v1),
            })
            .unwrap(),
            "{\"key\":\"IaWDneuFNZi8IB4MPA3qW1CD0M30EZSM\",\"valid_until\":60,\"expiry_time\":\"1970-01-01T00:01:00.000Z\"}" // cspell:disable-line
        );
    }
}
