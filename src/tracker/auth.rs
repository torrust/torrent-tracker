use std::panic::Location;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use derive_more::Display;
use log::debug;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use torrust_tracker_located_error::LocatedError;

use crate::protocol::clock::{Current, DurationSinceUnixEpoch, Time, TimeNow};
use crate::protocol::common::AUTH_KEY_LENGTH;

#[must_use]
/// # Panics
///
/// It would panic if the `lifetime: Duration` + Duration is more than `Duration::MAX`.
pub fn generate(lifetime: Duration) -> Key {
    let key: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(AUTH_KEY_LENGTH)
        .map(char::from)
        .collect();

    debug!("Generated key: {}, valid for: {:?} seconds", key, lifetime);

    Key {
        key,
        valid_until: Some(Current::add(&lifetime).unwrap()),
    }
}

/// # Errors
///
/// Will return `Error::KeyExpired` if `auth_key.valid_until` is past the `current_time`.
///
/// Will return `Error::KeyInvalid` if `auth_key.valid_until` is past the `None`.
pub fn verify(auth_key: &Key) -> Result<(), Error> {
    let current_time: DurationSinceUnixEpoch = Current::now();

    match auth_key.valid_until {
        Some(valid_until) => {
            if valid_until < current_time {
                Err(Error::KeyExpired {
                    location: Location::caller(),
                })
            } else {
                Ok(())
            }
        }
        None => Err(Error::UnableToReadKey {
            location: Location::caller(),
            key: Box::new(auth_key.clone()),
        }),
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Key {
    // todo: replace key field definition with:
    // pub key: KeyId,
    pub key: String,
    pub valid_until: Option<DurationSinceUnixEpoch>,
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "key: `{}`, valid until `{}`",
            self.key,
            match self.valid_until {
                Some(duration) => format!(
                    "{}",
                    DateTime::<Utc>::from_utc(
                        NaiveDateTime::from_timestamp(
                            i64::try_from(duration.as_secs()).expect("Overflow of i64 seconds, very future!"),
                            duration.subsec_nanos(),
                        ),
                        Utc
                    )
                ),
                None => "Empty!?".to_string(),
            }
        )
    }
}

impl Key {
    #[must_use]
    pub fn from_buffer(key_buffer: [u8; AUTH_KEY_LENGTH]) -> Option<Key> {
        if let Ok(key) = String::from_utf8(Vec::from(key_buffer)) {
            Some(Key { key, valid_until: None })
        } else {
            None
        }
    }

    #[must_use]
    pub fn from_string(key: &str) -> Option<Key> {
        if key.len() == AUTH_KEY_LENGTH {
            Some(Key {
                key: key.to_string(),
                valid_until: None,
            })
        } else {
            None
        }
    }

    /// # Panics
    ///
    /// Will fail if the key id is not a valid key id.
    #[must_use]
    pub fn id(&self) -> KeyId {
        // todo: replace the type of field `key` with type `KeyId`.
        // The constructor should fail if an invalid KeyId is provided.
        KeyId::from_str(&self.key).unwrap()
    }
}

#[derive(Debug, Display, PartialEq, Clone)]
pub struct KeyId(String);

#[derive(Debug, PartialEq, Eq)]
pub struct ParseKeyIdError;

impl FromStr for KeyId {
    type Err = ParseKeyIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != AUTH_KEY_LENGTH {
            return Err(ParseKeyIdError);
        }

        Ok(Self(s.to_string()))
    }
}

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum Error {
    #[error("Key could not be verified: {source}")]
    KeyVerificationError {
        source: LocatedError<'static, dyn std::error::Error + Send + Sync>,
    },
    #[error("Failed to read key: {key}, {location}")]
    UnableToReadKey {
        location: &'static Location<'static>,
        key: Box<Key>,
    },
    #[error("Key has expired, {location}")]
    KeyExpired { location: &'static Location<'static> },
}

impl From<r2d2_sqlite::rusqlite::Error> for Error {
    fn from(e: r2d2_sqlite::rusqlite::Error) -> Self {
        Error::KeyVerificationError {
            source: (Arc::new(e) as Arc<dyn std::error::Error + Send + Sync>).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use crate::protocol::clock::{Current, StoppedTime};
    use crate::tracker::auth;

    #[test]
    fn auth_key_from_buffer() {
        let auth_key = auth::Key::from_buffer([
            89, 90, 83, 108, 52, 108, 77, 90, 117, 112, 82, 117, 79, 112, 83, 82, 67, 51, 107, 114, 73, 75, 82, 53, 66, 80, 66,
            49, 52, 110, 114, 74,
        ]);

        assert!(auth_key.is_some());
        assert_eq!(auth_key.unwrap().key, "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ");
    }

    #[test]
    fn auth_key_from_string() {
        let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
        let auth_key = auth::Key::from_string(key_string);

        assert!(auth_key.is_some());
        assert_eq!(auth_key.unwrap().key, key_string);
    }

    #[test]
    fn auth_key_id_from_string() {
        let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
        let auth_key_id = auth::KeyId::from_str(key_string);

        assert!(auth_key_id.is_ok());
        assert_eq!(auth_key_id.unwrap().to_string(), key_string);
    }

    #[test]
    fn generate_valid_auth_key() {
        let auth_key = auth::generate(Duration::new(9999, 0));

        assert!(auth::verify(&auth_key).is_ok());
    }

    #[test]
    fn generate_and_check_expired_auth_key() {
        // Set the time to the current time.
        Current::local_set_to_system_time_now();

        // Make key that is valid for 19 seconds.
        let auth_key = auth::generate(Duration::from_secs(19));

        // Mock the time has passed 10 sec.
        Current::local_add(&Duration::from_secs(10)).unwrap();

        assert!(auth::verify(&auth_key).is_ok());

        // Mock the time has passed another 10 sec.
        Current::local_add(&Duration::from_secs(10)).unwrap();

        assert!(auth::verify(&auth_key).is_err());
    }
}
