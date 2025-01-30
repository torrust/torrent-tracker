//! Tracker authentication services and structs.
//!
//! This module contains functions to handle tracker keys.
//! Tracker keys are tokens used to authenticate the tracker clients when the tracker runs
//! in `private` or `private_listed` modes.
//!
//! There are services to [`generate_key`]  and [`verify_key_expiration`]  authentication keys.
//!
//! Authentication keys are used only by [`HTTP`](crate::servers::http) trackers. All keys have an expiration time, that means
//! they are only valid during a period of time. After that time the expiring key will no longer be valid.
//!
//! Keys are stored in this struct:
//!
//! ```rust,no_run
//! use bittorrent_tracker_core::authentication::Key;
//! use torrust_tracker_primitives::DurationSinceUnixEpoch;
//!
//! pub struct PeerKey {
//!     /// Random 32-char string. For example: `YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ`
//!     pub key: Key,
//!
//!     /// Timestamp, the key will be no longer valid after this timestamp.
//!     /// If `None` the keys will not expire (permanent key).
//!     pub valid_until: Option<DurationSinceUnixEpoch>,
//! }
//! ```
//!
//! You can generate a new key valid for `9999` seconds and `0` nanoseconds from the current time with the following:
//!
//! ```rust,no_run
//! use bittorrent_tracker_core::authentication;
//! use std::time::Duration;
//!
//! let expiring_key = authentication::key::generate_key(Some(Duration::new(9999, 0)));
//!
//! // And you can later verify it with:
//!
//! assert!(authentication::key::verify_key_expiration(&expiring_key).is_ok());
//! ```
pub mod repository;

use std::panic::Location;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use derive_more::Display;
use rand::distr::Alphanumeric;
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use torrust_tracker_clock::clock::Time;
use torrust_tracker_clock::conv::convert_from_timestamp_to_datetime_utc;
use torrust_tracker_located_error::{DynError, LocatedError};
use torrust_tracker_primitives::DurationSinceUnixEpoch;

use crate::CurrentClock;

/// HTTP tracker authentication key length.
///
/// For more information see function [`generate_key`](crate::authentication::key::generate_key) to generate the
/// [`PeerKey`](crate::authentication::PeerKey).
pub const AUTH_KEY_LENGTH: usize = 32;

/// It generates a new permanent random key [`PeerKey`].
#[must_use]
pub fn generate_permanent_key() -> PeerKey {
    generate_key(None)
}

/// It generates a new random 32-char authentication [`PeerKey`].
///
/// It can be an expiring or permanent key.
///
/// # Panics
///
/// It would panic if the `lifetime: Duration` + Duration is more than `Duration::MAX`.
///
/// # Arguments
///
/// * `lifetime`: if `None` the key will be permanent.
#[must_use]
pub fn generate_key(lifetime: Option<Duration>) -> PeerKey {
    let random_id: String = rng()
        .sample_iter(&Alphanumeric)
        .take(AUTH_KEY_LENGTH)
        .map(char::from)
        .collect();

    if let Some(lifetime) = lifetime {
        tracing::debug!("Generated key: {}, valid for: {:?} seconds", random_id, lifetime);

        PeerKey {
            key: random_id.parse::<Key>().unwrap(),
            valid_until: Some(CurrentClock::now_add(&lifetime).unwrap()),
        }
    } else {
        tracing::debug!("Generated key: {}, permanent", random_id);

        PeerKey {
            key: random_id.parse::<Key>().unwrap(),
            valid_until: None,
        }
    }
}

/// It verifies an [`PeerKey`]. It checks if the expiration date has passed.
/// Permanent keys without duration (`None`) do not expire.
///
/// # Errors
///
/// Will return:
///
/// - `Error::KeyExpired` if `auth_key.valid_until` is past the `current_time`.
/// - `Error::KeyInvalid` if `auth_key.valid_until` is past the `None`.
pub fn verify_key_expiration(auth_key: &PeerKey) -> Result<(), Error> {
    let current_time: DurationSinceUnixEpoch = CurrentClock::now();

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
        None => Ok(()), // Permanent key
    }
}

/// An authentication key which can potentially have an expiration time.
/// After that time is will automatically become invalid.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct PeerKey {
    /// Random 32-char string. For example: `YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ`
    pub key: Key,

    /// Timestamp, the key will be no longer valid after this timestamp.
    /// If `None` the keys will not expire (permanent key).
    pub valid_until: Option<DurationSinceUnixEpoch>,
}

impl std::fmt::Display for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.expiry_time() {
            Some(expire_time) => write!(f, "key: `{}`, valid until `{}`", self.key, expire_time),
            None => write!(f, "key: `{}`, permanent", self.key),
        }
    }
}

impl PeerKey {
    #[must_use]
    pub fn key(&self) -> Key {
        self.key.clone()
    }

    /// It returns the expiry time. For example, for the starting time for Unix Epoch
    /// (timestamp 0) it will return a `DateTime` whose string representation is
    /// `1970-01-01 00:00:00 UTC`.
    ///
    /// # Panics
    ///
    /// Will panic when the key timestamp overflows the internal i64 type.
    /// (this will naturally happen in 292.5 billion years)
    #[must_use]
    pub fn expiry_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.valid_until.map(convert_from_timestamp_to_datetime_utc)
    }
}

/// A token used for authentication.
///
/// - It contains only ascii alphanumeric chars: lower and uppercase letters and
///   numbers.
/// - It's a 32-char string.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Display, Hash)]
pub struct Key(String);

impl Key {
    /// # Errors
    ///
    /// Will return an error is the string represents an invalid key.
    /// Valid keys can only contain 32 chars including 0-9, a-z and A-Z.
    pub fn new(value: &str) -> Result<Self, ParseKeyError> {
        if value.len() != AUTH_KEY_LENGTH {
            return Err(ParseKeyError::InvalidKeyLength);
        }

        if !value.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(ParseKeyError::InvalidChars);
        }

        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Error returned when a key cannot be parsed from a string.
///
/// ```text
/// use bittorrent_tracker_core::authentication::Key;
/// use std::str::FromStr;
///
/// let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
/// let key = Key::from_str(key_string);
///
/// assert!(key.is_ok());
/// assert_eq!(key.unwrap().to_string(), key_string);
/// ```
///
/// If the string does not contains a valid key, the parser function will return
/// this error.
#[derive(Debug, Error)]
pub enum ParseKeyError {
    #[error("Invalid key length. Key must be have 32 chars")]
    InvalidKeyLength,
    #[error("Invalid chars for key. Key can only alphanumeric chars (0-9, a-z, A-Z)")]
    InvalidChars,
}

impl FromStr for Key {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Key::new(s)?;
        Ok(Self(s.to_string()))
    }
}

/// Verification error. Error returned when an [`PeerKey`] cannot be
/// verified with the (`crate::authentication::verify_key`) function.
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
            source: (Arc::new(e) as DynError).into(),
        }
    }
}

#[cfg(test)]
mod tests {

    mod key {
        use std::str::FromStr;

        use crate::authentication::Key;

        #[test]
        fn should_be_parsed_from_an_string() {
            let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
            let key = Key::from_str(key_string);

            assert!(key.is_ok());
            assert_eq!(key.unwrap().to_string(), key_string);
        }

        #[test]
        fn length_should_be_32() {
            let key = Key::new("");
            assert!(key.is_err());

            let string_longer_than_32 = "012345678901234567890123456789012"; // DevSkim: ignore  DS173237
            let key = Key::new(string_longer_than_32);
            assert!(key.is_err());
        }

        #[test]
        fn should_only_include_alphanumeric_chars() {
            let key = Key::new("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
            assert!(key.is_err());
        }
    }

    mod expiring_auth_key {
        use std::str::FromStr;
        use std::time::Duration;

        use torrust_tracker_clock::clock;
        use torrust_tracker_clock::clock::stopped::Stopped as _;

        use crate::authentication;

        #[test]
        fn should_be_parsed_from_an_string() {
            let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
            let auth_key = authentication::Key::from_str(key_string);

            assert!(auth_key.is_ok());
            assert_eq!(auth_key.unwrap().to_string(), key_string);
        }

        #[test]
        fn should_be_displayed() {
            // Set the time to the current time.
            clock::Stopped::local_set_to_unix_epoch();

            let expiring_key = authentication::key::generate_key(Some(Duration::from_secs(0)));

            assert_eq!(
                expiring_key.to_string(),
                format!("key: `{}`, valid until `1970-01-01 00:00:00 UTC`", expiring_key.key) // cspell:disable-line
            );
        }

        #[test]
        fn should_be_generated_with_a_expiration_time() {
            let expiring_key = authentication::key::generate_key(Some(Duration::new(9999, 0)));

            assert!(authentication::key::verify_key_expiration(&expiring_key).is_ok());
        }

        #[test]
        fn should_be_generate_and_verified() {
            // Set the time to the current time.
            clock::Stopped::local_set_to_system_time_now();

            // Make key that is valid for 19 seconds.
            let expiring_key = authentication::key::generate_key(Some(Duration::from_secs(19)));

            // Mock the time has passed 10 sec.
            clock::Stopped::local_add(&Duration::from_secs(10)).unwrap();

            assert!(authentication::key::verify_key_expiration(&expiring_key).is_ok());

            // Mock the time has passed another 10 sec.
            clock::Stopped::local_add(&Duration::from_secs(10)).unwrap();

            assert!(authentication::key::verify_key_expiration(&expiring_key).is_err());
        }
    }
}
