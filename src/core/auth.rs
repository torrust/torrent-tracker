//! Tracker authentication services and structs.
//!
//! This module contains functions to handle tracker keys.
//! Tracker keys are tokens used to authenticate the tracker clients when the tracker runs
//! in `private` or `private_listed` modes.
//!
//! There are services to [`generate`]  and [`verify`]  authentication keys.
//!
//! Authentication keys are used only by [`HTTP`](crate::servers::http) trackers. All keys have an expiration time, that means
//! they are only valid during a period of time. After that time the expiring key will no longer be valid.
//!
//! Keys are stored in this struct:
//!
//! ```rust,no_run
//! use torrust_tracker::core::auth::Key;
//! use torrust_tracker::shared::clock::DurationSinceUnixEpoch;
//!
//! pub struct ExpiringKey {
//!     /// Random 32-char string. For example: `YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ`
//!     pub key: Key,
//!     /// Timestamp, the key will be no longer valid after this timestamp
//!     pub valid_until: DurationSinceUnixEpoch,
//! }
//! ```
//!
//! You can generate a new key valid for `9999` seconds and `0` nanoseconds from the current time with the following:
//!
//! ```rust,no_run
//! use torrust_tracker::core::auth;
//! use std::time::Duration;
//!
//! let expiring_key = auth::generate(Duration::new(9999, 0));
//!
//! // And you can later verify it with:
//!
//! assert!(auth::verify(&expiring_key).is_ok());
//! ```

use std::panic::Location;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use derive_more::Display;
use log::debug;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use torrust_tracker_located_error::{DynError, LocatedError};

use crate::shared::bit_torrent::common::AUTH_KEY_LENGTH;
use crate::shared::clock::{convert_from_timestamp_to_datetime_utc, Current, DurationSinceUnixEpoch, Time, TimeNow};

#[must_use]
/// It generates a new random 32-char authentication [`ExpiringKey`]
///
/// # Panics
///
/// It would panic if the `lifetime: Duration` + Duration is more than `Duration::MAX`.
pub fn generate(lifetime: Duration) -> ExpiringKey {
    let random_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(AUTH_KEY_LENGTH)
        .map(char::from)
        .collect();

    debug!("Generated key: {}, valid for: {:?} seconds", random_id, lifetime);

    ExpiringKey {
        key: random_id.parse::<Key>().unwrap(),
        valid_until: Current::add(&lifetime).unwrap(),
    }
}

/// It verifies an [`ExpiringKey`]. It checks if the expiration date has passed.
///
/// # Errors
///
/// Will return `Error::KeyExpired` if `auth_key.valid_until` is past the `current_time`.
///
/// Will return `Error::KeyInvalid` if `auth_key.valid_until` is past the `None`.
pub fn verify(auth_key: &ExpiringKey) -> Result<(), Error> {
    let current_time: DurationSinceUnixEpoch = Current::now();

    if auth_key.valid_until < current_time {
        Err(Error::KeyExpired {
            location: Location::caller(),
        })
    } else {
        Ok(())
    }
}

/// An authentication key which has an expiration time.
/// After that time is will automatically become invalid.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct ExpiringKey {
    /// Random 32-char string. For example: `YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ`
    pub key: Key,
    /// Timestamp, the key will be no longer valid after this timestamp
    pub valid_until: DurationSinceUnixEpoch,
}

impl std::fmt::Display for ExpiringKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "key: `{}`, valid until `{}`", self.key, self.expiry_time())
    }
}

impl ExpiringKey {
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
    pub fn expiry_time(&self) -> chrono::DateTime<chrono::Utc> {
        convert_from_timestamp_to_datetime_utc(self.valid_until)
    }
}

/// A randomly generated token used for authentication.
///
/// It contains lower and uppercase letters and numbers.
/// It's a 32-char string.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Display, Hash)]
pub struct Key(String);

/// Error returned when a key cannot be parsed from a string.
///
/// ```rust,no_run
/// use torrust_tracker::core::auth::Key;
/// use std::str::FromStr;
///
/// let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
/// let key = Key::from_str(key_string);
///
/// assert!(key.is_ok());
/// assert_eq!(key.unwrap().to_string(), key_string);
/// ```
///
/// If the string does not contains a valid key, the parser function will return this error.
#[derive(Debug, PartialEq, Eq)]
pub struct ParseKeyError;

impl FromStr for Key {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != AUTH_KEY_LENGTH {
            return Err(ParseKeyError);
        }

        Ok(Self(s.to_string()))
    }
}

/// Verification error. Error returned when an [`ExpiringKey`] cannot be verified with the [`verify(...)`](crate::core::auth::verify) function.
///
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

        use crate::core::auth::Key;

        #[test]
        fn should_be_parsed_from_an_string() {
            let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
            let key = Key::from_str(key_string);

            assert!(key.is_ok());
            assert_eq!(key.unwrap().to_string(), key_string);
        }
    }

    mod expiring_auth_key {
        use std::str::FromStr;
        use std::time::Duration;

        use crate::core::auth;
        use crate::shared::clock::{Current, StoppedTime};

        #[test]
        fn should_be_parsed_from_an_string() {
            let key_string = "YZSl4lMZupRuOpSRC3krIKR5BPB14nrJ";
            let auth_key = auth::Key::from_str(key_string);

            assert!(auth_key.is_ok());
            assert_eq!(auth_key.unwrap().to_string(), key_string);
        }

        #[test]
        fn should_be_displayed() {
            // Set the time to the current time.
            Current::local_set_to_unix_epoch();

            let expiring_key = auth::generate(Duration::from_secs(0));

            assert_eq!(
                expiring_key.to_string(),
                format!("key: `{}`, valid until `1970-01-01 00:00:00 UTC`", expiring_key.key) // cspell:disable-line
            );
        }

        #[test]
        fn should_be_generated_with_a_expiration_time() {
            let expiring_key = auth::generate(Duration::new(9999, 0));

            assert!(auth::verify(&expiring_key).is_ok());
        }

        #[test]
        fn should_be_generate_and_verified() {
            // Set the time to the current time.
            Current::local_set_to_system_time_now();

            // Make key that is valid for 19 seconds.
            let expiring_key = auth::generate(Duration::from_secs(19));

            // Mock the time has passed 10 sec.
            Current::local_add(&Duration::from_secs(10)).unwrap();

            assert!(auth::verify(&expiring_key).is_ok());

            // Mock the time has passed another 10 sec.
            Current::local_add(&Duration::from_secs(10)).unwrap();

            assert!(auth::verify(&expiring_key).is_err());
        }
    }
}
