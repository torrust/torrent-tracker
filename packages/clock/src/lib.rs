//! Time related functions and types.
//!
//! It's usually a good idea to control where the time comes from
//! in an application so that it can be mocked for testing and it can be
//! controlled in production so we get the intended behavior without
//! relying on the specific time zone for the underlying system.
//!
//! Clocks use the type `DurationSinceUnixEpoch` which is a
//! `std::time::Duration` since the Unix Epoch (timestamp).
//!
//! ```text
//! Local time:     lun 2023-03-27 16:12:00 WEST
//! Universal time: lun 2023-03-27 15:12:00 UTC
//! Time zone:      Atlantic/Canary (WEST, +0100)
//! Timestamp:      1679929914
//! Duration:       1679929914.10167426
//! ```
//!
//! > **NOTICE**: internally the `Duration` is stores it's main unit as seconds in a `u64` and it will
//! > overflow in 584.9 billion years.
//!
//! > **NOTICE**: the timestamp does not depend on the time zone. That gives you
//! > the ability to use the clock regardless of the underlying system time zone
//! > configuration. See [Unix time Wikipedia entry](https://en.wikipedia.org/wiki/Unix_time).

pub mod clock;
pub mod conv;
pub mod static_time;

#[macro_use]
extern crate lazy_static;

/// This code needs to be copied into each crate.
/// Working version, for production.
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) type CurrentClock = clock::Working;

/// Stopped version, for testing.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) type CurrentClock = clock::Stopped;
