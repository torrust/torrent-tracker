//! Module for Generating and Verifying Connection IDs (Cookies) in the UDP Tracker Protocol
//!
//! **Overview:**
//!
//! In the `BitTorrent` UDP tracker protocol, clients initiate communication by obtaining a connection ID from the server. This connection ID serves as a safeguard against IP spoofing and replay attacks, ensuring that only legitimate clients can interact with the tracker.
//!
//! To maintain a stateless server architecture, this module implements a method for generating and verifying connection IDs based on the client's fingerprint (typically derived from the client's IP address) and the time of issuance, without storing state on the server.
//!
//! The connection ID is an encrypted, opaque cookie held by the client. Since the same server that generates the cookie also validates it, endianness is not a concern.
//!
//! **Connection ID Generation Algorithm:**
//!
//! 1. **Issue Time (`issue_at`):**
//!    - Obtain a 64-bit floating-point number (`f64`), this number should be a normal number.
//!
//! 2. **Fingerprint:**
//!    - Use an 8-byte fingerprint unique to the client (e.g., derived from the client's IP address).
//!
//! 3. **Assemble Cookie Value:**
//!    - Interpret the bytes of `issue_at` as a 64-bit integer (`i64`) without altering the bit pattern.
//!    - Similarly, interpret the fingerprint bytes as an `i64`.
//!    - Compute the cookie value:
//!      ```rust,ignore
//!      let cookie_value = issue_at_i64.wrapping_add(fingerprint_i64);
//!      ```
//!      - *Note:* Wrapping addition handles potential integer overflows gracefully.
//!
//! 4. **Encrypt Cookie Value:**
//!    - Encrypt `cookie_value` using a symmetric block cipher obtained from `Current::get_cipher()`.
//!    - The encrypted `cookie_value` becomes the connection ID sent to the client.
//!
//! **Connection ID Verification Algorithm:**
//!
//! When a client sends a request with a connection ID, the server verifies it using the following steps:
//!
//! 1. **Decrypt Connection ID:**
//!    - Decrypt the received connection ID using the same cipher to retrieve `cookie_value`.
//!    - *Important:* The decryption is non-authenticated, meaning it does not verify the integrity or authenticity of the ciphertext. The decrypted `cookie_value` can be any byte sequence, including manipulated data.
//!
//! 2. **Recover Issue Time:**
//!    - Interpret the fingerprint bytes as `i64`.
//!    - Compute the issue time:
//!      ```rust,ignore
//!      let issue_at_i64 = cookie_value.wrapping_sub(fingerprint_i64);
//!      ```
//!      - *Note:* Wrapping subtraction handles potential integer underflows gracefully.
//!    - Reinterpret `issue_at_i64` bytes as an `f64` to get `issue_time`.
//!
//! 3. **Validate Issue Time:**
//!    - **Handling Arbitrary `issue_time` Values:**
//!        - Since the decrypted `cookie_value` may be arbitrary, `issue_time` can be any `f64` value, including special values like `NaN`, positive or negative infinity, and subnormal numbers.
//!    - **Validation Steps:**
//!        - **Step 1:** Check if `issue_time` is finite using `issue_time.is_finite()`.
//!            - If `issue_time` is `NaN` or infinite, it is considered invalid.
//!        - **Step 2:** If `issue_time` is finite, perform range checks:
//!            - Verify that `min <= issue_time <= max`.
//!    - If `issue_time` passes these checks, accept the connection ID; otherwise, reject it with an appropriate error.
//!
//! **Security Considerations:**
//!
//! - **Non-Authenticated Encryption:**
//!   - Due to protocol constraints (an 8-byte connection ID), using an authenticated encryption algorithm is not feasible.
//!   - As a result, attackers might attempt to forge or manipulate connection IDs.
//!   - However, the probability of an arbitrary 64-bit value decrypting to a valid `issue_time` within the acceptable range is extremely low, effectively serving as a form of authentication.
//!
//! - **Handling Special `f64` Values:**
//!   - By checking `issue_time.is_finite()`, the implementation excludes `NaN` and infinite values, ensuring that only valid, finite timestamps are considered.
//!
//! - **Probability of Successful Attack:**
//!   - Given the narrow valid time window (usually around 2 minutes) compared to the vast range of `f64` values, the chance of successfully guessing a valid `issue_time` is negligible.
//!
//! **Key Points:**
//!
//! - The server maintains a stateless design, reducing resource consumption and complexity.
//! - Wrapping arithmetic ensures that the addition and subtraction of `i64` values are safe from overflow or underflow issues.
//! - The validation process is robust against malformed or malicious connection IDs due to stringent checks on the deserialized `issue_time`.
//! - The module leverages existing cryptographic primitives while acknowledging and addressing the limitations imposed by the protocol's specifications.
//!

use aquatic_udp_protocol::ConnectionId as Cookie;
use cookie_builder::{assemble, decode, disassemble, encode};
use tracing::instrument;
use zerocopy::AsBytes;

use super::error::Error;
use crate::shared::crypto::keys::CipherArrayBlowfish;

/// Generates a new connection cookie.
///
/// # Errors
///
/// It would error if the supplied `issue_at` value is a zero, infinite, subnormal, or NaN.
///
/// # Panics
///
/// It would panic if the cookie is not exactly 8 bytes is size.
///
#[instrument(err)]
pub fn make(fingerprint: u64, issue_at: f64) -> Result<Cookie, Error> {
    if !issue_at.is_normal() {
        return Err(Error::CookieValueNotNormal {
            not_normal_value: issue_at,
        });
    }

    let cookie = assemble(fingerprint, issue_at);
    let cookie = encode(cookie);

    // using `read_from` as the array may be not correctly aligned
    Ok(zerocopy::FromBytes::read_from(cookie.as_slice()).expect("it should be the same size"))
}

use std::ops::Range;

/// Checks if the supplied `connection_cookie` is valid.
///
/// # Errors
///
/// It would error if the connection cookie is somehow invalid or expired.
///
/// # Panics
///
/// It would panic if the range start is not smaller than it's end.
#[instrument(err)]
pub fn check(cookie: &Cookie, fingerprint: u64, valid_range: Range<f64>) -> Result<f64, Error> {
    assert!(valid_range.start <= valid_range.end, "range start is larger than range end");

    let cookie_bytes = CipherArrayBlowfish::from_slice(cookie.0.as_bytes());
    let cookie_bytes = decode(*cookie_bytes);

    let issue_time = disassemble(fingerprint, cookie_bytes);

    if !issue_time.is_normal() {
        return Err(Error::CookieValueNotNormal {
            not_normal_value: issue_time,
        });
    }

    if issue_time < valid_range.start {
        return Err(Error::CookieValueExpired {
            expired_value: issue_time,
            min_value: valid_range.start,
        });
    }

    if issue_time > valid_range.end {
        return Err(Error::CookieValueFromFuture {
            future_value: issue_time,
            max_value: valid_range.end,
        });
    }

    Ok(issue_time)
}

mod cookie_builder {
    use cipher::{BlockDecrypt, BlockEncrypt};
    use tracing::instrument;
    use zerocopy::{byteorder, AsBytes as _, NativeEndian};

    pub type CookiePlainText = CipherArrayBlowfish;
    pub type CookieCipherText = CipherArrayBlowfish;

    use crate::shared::crypto::keys::{CipherArrayBlowfish, Current, Keeper};

    #[instrument()]
    pub(super) fn assemble(fingerprint: u64, issue_at: f64) -> CookiePlainText {
        let issue_at: byteorder::I64<NativeEndian> =
            *zerocopy::FromBytes::ref_from(&issue_at.to_ne_bytes()).expect("it should be aligned");
        let fingerprint: byteorder::I64<NativeEndian> =
            *zerocopy::FromBytes::ref_from(&fingerprint.to_ne_bytes()).expect("it should be aligned");

        let cookie = issue_at.get().wrapping_add(fingerprint.get());
        let cookie: byteorder::I64<NativeEndian> =
            *zerocopy::FromBytes::ref_from(&cookie.to_ne_bytes()).expect("it should be aligned");

        *CipherArrayBlowfish::from_slice(cookie.as_bytes())
    }

    #[instrument()]
    pub(super) fn disassemble(fingerprint: u64, cookie: CookiePlainText) -> f64 {
        let fingerprint: byteorder::I64<NativeEndian> =
            *zerocopy::FromBytes::ref_from(&fingerprint.to_ne_bytes()).expect("it should be aligned");

        // the array may be not aligned, so we read instead of reference.
        let cookie: byteorder::I64<NativeEndian> =
            zerocopy::FromBytes::read_from(cookie.as_bytes()).expect("it should be the same size");

        let issue_time_bytes = cookie.get().wrapping_sub(fingerprint.get()).to_ne_bytes();

        let issue_time: byteorder::F64<NativeEndian> =
            *zerocopy::FromBytes::ref_from(&issue_time_bytes).expect("it should be aligned");

        issue_time.get()
    }

    #[instrument()]
    pub(super) fn encode(mut cookie: CookiePlainText) -> CookieCipherText {
        let cipher = Current::get_cipher_blowfish();

        cipher.encrypt_block(&mut cookie);

        cookie
    }

    #[instrument()]
    pub(super) fn decode(mut cookie: CookieCipherText) -> CookiePlainText {
        let cipher = Current::get_cipher_blowfish();

        cipher.decrypt_block(&mut cookie);

        cookie
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_should_make_a_connection_cookie() {
        let fingerprint = 1_000_000;
        let issue_at = 1000.0;
        let cookie = make(fingerprint, issue_at).unwrap().0.get();

        // Expected connection ID derived through experimentation
        assert_eq!(cookie.to_le_bytes(), [10, 130, 175, 211, 244, 253, 230, 210]);
    }

    #[test]
    fn it_should_create_same_cookie_for_same_input() {
        let fingerprint = 1_000_000;
        let issue_at = 1000.0;
        let cookie1 = make(fingerprint, issue_at).unwrap();
        let cookie2 = make(fingerprint, issue_at).unwrap();

        assert_eq!(cookie1, cookie2);
    }

    #[test]
    fn it_should_create_different_cookies_for_different_fingerprints() {
        let fingerprint1 = 1_000_000;
        let fingerprint2 = 2_000_000;
        let issue_at = 1000.0;
        let cookie1 = make(fingerprint1, issue_at).unwrap();
        let cookie2 = make(fingerprint2, issue_at).unwrap();

        assert_ne!(cookie1, cookie2);
    }

    #[test]
    fn it_should_create_different_cookies_for_different_issue_times() {
        let fingerprint = 1_000_000;
        let issue_at1 = 1000.0;
        let issue_at2 = 2000.0;
        let cookie1 = make(fingerprint, issue_at1).unwrap();
        let cookie2 = make(fingerprint, issue_at2).unwrap();

        assert_ne!(cookie1, cookie2);
    }

    #[test]
    fn it_should_validate_a_valid_cookie() {
        let fingerprint = 1_000_000;
        let issue_at = 1_000_000_000_f64;
        let cookie = make(fingerprint, issue_at).unwrap();

        let min = issue_at - 10.0;
        let max = issue_at + 10.0;

        let result = check(&cookie, fingerprint, min..max).unwrap();

        // we should have exactly the same bytes returned
        assert_eq!(result.to_ne_bytes(), issue_at.to_ne_bytes());
    }

    #[test]
    fn it_should_reject_an_expired_cookie() {
        let fingerprint = 1_000_000;
        let issue_at = 1_000_000_000_f64;
        let cookie = make(fingerprint, issue_at).unwrap();

        let min = issue_at + 10.0;
        let max = issue_at + 20.0;

        let result = check(&cookie, fingerprint, min..max).unwrap_err();

        match result {
            Error::CookieValueExpired { .. } => {} // Expected error
            _ => panic!("Expected ConnectionIdExpired error"),
        }
    }

    #[test]
    fn it_should_reject_a_cookie_from_the_future() {
        let fingerprint = 1_000_000;
        let issue_at = 1_000_000_000_f64;

        let cookie = make(fingerprint, issue_at).unwrap();

        let min = issue_at - 20.0;
        let max = issue_at - 10.0;

        let result = check(&cookie, fingerprint, min..max).unwrap_err();

        match result {
            Error::CookieValueFromFuture { .. } => {} // Expected error
            _ => panic!("Expected ConnectionIdFromFuture error"),
        }
    }
}
