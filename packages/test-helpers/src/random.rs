//! Random data generators for testing.
use rand::distr::Alphanumeric;
use rand::{rng, Rng};

/// Returns a random alphanumeric string of a certain size.
///
/// It is useful for generating random names, IDs, etc for testing.
pub fn string(size: usize) -> String {
    rng().sample_iter(&Alphanumeric).take(size).map(char::from).collect()
}
