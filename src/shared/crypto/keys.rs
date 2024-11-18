//! This module contains logic related to cryptographic keys.
//!
//! Specifically, it contains the logic for storing the seed and providing
//! it to other modules.
//!
//! It also provides the logic for the cipher for encryption and decryption.

use self::detail_cipher::CURRENT_CIPHER;
use self::detail_seed::CURRENT_SEED;
pub use crate::shared::crypto::ephemeral_instance_keys::CipherArrayBlowfish;
use crate::shared::crypto::ephemeral_instance_keys::{CipherBlowfish, Seed, RANDOM_CIPHER_BLOWFISH, RANDOM_SEED};

/// This trait is for structures that can keep and provide a seed.
pub trait Keeper {
    type Seed: Sized + Default + AsMut<[u8]>;
    type Cipher: cipher::BlockCipher;

    /// It returns a reference to the seed that is keeping.
    fn get_seed() -> &'static Self::Seed;
    fn get_cipher_blowfish() -> &'static Self::Cipher;
}

/// The keeper for the instance. When the application is running
/// in production, this will be the seed keeper that is used.
pub struct Instance;

/// The keeper for the current execution. It's a facade at compilation
/// time that will either be the instance seed keeper (with a randomly
/// generated key for production) or the zeroed seed keeper.
pub struct Current;

impl Keeper for Instance {
    type Seed = Seed;
    type Cipher = CipherBlowfish;

    fn get_seed() -> &'static Self::Seed {
        &RANDOM_SEED
    }

    fn get_cipher_blowfish() -> &'static Self::Cipher {
        &RANDOM_CIPHER_BLOWFISH
    }
}

impl Keeper for Current {
    type Seed = Seed;
    type Cipher = CipherBlowfish;

    #[allow(clippy::needless_borrow)]
    fn get_seed() -> &'static Self::Seed {
        &CURRENT_SEED
    }

    fn get_cipher_blowfish() -> &'static Self::Cipher {
        &CURRENT_CIPHER
    }
}

#[cfg(test)]
mod tests {

    use super::detail_seed::ZEROED_TEST_SEED;
    use super::{Current, Instance, Keeper};
    use crate::shared::crypto::ephemeral_instance_keys::{CipherBlowfish, Seed, ZEROED_TEST_CIPHER_BLOWFISH};

    pub struct ZeroedTest;

    impl Keeper for ZeroedTest {
        type Seed = Seed;
        type Cipher = CipherBlowfish;

        #[allow(clippy::needless_borrow)]
        fn get_seed() -> &'static Self::Seed {
            &ZEROED_TEST_SEED
        }

        fn get_cipher_blowfish() -> &'static Self::Cipher {
            &ZEROED_TEST_CIPHER_BLOWFISH
        }
    }

    #[test]
    fn the_default_seed_and_the_zeroed_seed_should_be_the_same_when_testing() {
        assert_eq!(Current::get_seed(), ZeroedTest::get_seed());
    }

    #[test]
    fn the_default_seed_and_the_instance_seed_should_be_different_when_testing() {
        assert_ne!(Current::get_seed(), Instance::get_seed());
    }
}

mod detail_seed {
    use crate::shared::crypto::ephemeral_instance_keys::Seed;

    #[allow(dead_code)]
    pub const ZEROED_TEST_SEED: Seed = [0u8; 32];

    #[cfg(test)]
    pub use ZEROED_TEST_SEED as CURRENT_SEED;

    #[cfg(not(test))]
    pub use crate::shared::crypto::ephemeral_instance_keys::RANDOM_SEED as CURRENT_SEED;

    #[cfg(test)]
    mod tests {
        use crate::shared::crypto::ephemeral_instance_keys::RANDOM_SEED;
        use crate::shared::crypto::keys::detail_seed::ZEROED_TEST_SEED;
        use crate::shared::crypto::keys::CURRENT_SEED;

        #[test]
        fn it_should_have_a_zero_test_seed() {
            assert_eq!(ZEROED_TEST_SEED, [0u8; 32]);
        }

        #[test]
        fn it_should_default_to_zeroed_seed_when_testing() {
            assert_eq!(CURRENT_SEED, ZEROED_TEST_SEED);
        }

        #[test]
        fn it_should_have_a_large_random_seed() {
            assert!(u128::from_ne_bytes((*RANDOM_SEED)[..16].try_into().unwrap()) > u128::from(u64::MAX));
            assert!(u128::from_ne_bytes((*RANDOM_SEED)[16..].try_into().unwrap()) > u128::from(u64::MAX));
        }
    }
}

mod detail_cipher {
    #[allow(unused_imports)]
    #[cfg(not(test))]
    pub use crate::shared::crypto::ephemeral_instance_keys::RANDOM_CIPHER_BLOWFISH as CURRENT_CIPHER;
    #[cfg(test)]
    pub use crate::shared::crypto::ephemeral_instance_keys::ZEROED_TEST_CIPHER_BLOWFISH as CURRENT_CIPHER;

    #[cfg(test)]
    mod tests {
        use cipher::BlockEncrypt;

        use crate::shared::crypto::ephemeral_instance_keys::{CipherArrayBlowfish, ZEROED_TEST_CIPHER_BLOWFISH};
        use crate::shared::crypto::keys::detail_cipher::CURRENT_CIPHER;

        #[test]
        fn it_should_default_to_zeroed_seed_when_testing() {
            let mut data: cipher::generic_array::GenericArray<u8, _> = CipherArrayBlowfish::from([0u8; 8]);
            let mut data_2 = CipherArrayBlowfish::from([0u8; 8]);

            CURRENT_CIPHER.encrypt_block(&mut data);
            ZEROED_TEST_CIPHER_BLOWFISH.encrypt_block(&mut data_2);

            assert_eq!(data, data_2);
        }
    }
}
