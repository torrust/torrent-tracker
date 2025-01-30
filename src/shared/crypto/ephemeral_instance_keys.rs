//! This module contains the ephemeral instance keys used by the application.
//!
//! They are ephemeral because they are generated at runtime when the
//! application starts and are not persisted anywhere.

use blowfish::BlowfishLE;
use cipher::generic_array::GenericArray;
use cipher::{BlockSizeUser, KeyInit};
use rand::rngs::ThreadRng;
use rand::Rng;

pub type Seed = [u8; 32];
pub type CipherBlowfish = BlowfishLE;
pub type CipherArrayBlowfish = GenericArray<u8, <CipherBlowfish as BlockSizeUser>::BlockSize>;

lazy_static! {
    /// The random static seed.
    pub static ref RANDOM_SEED: Seed = Rng::random(&mut ThreadRng::default());

    /// The random cipher from the seed.
    pub static ref RANDOM_CIPHER_BLOWFISH: CipherBlowfish = CipherBlowfish::new_from_slice(&Rng::random::<Seed>(&mut ThreadRng::default())).expect("it could not generate key");

    /// The constant cipher for testing.
    pub static ref ZEROED_TEST_CIPHER_BLOWFISH: CipherBlowfish = CipherBlowfish::new_from_slice(&[0u8; 32]).expect("it could not generate key");
}
