pub mod asserts;
pub mod asserts_warp;
pub mod client;
pub mod requests;
pub mod responses;
pub mod test_environment;

use percent_encoding::NON_ALPHANUMERIC;

pub type ByteArray20 = [u8; 20];

pub fn percent_encode_byte_array(bytes: &ByteArray20) -> String {
    percent_encoding::percent_encode(bytes, NON_ALPHANUMERIC).to_string()
}

pub struct InfoHash(ByteArray20);

impl InfoHash {
    pub fn new(vec: &[u8]) -> Self {
        let mut byte_array_20: ByteArray20 = Default::default();
        byte_array_20.clone_from_slice(vec);
        Self(byte_array_20)
    }

    pub fn bytes(&self) -> ByteArray20 {
        self.0
    }
}
