pub mod client;

use percent_encoding::NON_ALPHANUMERIC;

pub type ByteArray20 = [u8; 20];

#[must_use]
pub fn percent_encode_byte_array(bytes: &ByteArray20) -> String {
    percent_encoding::percent_encode(bytes, NON_ALPHANUMERIC).to_string()
}

pub struct InfoHash(ByteArray20);

impl InfoHash {
    #[must_use]
    pub fn new(vec: &[u8]) -> Self {
        let mut byte_array_20: ByteArray20 = Default::default();
        byte_array_20.clone_from_slice(vec);
        Self(byte_array_20)
    }

    #[must_use]
    pub fn bytes(&self) -> ByteArray20 {
        self.0
    }
}
