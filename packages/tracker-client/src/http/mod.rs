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

#[cfg(test)]
mod tests {
    use crate::http::percent_encode_byte_array;

    #[test]
    fn it_should_encode_a_20_byte_array() {
        assert_eq!(
            percent_encode_byte_array(&[
                0x3b, 0x24, 0x55, 0x04, 0xcf, 0x5f, 0x11, 0xbb, 0xdb, 0xe1, 0x20, 0x1c, 0xea, 0x6a, 0x6b, 0xf4, 0x5a, 0xee, 0x1b,
                0xc0,
            ]),
            "%3B%24U%04%CF%5F%11%BB%DB%E1%20%1C%EAjk%F4Z%EE%1B%C0"
        );
    }
}
