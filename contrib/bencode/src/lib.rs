//! Library for parsing and converting bencoded data.
//!
//! # Examples
//!
//! Decoding bencoded data:
//!
//! ```rust
//!     extern crate torrust_tracker_contrib_bencode;
//!
//!     use torrust_tracker_contrib_bencode::{BencodeRef, BRefAccess, BDecodeOpt};
//!
//!     fn main() {
//!         let data = b"d12:lucky_numberi7ee"; // cspell:disable-line
//!         let bencode = BencodeRef::decode(data, BDecodeOpt::default()).unwrap();
//!
//!         assert_eq!(7, bencode.dict().unwrap().lookup("lucky_number".as_bytes())
//!             .unwrap().int().unwrap());
//!     }
//! ```
//!
//! Encoding bencoded data:
//!
//! ```rust
//!     #[macro_use]
//!     extern crate torrust_tracker_contrib_bencode;
//!
//!     fn main() {
//!         let message = (ben_map!{
//!             "lucky_number" => ben_int!(7),
//!             "lucky_string" => ben_bytes!("7")
//!         }).encode();
//!
//!         let data = b"d12:lucky_numberi7e12:lucky_string1:7e"; // cspell:disable-line
//!         assert_eq!(&data[..], &message[..]);
//!     }
//! ```

mod access;
mod cow;
mod error;
mod mutable;
mod reference;

/// Traits for implementation functionality.
pub mod inner {
    pub use crate::cow::BCowConvert;
}

/// Traits for extended functionality.
pub mod ext {
    #[allow(clippy::module_name_repetitions)]
    pub use crate::access::bencode::BRefAccessExt;
    #[allow(clippy::module_name_repetitions)]
    pub use crate::access::convert::BConvertExt;
}

#[deprecated(since = "1.0.0", note = "use `MutKind` instead.")]
pub use crate::access::bencode::MutKind as BencodeMutKind;
#[deprecated(since = "1.0.0", note = "use `RefKind` instead.")]
pub use crate::access::bencode::RefKind as BencodeRefKind;
pub use crate::access::bencode::{BMutAccess, BRefAccess, MutKind, RefKind};
pub use crate::access::convert::BConvert;
pub use crate::access::dict::BDictAccess;
pub use crate::access::list::BListAccess;
pub use crate::error::{BencodeConvertError, BencodeConvertResult, BencodeParseError, BencodeParseResult};
pub use crate::mutable::bencode_mut::BencodeMut;
pub use crate::reference::bencode_ref::BencodeRef;
pub use crate::reference::decode_opt::BDecodeOpt;

const BEN_END: u8 = b'e';
const DICT_START: u8 = b'd';
const LIST_START: u8 = b'l';
const INT_START: u8 = b'i';

const BYTE_LEN_LOW: u8 = b'0';
const BYTE_LEN_HIGH: u8 = b'9';
const BYTE_LEN_END: u8 = b':';

/// Construct a `BencodeMut` map by supplying string references as keys and `BencodeMut` as values.
#[macro_export]
macro_rules! ben_map {
( $($key:expr => $val:expr),* ) => {
        {
            use $crate::{BMutAccess, BencodeMut};
            use $crate::inner::BCowConvert;

            let mut bencode_map = BencodeMut::new_dict();
            {
                let map = bencode_map.dict_mut().unwrap();
                $(
                    map.insert(BCowConvert::convert($key), $val);
                )*
            }

            bencode_map
        }
    }
}

/// Construct a `BencodeMut` list by supplying a list of `BencodeMut` values.
#[macro_export]
macro_rules! ben_list {
    ( $($ben:expr),* ) => {
        {
            use $crate::{BencodeMut, BMutAccess};

            let mut bencode_list = BencodeMut::new_list();
            {
                let list = bencode_list.list_mut().unwrap();
                $(
                    list.push($ben);
                )*
            }

            bencode_list
        }
    }
}

/// Construct `BencodeMut` bytes by supplying a type convertible to `Vec<u8>`.
#[macro_export]
macro_rules! ben_bytes {
    ( $ben:expr ) => {{
        use $crate::inner::BCowConvert;
        use $crate::BencodeMut;

        BencodeMut::new_bytes(BCowConvert::convert($ben))
    }};
}

/// Construct a `BencodeMut` integer by supplying an `i64`.
#[macro_export]
macro_rules! ben_int {
    ( $ben:expr ) => {{
        use $crate::BencodeMut;

        BencodeMut::new_int($ben)
    }};
}
