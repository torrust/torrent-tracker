use std::collections::BTreeMap;
use std::str;

use crate::access::bencode::{BRefAccess, BRefAccessExt, RefKind};
use crate::access::dict::BDictAccess;
use crate::access::list::BListAccess;
use crate::error::{BencodeParseError, BencodeParseResult};
use crate::reference::decode;
use crate::reference::decode_opt::BDecodeOpt;

/// Bencode object that holds references to the underlying data.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum Inner<'a> {
    /// Bencode Integer.
    Int(i64, &'a [u8]),
    /// Bencode Bytes.
    Bytes(&'a [u8], &'a [u8]),
    /// Bencode List.
    List(Vec<BencodeRef<'a>>, &'a [u8]),
    /// Bencode Dictionary.
    Dict(BTreeMap<&'a [u8], BencodeRef<'a>>, &'a [u8]),
}

impl<'a> From<Inner<'a>> for BencodeRef<'a> {
    fn from(val: Inner<'a>) -> Self {
        BencodeRef { inner: val }
    }
}

/// `BencodeRef` object that stores references to some buffer.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct BencodeRef<'a> {
    inner: Inner<'a>,
}

impl<'a> BencodeRef<'a> {
    /// Decode the given bytes into a `BencodeRef` using the given decode options.
    #[allow(clippy::missing_errors_doc)]
    pub fn decode(bytes: &'a [u8], opts: BDecodeOpt) -> BencodeParseResult<BencodeRef<'a>> {
        // Apply try so any errors return before the eof check
        let (bencode, end_pos) = decode::decode(bytes, 0, opts, 0)?;

        if end_pos != bytes.len() && opts.enforce_full_decode() {
            return Err(BencodeParseError::BytesEmpty { pos: end_pos });
        }

        Ok(bencode)
    }

    /// Get a byte slice of the current bencode byte representation.
    #[must_use]
    pub fn buffer(&self) -> &'a [u8] {
        #[allow(clippy::match_same_arms)]
        match self.inner {
            Inner::Int(_, buffer) => buffer,
            Inner::Bytes(_, buffer) => buffer,
            Inner::List(_, buffer) => buffer,
            Inner::Dict(_, buffer) => buffer,
        }
    }
}

impl<'a> BRefAccess for BencodeRef<'a> {
    type BKey = &'a [u8];
    type BType = BencodeRef<'a>;

    fn kind<'b>(&'b self) -> RefKind<'b, &'a [u8], BencodeRef<'a>> {
        match self.inner {
            Inner::Int(n, _) => RefKind::Int(n),
            Inner::Bytes(n, _) => RefKind::Bytes(n),
            Inner::List(ref n, _) => RefKind::List(n),
            Inner::Dict(ref n, _) => RefKind::Dict(n),
        }
    }

    fn str(&self) -> Option<&str> {
        self.str_ext()
    }

    fn int(&self) -> Option<i64> {
        match self.inner {
            Inner::Int(n, _) => Some(n),
            _ => None,
        }
    }

    fn bytes(&self) -> Option<&[u8]> {
        self.bytes_ext()
    }

    fn list(&self) -> Option<&dyn BListAccess<BencodeRef<'a>>> {
        match self.inner {
            Inner::List(ref n, _) => Some(n),
            _ => None,
        }
    }

    fn dict(&self) -> Option<&dyn BDictAccess<&'a [u8], BencodeRef<'a>>> {
        match self.inner {
            Inner::Dict(ref n, _) => Some(n),
            _ => None,
        }
    }
}

impl<'a> BRefAccessExt<'a> for BencodeRef<'a> {
    fn str_ext(&self) -> Option<&'a str> {
        let bytes = self.bytes_ext()?;

        str::from_utf8(bytes).ok()
    }

    fn bytes_ext(&self) -> Option<&'a [u8]> {
        match self.inner {
            Inner::Bytes(n, _) => Some(&n[0..]),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::access::bencode::BRefAccess;
    use crate::reference::bencode_ref::BencodeRef;
    use crate::reference::decode_opt::BDecodeOpt;

    #[test]
    fn positive_int_buffer() {
        let int_bytes = b"i-500e"; // cspell:disable-line
        let bencode = BencodeRef::decode(&int_bytes[..], BDecodeOpt::default()).unwrap();

        assert_eq!(int_bytes, bencode.buffer());
    }

    #[test]
    fn positive_bytes_buffer() {
        let bytes_bytes = b"3:asd"; // cspell:disable-line
        let bencode = BencodeRef::decode(&bytes_bytes[..], BDecodeOpt::default()).unwrap();

        assert_eq!(bytes_bytes, bencode.buffer());
    }

    #[test]
    fn positive_list_buffer() {
        let list_bytes = b"l3:asde"; // cspell:disable-line
        let bencode = BencodeRef::decode(&list_bytes[..], BDecodeOpt::default()).unwrap();

        assert_eq!(list_bytes, bencode.buffer());
    }

    #[test]
    fn positive_dict_buffer() {
        let dict_bytes = b"d3:asd3:asde"; // cspell:disable-line
        let bencode = BencodeRef::decode(&dict_bytes[..], BDecodeOpt::default()).unwrap();

        assert_eq!(dict_bytes, bencode.buffer());
    }

    #[test]
    fn positive_list_nested_int_buffer() {
        let nested_int_bytes = b"li-500ee"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_int_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_list = bencode.list().unwrap();
        let bencode_int = bencode_list.get(0).unwrap();

        let int_bytes = b"i-500e"; // cspell:disable-line
        assert_eq!(int_bytes, bencode_int.buffer());
    }

    #[test]
    fn positive_dict_nested_int_buffer() {
        let nested_int_bytes = b"d3:asdi-500ee"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_int_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_dict = bencode.dict().unwrap();
        /* cspell:disable-next-line */
        let bencode_int = bencode_dict.lookup(&b"asd"[..]).unwrap();

        let int_bytes = b"i-500e"; // cspell:disable-line
        assert_eq!(int_bytes, bencode_int.buffer());
    }

    #[test]
    fn positive_list_nested_bytes_buffer() {
        let nested_bytes_bytes = b"l3:asde"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_bytes_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_list = bencode.list().unwrap();
        let bencode_bytes = bencode_list.get(0).unwrap();

        let bytes_bytes = b"3:asd"; // cspell:disable-line
        assert_eq!(bytes_bytes, bencode_bytes.buffer());
    }

    #[test]
    fn positive_dict_nested_bytes_buffer() {
        let nested_bytes_bytes = b"d3:asd3:asde"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_bytes_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_dict = bencode.dict().unwrap();
        /* cspell:disable-next-line */
        let bencode_bytes = bencode_dict.lookup(&b"asd"[..]).unwrap();

        let bytes_bytes = b"3:asd"; // cspell:disable-line
        assert_eq!(bytes_bytes, bencode_bytes.buffer());
    }

    #[test]
    fn positive_list_nested_list_buffer() {
        let nested_list_bytes = b"ll3:asdee"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_list_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_list = bencode.list().unwrap();
        let bencode_list = bencode_list.get(0).unwrap();

        let list_bytes = b"l3:asde"; // cspell:disable-line
        assert_eq!(list_bytes, bencode_list.buffer());
    }

    #[test]
    fn positive_dict_nested_list_buffer() {
        let nested_list_bytes = b"d3:asdl3:asdee"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_list_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_dict = bencode.dict().unwrap();
        /* cspell:disable-next-line */
        let bencode_list = bencode_dict.lookup(&b"asd"[..]).unwrap();

        let list_bytes = b"l3:asde"; // cspell:disable-line
        assert_eq!(list_bytes, bencode_list.buffer());
    }

    #[test]
    fn positive_list_nested_dict_buffer() {
        let nested_dict_bytes = b"ld3:asd3:asdee"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_dict_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_list = bencode.list().unwrap();
        let bencode_dict = bencode_list.get(0).unwrap();

        let dict_bytes = b"d3:asd3:asde"; // cspell:disable-line
        assert_eq!(dict_bytes, bencode_dict.buffer());
    }

    #[test]
    fn positive_dict_nested_dict_buffer() {
        let nested_dict_bytes = b"d3:asdd3:asd3:asdee"; // cspell:disable-line
        let bencode = BencodeRef::decode(&nested_dict_bytes[..], BDecodeOpt::default()).unwrap();

        let bencode_dict = bencode.dict().unwrap();
        /* cspell:disable-next-line */
        let bencode_dict = bencode_dict.lookup(&b"asd"[..]).unwrap();

        let dict_bytes = b"d3:asd3:asde"; // cspell:disable-line
        assert_eq!(dict_bytes, bencode_dict.buffer());
    }
}
