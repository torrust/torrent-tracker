use std::borrow::Cow;
use std::collections::BTreeMap;
use std::str;

use crate::access::bencode::{BMutAccess, BRefAccess, MutKind, RefKind};
use crate::access::dict::BDictAccess;
use crate::access::list::BListAccess;
use crate::mutable::encode;

/// Bencode object that holds references to the underlying data.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum Inner<'a> {
    /// Bencode Integer.
    Int(i64),
    /// Bencode Bytes.
    Bytes(Cow<'a, [u8]>),
    /// Bencode List.
    List(Vec<BencodeMut<'a>>),
    /// Bencode Dictionary.
    Dict(BTreeMap<Cow<'a, [u8]>, BencodeMut<'a>>),
}

/// `BencodeMut` object that stores references to some data.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct BencodeMut<'a> {
    inner: Inner<'a>,
}

impl<'a> BencodeMut<'a> {
    fn new(inner: Inner<'a>) -> BencodeMut<'a> {
        BencodeMut { inner }
    }

    /// Create a new `BencodeMut` representing an `i64`.
    #[must_use]
    pub fn new_int(value: i64) -> BencodeMut<'a> {
        BencodeMut::new(Inner::Int(value))
    }

    /// Create a new `BencodeMut` representing a `[u8]`.
    #[must_use]
    pub fn new_bytes(value: Cow<'a, [u8]>) -> BencodeMut<'a> {
        BencodeMut::new(Inner::Bytes(value))
    }

    /// Create a new `BencodeMut` representing a `BListAccess`.
    #[must_use]
    pub fn new_list() -> BencodeMut<'a> {
        BencodeMut::new(Inner::List(Vec::new()))
    }

    /// Create a new `BencodeMut` representing a `BDictAccess`.
    #[must_use]
    pub fn new_dict() -> BencodeMut<'a> {
        BencodeMut::new(Inner::Dict(BTreeMap::new()))
    }

    /// Encode the `BencodeMut` into a buffer representing the bencode.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        encode::encode(self, &mut buffer);

        buffer
    }
}

impl<'a> BRefAccess for BencodeMut<'a> {
    type BKey = Cow<'a, [u8]>;
    type BType = BencodeMut<'a>;

    fn kind<'b>(&'b self) -> RefKind<'b, Cow<'a, [u8]>, BencodeMut<'a>> {
        match self.inner {
            Inner::Int(n) => RefKind::Int(n),
            Inner::Bytes(ref n) => RefKind::Bytes(n),
            Inner::List(ref n) => RefKind::List(n),
            Inner::Dict(ref n) => RefKind::Dict(n),
        }
    }

    fn str(&self) -> Option<&str> {
        let bytes = self.bytes()?;

        str::from_utf8(bytes).ok()
    }

    fn int(&self) -> Option<i64> {
        match self.inner {
            Inner::Int(n) => Some(n),
            _ => None,
        }
    }

    fn bytes(&self) -> Option<&[u8]> {
        match self.inner {
            Inner::Bytes(ref n) => Some(n.as_ref()),
            _ => None,
        }
    }

    fn list(&self) -> Option<&dyn BListAccess<BencodeMut<'a>>> {
        match self.inner {
            Inner::List(ref n) => Some(n),
            _ => None,
        }
    }

    fn dict(&self) -> Option<&dyn BDictAccess<Cow<'a, [u8]>, BencodeMut<'a>>> {
        match self.inner {
            Inner::Dict(ref n) => Some(n),
            _ => None,
        }
    }
}

impl<'a> BMutAccess for BencodeMut<'a> {
    fn kind_mut<'b>(&'b mut self) -> MutKind<'b, Cow<'a, [u8]>, BencodeMut<'a>> {
        match self.inner {
            Inner::Int(n) => MutKind::Int(n),
            Inner::Bytes(ref mut n) => MutKind::Bytes((*n).as_ref()),
            Inner::List(ref mut n) => MutKind::List(n),
            Inner::Dict(ref mut n) => MutKind::Dict(n),
        }
    }

    fn list_mut(&mut self) -> Option<&mut dyn BListAccess<BencodeMut<'a>>> {
        match self.inner {
            Inner::List(ref mut n) => Some(n),
            _ => None,
        }
    }

    fn dict_mut(&mut self) -> Option<&mut dyn BDictAccess<Cow<'a, [u8]>, BencodeMut<'a>>> {
        match self.inner {
            Inner::Dict(ref mut n) => Some(n),
            _ => None,
        }
    }
}

// impl<'a> From<BencodeRef<'a>> for BencodeMut<'a> {
//     fn from(value: BencodeRef<'a>) -> Self {
//         let inner = match value.kind() {
//             BencodeRefKind::Int(value) => InnerBencodeMut::Int(value),
//             BencodeRefKind::Bytes(value) => InnerBencodeMut::Bytes(Cow::Owned(Vec::from(value))),
//             BencodeRefKind::List(value) => {
//                 InnerBencodeMut::List(value.clone().into_iter().map(|b| BencodeMut::from(b.clone())).collect())
//             }
//             BencodeRefKind::Dict(value) => InnerBencodeMut::Dict(
//                 value
//                     .to_list()
//                     .into_iter()
//                     .map(|(key, value)| (Cow::Owned(Vec::from(*key)), BencodeMut::from(value.clone())))
//                     .collect(),
//             ),
//         };
//         BencodeMut { inner }
//     }
// }

#[cfg(test)]
mod test {
    use crate::access::bencode::BMutAccess;
    use crate::mutable::bencode_mut::BencodeMut;

    #[test]
    fn positive_int_encode() {
        let bencode_int = BencodeMut::new_int(-560);

        let int_bytes = b"i-560e"; // cspell:disable-line
        assert_eq!(&int_bytes[..], &bencode_int.encode()[..]);
    }

    #[test]
    fn positive_bytes_encode() {
        /* cspell:disable-next-line */
        let bencode_bytes = BencodeMut::new_bytes((&b"asdasd"[..]).into());

        let bytes_bytes = b"6:asdasd"; // cspell:disable-line
        assert_eq!(&bytes_bytes[..], &bencode_bytes.encode()[..]);
    }

    #[test]
    fn positive_empty_list_encode() {
        let bencode_list = BencodeMut::new_list();

        let list_bytes = b"le"; // cspell:disable-line
        assert_eq!(&list_bytes[..], &bencode_list.encode()[..]);
    }

    #[test]
    fn positive_nonempty_list_encode() {
        let mut bencode_list = BencodeMut::new_list();

        {
            let list_mut = bencode_list.list_mut().unwrap();
            list_mut.push(BencodeMut::new_int(56));
        }

        let list_bytes = b"li56ee"; // cspell:disable-line
        assert_eq!(&list_bytes[..], &bencode_list.encode()[..]);
    }

    #[test]
    fn positive_empty_dict_encode() {
        let bencode_dict = BencodeMut::new_dict();

        let dict_bytes = b"de"; // cspell:disable-line
        assert_eq!(&dict_bytes[..], &bencode_dict.encode()[..]);
    }

    #[test]
    fn positive_nonempty_dict_encode() {
        let mut bencode_dict = BencodeMut::new_dict();

        {
            let dict_mut = bencode_dict.dict_mut().unwrap();
            /* cspell:disable-next-line */
            dict_mut.insert((&b"asd"[..]).into(), BencodeMut::new_bytes((&b"asdasd"[..]).into()));
        }

        let dict_bytes = b"d3:asd6:asdasde"; // cspell:disable-line
        assert_eq!(&dict_bytes[..], &bencode_dict.encode()[..]);
    }
}
