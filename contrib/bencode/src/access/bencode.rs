use crate::access::dict::BDictAccess;
use crate::access::list::BListAccess;

/// Abstract representation of a `BencodeRef` object.
pub enum RefKind<'a, K, V> {
    /// Bencode Integer.
    Int(i64),
    /// Bencode Bytes.
    Bytes(&'a [u8]),
    /// Bencode List.
    List(&'a dyn BListAccess<V>),
    /// Bencode Dictionary.
    Dict(&'a dyn BDictAccess<K, V>),
}

/// Trait for read access to some bencode type.
pub trait BRefAccess: Sized {
    type BKey;
    type BType: BRefAccess<BKey = Self::BKey>;

    /// Access the bencode as a `BencodeRefKind`.
    fn kind(&self) -> RefKind<'_, Self::BKey, Self::BType>;

    /// Attempt to access the bencode as a `str`.
    fn str(&self) -> Option<&str>;

    /// Attempt to access the bencode as an `i64`.
    fn int(&self) -> Option<i64>;

    /// Attempt to access the bencode as an `[u8]`.
    fn bytes(&self) -> Option<&[u8]>;

    /// Attempt to access the bencode as an `BListAccess`.
    fn list(&self) -> Option<&dyn BListAccess<Self::BType>>;

    /// Attempt to access the bencode as an `BDictAccess`.
    fn dict(&self) -> Option<&dyn BDictAccess<Self::BKey, Self::BType>>;
}

/// Trait for extended read access to some bencode type.
///
/// Use this trait when you want to make sure that the lifetime of
/// the underlying buffers is tied to the lifetime of the backing
/// bencode buffer.
pub trait BRefAccessExt<'a>: BRefAccess {
    /// Attempt to access the bencode as a `str`.
    fn str_ext(&self) -> Option<&'a str>;

    /// Attempt to access the bencode as an `[u8]`.
    fn bytes_ext(&self) -> Option<&'a [u8]>;
}

impl<T> BRefAccess for &T
where
    T: BRefAccess,
{
    type BKey = T::BKey;
    type BType = T::BType;

    fn kind(&self) -> RefKind<'_, Self::BKey, Self::BType> {
        (*self).kind()
    }

    fn str(&self) -> Option<&str> {
        (*self).str()
    }

    fn int(&self) -> Option<i64> {
        (*self).int()
    }

    fn bytes(&self) -> Option<&[u8]> {
        (*self).bytes()
    }

    fn list(&self) -> Option<&dyn BListAccess<Self::BType>> {
        (*self).list()
    }

    fn dict(&self) -> Option<&dyn BDictAccess<Self::BKey, Self::BType>> {
        (*self).dict()
    }
}

impl<'a: 'b, 'b, T> BRefAccessExt<'a> for &'b T
where
    T: BRefAccessExt<'a>,
{
    fn str_ext(&self) -> Option<&'a str> {
        (*self).str_ext()
    }

    fn bytes_ext(&self) -> Option<&'a [u8]> {
        (*self).bytes_ext()
    }
}

/// Abstract representation of a `BencodeMut` object.
pub enum MutKind<'a, K, V> {
    /// Bencode Integer.
    Int(i64),
    /// Bencode Bytes.
    Bytes(&'a [u8]),
    /// Bencode List.
    List(&'a mut dyn BListAccess<V>),
    /// Bencode Dictionary.
    Dict(&'a mut dyn BDictAccess<K, V>),
}

/// Trait for write access to some bencode type.
pub trait BMutAccess: Sized + BRefAccess {
    /// Access the bencode as a `BencodeMutKind`.
    fn kind_mut(&mut self) -> MutKind<'_, Self::BKey, Self::BType>;

    /// Attempt to access the bencode as a mutable `BListAccess`.
    fn list_mut(&mut self) -> Option<&mut dyn BListAccess<Self::BType>>;

    /// Attempt to access the bencode as a mutable `BDictAccess`.
    fn dict_mut(&mut self) -> Option<&mut dyn BDictAccess<Self::BKey, Self::BType>>;
}
