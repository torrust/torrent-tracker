use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::str;

use crate::error::{BencodeParseError, BencodeParseResult};
use crate::reference::bencode_ref::{BencodeRef, Inner};
use crate::reference::decode_opt::BDecodeOpt;

pub fn decode(bytes: &[u8], pos: usize, opts: BDecodeOpt, depth: usize) -> BencodeParseResult<(BencodeRef<'_>, usize)> {
    if depth >= opts.max_recursion() {
        return Err(BencodeParseError::InvalidRecursionExceeded { pos, max: depth });
    }
    let curr_byte = peek_byte(bytes, pos)?;

    match curr_byte {
        crate::INT_START => {
            let (bencode, next_pos) = decode_int(bytes, pos + 1, crate::BEN_END)?;
            Ok((Inner::Int(bencode, &bytes[pos..next_pos]).into(), next_pos))
        }
        crate::LIST_START => {
            let (bencode, next_pos) = decode_list(bytes, pos + 1, opts, depth)?;
            Ok((Inner::List(bencode, &bytes[pos..next_pos]).into(), next_pos))
        }
        crate::DICT_START => {
            let (bencode, next_pos) = decode_dict(bytes, pos + 1, opts, depth)?;
            Ok((Inner::Dict(bencode, &bytes[pos..next_pos]).into(), next_pos))
        }
        crate::BYTE_LEN_LOW..=crate::BYTE_LEN_HIGH => {
            let (bencode, next_pos) = decode_bytes(bytes, pos)?;
            // Include the length digit, don't increment position
            Ok((Inner::Bytes(bencode, &bytes[pos..next_pos]).into(), next_pos))
        }
        _ => Err(BencodeParseError::InvalidByte { pos }),
    }
}

fn decode_int(bytes: &[u8], pos: usize, delim: u8) -> BencodeParseResult<(i64, usize)> {
    let (_, begin_decode) = bytes.split_at(pos);

    let Some(relative_end_pos) = begin_decode.iter().position(|n| *n == delim) else {
        return Err(BencodeParseError::InvalidIntNoDelimiter { pos });
    };
    let int_byte_slice = &begin_decode[..relative_end_pos];

    if int_byte_slice.len() > 1 {
        // Negative zero is not allowed (this would not be caught when converting)
        if int_byte_slice[0] == b'-' && int_byte_slice[1] == b'0' {
            return Err(BencodeParseError::InvalidIntNegativeZero { pos });
        }

        // Zero padding is illegal, and unspecified for key lengths (we disallow both)
        if int_byte_slice[0] == b'0' {
            return Err(BencodeParseError::InvalidIntZeroPadding { pos });
        }
    }

    let Ok(int_str) = str::from_utf8(int_byte_slice) else {
        return Err(BencodeParseError::InvalidIntParseError { pos });
    };

    // Position of end of integer type, next byte is the start of the next value
    let absolute_end_pos = pos + relative_end_pos;
    let next_pos = absolute_end_pos + 1;
    match int_str.parse::<i64>() {
        Ok(n) => Ok((n, next_pos)),
        Err(_) => Err(BencodeParseError::InvalidIntParseError { pos }),
    }
}

use std::convert::TryFrom;

fn decode_bytes(bytes: &[u8], pos: usize) -> BencodeParseResult<(&[u8], usize)> {
    let (num_bytes, start_pos) = decode_int(bytes, pos, crate::BYTE_LEN_END)?;

    if num_bytes < 0 {
        return Err(BencodeParseError::InvalidLengthNegative { pos });
    }

    // Use usize::try_from to handle potential overflow
    let num_bytes = usize::try_from(num_bytes).map_err(|_| BencodeParseError::InvalidLengthOverflow { pos })?;

    if num_bytes > bytes[start_pos..].len() {
        return Err(BencodeParseError::InvalidLengthOverflow { pos });
    }

    let next_pos = start_pos + num_bytes;
    Ok((&bytes[start_pos..next_pos], next_pos))
}

fn decode_list(bytes: &[u8], pos: usize, opts: BDecodeOpt, depth: usize) -> BencodeParseResult<(Vec<BencodeRef<'_>>, usize)> {
    let mut bencode_list = Vec::new();

    let mut curr_pos = pos;
    let mut curr_byte = peek_byte(bytes, curr_pos)?;

    while curr_byte != crate::BEN_END {
        let (bencode, next_pos) = decode(bytes, curr_pos, opts, depth + 1)?;

        bencode_list.push(bencode);

        curr_pos = next_pos;
        curr_byte = peek_byte(bytes, curr_pos)?;
    }

    let next_pos = curr_pos + 1;
    Ok((bencode_list, next_pos))
}

fn decode_dict(
    bytes: &[u8],
    pos: usize,
    opts: BDecodeOpt,
    depth: usize,
) -> BencodeParseResult<(BTreeMap<&[u8], BencodeRef<'_>>, usize)> {
    let mut bencode_dict = BTreeMap::new();

    let mut curr_pos = pos;
    let mut curr_byte = peek_byte(bytes, curr_pos)?;

    while curr_byte != crate::BEN_END {
        let (key_bytes, next_pos) = decode_bytes(bytes, curr_pos)?;

        // Spec says that the keys must be in alphabetical order
        match (bencode_dict.keys().last(), opts.check_key_sort()) {
            (Some(last_key), true) if key_bytes < *last_key => {
                return Err(BencodeParseError::InvalidKeyOrdering {
                    pos: curr_pos,
                    key: key_bytes.to_vec(),
                })
            }
            _ => (),
        }

        curr_pos = next_pos;

        let (value, next_pos) = decode(bytes, curr_pos, opts, depth + 1)?;
        match bencode_dict.entry(key_bytes) {
            Entry::Vacant(n) => n.insert(value),
            Entry::Occupied(_) => {
                return Err(BencodeParseError::InvalidKeyDuplicates {
                    pos: curr_pos,
                    key: key_bytes.to_vec(),
                })
            }
        };

        curr_pos = next_pos;
        curr_byte = peek_byte(bytes, curr_pos)?;
    }

    let next_pos = curr_pos + 1;
    Ok((bencode_dict, next_pos))
}

fn peek_byte(bytes: &[u8], pos: usize) -> BencodeParseResult<u8> {
    bytes.get(pos).copied().ok_or(BencodeParseError::BytesEmpty { pos })
}

#[cfg(test)]
mod tests {

    use crate::access::bencode::BRefAccess;
    use crate::reference::bencode_ref::BencodeRef;
    use crate::reference::decode_opt::BDecodeOpt;

    /* cSpell:disable */
    // Positive Cases
    const GENERAL: &[u8] = b"d0:12:zero_len_key8:location17:udp://test.com:8011:nested dictd4:listli-500500eee6:numberi500500ee";
    const RECURSION: &[u8] = b"lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllleeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const BYTES_UTF8: &[u8] = b"16:valid_utf8_bytes";
    const DICTIONARY: &[u8] = b"d9:test_dictd10:nested_key12:nested_value11:nested_listli500ei-500ei0eee8:test_key10:test_valuee";
    const LIST: &[u8] = b"l10:test_bytesi500ei0ei-500el12:nested_bytesed8:test_key10:test_valueee";
    const BYTES: &[u8] = b"5:\xC5\xE6\xBE\xE6\xF2";
    const BYTES_ZERO_LEN: &[u8] = b"0:";
    const INT: &[u8] = b"i500e";
    const INT_NEGATIVE: &[u8] = b"i-500e";
    const INT_ZERO: &[u8] = b"i0e";
    const PARTIAL: &[u8] = b"i0e_asd";

    // Negative Cases
    const BYTES_NEG_LEN: &[u8] = b"-4:test";
    const BYTES_EXTRA: &[u8] = b"l15:processed_bytese17:unprocessed_bytes";
    const BYTES_NOT_UTF8: &[u8] = b"5:\xC5\xE6\xBE\xE6\xF2";
    const INT_NAN: &[u8] = b"i500a500e";
    const INT_LEADING_ZERO: &[u8] = b"i0500e";
    const INT_DOUBLE_ZERO: &[u8] = b"i00e";
    const INT_NEGATIVE_ZERO: &[u8] = b"i-0e";
    const INT_DOUBLE_NEGATIVE: &[u8] = b"i--5e";
    const DICT_UNORDERED_KEYS: &[u8] = b"d5:z_key5:value5:a_key5:valuee";
    const DICT_DUP_KEYS_SAME_DATA: &[u8] = b"d5:a_keyi0e5:a_keyi0ee";
    const DICT_DUP_KEYS_DIFF_DATA: &[u8] = b"d5:a_keyi0e5:a_key7:a_valuee";
    /* cSpell:enable */

    #[test]
    fn positive_decode_general() {
        let bencode = BencodeRef::decode(GENERAL, BDecodeOpt::default()).unwrap();

        let ben_dict = bencode.dict().unwrap();
        assert_eq!(ben_dict.lookup("".as_bytes()).unwrap().str().unwrap(), "zero_len_key");
        assert_eq!(
            ben_dict.lookup("location".as_bytes()).unwrap().str().unwrap(),
            "udp://test.com:80"
        );
        assert_eq!(ben_dict.lookup("number".as_bytes()).unwrap().int().unwrap(), 500_500_i64);

        let nested_dict = ben_dict.lookup("nested dict".as_bytes()).unwrap().dict().unwrap();
        let nested_list = nested_dict.lookup("list".as_bytes()).unwrap().list().unwrap();
        assert_eq!(nested_list[0].int().unwrap(), -500_500_i64);
    }

    #[test]
    fn positive_decode_recursion() {
        BencodeRef::decode(RECURSION, BDecodeOpt::new(50, true, true)).unwrap_err();

        // As long as we didn't overflow our call stack, we are good!
    }

    #[test]
    fn positive_decode_bytes_utf8() {
        let bencode = BencodeRef::decode(BYTES_UTF8, BDecodeOpt::default()).unwrap();

        assert_eq!(bencode.str().unwrap(), "valid_utf8_bytes");
    }

    #[test]
    fn positive_decode_dict() {
        let bencode = BencodeRef::decode(DICTIONARY, BDecodeOpt::default()).unwrap();
        let dict = bencode.dict().unwrap();
        assert_eq!(dict.lookup("test_key".as_bytes()).unwrap().str().unwrap(), "test_value");

        let nested_dict = dict.lookup("test_dict".as_bytes()).unwrap().dict().unwrap();
        assert_eq!(
            nested_dict.lookup("nested_key".as_bytes()).unwrap().str().unwrap(),
            "nested_value"
        );

        let nested_list = nested_dict.lookup("nested_list".as_bytes()).unwrap().list().unwrap();
        assert_eq!(nested_list[0].int().unwrap(), 500i64);
        assert_eq!(nested_list[1].int().unwrap(), -500i64);
        assert_eq!(nested_list[2].int().unwrap(), 0i64);
    }

    #[test]
    fn positive_decode_list() {
        let bencode = BencodeRef::decode(LIST, BDecodeOpt::default()).unwrap();
        let list = bencode.list().unwrap();

        assert_eq!(list[0].str().unwrap(), "test_bytes");
        assert_eq!(list[1].int().unwrap(), 500i64);
        assert_eq!(list[2].int().unwrap(), 0i64);
        assert_eq!(list[3].int().unwrap(), -500i64);

        let nested_list = list[4].list().unwrap();
        assert_eq!(nested_list[0].str().unwrap(), "nested_bytes");

        let nested_dict = list[5].dict().unwrap();
        assert_eq!(
            nested_dict.lookup("test_key".as_bytes()).unwrap().str().unwrap(),
            "test_value"
        );
    }

    #[test]
    fn positive_decode_bytes() {
        let bytes = super::decode_bytes(BYTES, 0).unwrap().0;
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0] as char, 'Å');
        assert_eq!(bytes[1] as char, 'æ');
        assert_eq!(bytes[2] as char, '¾');
        assert_eq!(bytes[3] as char, 'æ');
        assert_eq!(bytes[4] as char, 'ò');
    }

    #[test]
    fn positive_decode_bytes_zero_len() {
        let bytes = super::decode_bytes(BYTES_ZERO_LEN, 0).unwrap().0;
        assert_eq!(bytes.len(), 0);
    }

    #[test]
    fn positive_decode_int() {
        let int_value = super::decode_int(INT, 1, crate::BEN_END).unwrap().0;
        assert_eq!(int_value, 500i64);
    }

    #[test]
    fn positive_decode_int_negative() {
        let int_value = super::decode_int(INT_NEGATIVE, 1, crate::BEN_END).unwrap().0;
        assert_eq!(int_value, -500i64);
    }

    #[test]
    fn positive_decode_int_zero() {
        let int_value = super::decode_int(INT_ZERO, 1, crate::BEN_END).unwrap().0;
        assert_eq!(int_value, 0i64);
    }

    #[test]
    fn positive_decode_partial() {
        let bencode = BencodeRef::decode(PARTIAL, BDecodeOpt::new(2, true, false)).unwrap();

        assert_ne!(PARTIAL.len(), bencode.buffer().len());
        assert_eq!(3, bencode.buffer().len());
    }

    #[test]
    fn positive_decode_dict_unordered_keys() {
        BencodeRef::decode(DICT_UNORDERED_KEYS, BDecodeOpt::default()).unwrap();
    }

    #[test]
    #[should_panic = "InvalidByte { pos: 0 }"]
    fn negative_decode_bytes_neg_len() {
        BencodeRef::decode(BYTES_NEG_LEN, BDecodeOpt::default()).unwrap();
    }

    #[test]
    #[should_panic = "BytesEmpty { pos: 20 }"]
    fn negative_decode_bytes_extra() {
        BencodeRef::decode(BYTES_EXTRA, BDecodeOpt::default()).unwrap();
    }

    #[test]
    fn negative_decode_bytes_not_utf8() {
        let bencode = BencodeRef::decode(BYTES_NOT_UTF8, BDecodeOpt::default()).unwrap();

        assert!(bencode.str().is_none());
    }

    #[test]
    #[should_panic = "InvalidIntParseError { pos: 1 }"]
    fn negative_decode_int_nan() {
        super::decode_int(INT_NAN, 1, crate::BEN_END).unwrap();
    }

    #[test]
    #[should_panic = "InvalidIntZeroPadding { pos: 1 }"]
    fn negative_decode_int_leading_zero() {
        super::decode_int(INT_LEADING_ZERO, 1, crate::BEN_END).unwrap();
    }

    #[test]
    #[should_panic = "InvalidIntZeroPadding { pos: 1 }"]
    fn negative_decode_int_double_zero() {
        super::decode_int(INT_DOUBLE_ZERO, 1, crate::BEN_END).unwrap();
    }

    #[test]
    #[should_panic = "InvalidIntNegativeZero { pos: 1 }"]
    fn negative_decode_int_negative_zero() {
        super::decode_int(INT_NEGATIVE_ZERO, 1, crate::BEN_END).unwrap();
    }

    #[test]
    #[should_panic = " InvalidIntParseError { pos: 1 }"]
    fn negative_decode_int_double_negative() {
        super::decode_int(INT_DOUBLE_NEGATIVE, 1, crate::BEN_END).unwrap();
    }

    #[test]
    #[should_panic = "InvalidKeyOrdering { pos: 15, key: [97, 95, 107, 101, 121] }"]
    fn negative_decode_dict_unordered_keys() {
        BencodeRef::decode(DICT_UNORDERED_KEYS, BDecodeOpt::new(5, true, true)).unwrap();
    }

    #[test]
    #[should_panic = "InvalidKeyDuplicates { pos: 18, key: [97, 95, 107, 101, 121] }"]
    fn negative_decode_dict_dup_keys_same_data() {
        BencodeRef::decode(DICT_DUP_KEYS_SAME_DATA, BDecodeOpt::default()).unwrap();
    }

    #[test]
    #[should_panic = "InvalidKeyDuplicates { pos: 18, key: [97, 95, 107, 101, 121] }"]
    fn negative_decode_dict_dup_keys_diff_data() {
        BencodeRef::decode(DICT_DUP_KEYS_DIFF_DATA, BDecodeOpt::default()).unwrap();
    }
}
