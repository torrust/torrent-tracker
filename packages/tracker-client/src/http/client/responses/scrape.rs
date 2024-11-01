use std::collections::HashMap;
use std::fmt::Write;
use std::str;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use serde_bencode::value::Value;

use crate::http::{ByteArray20, InfoHash};

#[derive(Debug, PartialEq, Default, Deserialize)]
pub struct Response {
    pub files: HashMap<ByteArray20, File>,
}

impl Response {
    #[must_use]
    pub fn with_one_file(info_hash_bytes: ByteArray20, file: File) -> Self {
        let mut files: HashMap<ByteArray20, File> = HashMap::new();
        files.insert(info_hash_bytes, file);
        Self { files }
    }

    /// # Errors
    ///
    /// Will return an error if the deserialized bencoded response can't not be converted into a valid response.
    ///
    /// # Panics
    ///
    /// Will panic if it can't deserialize the bencoded response.
    pub fn try_from_bencoded(bytes: &[u8]) -> Result<Self, BencodeParseError> {
        let scrape_response: DeserializedResponse =
            serde_bencode::from_bytes(bytes).expect("provided bytes should be a valid bencoded response");
        Self::try_from(scrape_response)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct File {
    pub complete: i64,   // The number of active peers that have completed downloading
    pub downloaded: i64, // The number of peers that have ever completed downloading
    pub incomplete: i64, // The number of active peers that have not completed downloading
}

impl File {
    #[must_use]
    pub fn zeroed() -> Self {
        Self::default()
    }
}

impl TryFrom<DeserializedResponse> for Response {
    type Error = BencodeParseError;

    fn try_from(scrape_response: DeserializedResponse) -> Result<Self, Self::Error> {
        parse_bencoded_response(&scrape_response.files)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct DeserializedResponse {
    pub files: Value,
}

// Custom serialization for Response
impl Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.files.len()))?;
        for (key, value) in &self.files {
            // Convert ByteArray20 key to hex string
            let hex_key = byte_array_to_hex_string(key);
            map.serialize_entry(&hex_key, value)?;
        }
        map.end()
    }
}

// Helper function to convert ByteArray20 to hex string
fn byte_array_to_hex_string(byte_array: &ByteArray20) -> String {
    let mut hex_string = String::with_capacity(byte_array.len() * 2);
    for byte in byte_array {
        write!(hex_string, "{byte:02x}").expect("Writing to string should never fail");
    }
    hex_string
}

#[derive(Default)]
pub struct ResponseBuilder {
    response: Response,
}

impl ResponseBuilder {
    #[must_use]
    pub fn add_file(mut self, info_hash_bytes: ByteArray20, file: File) -> Self {
        self.response.files.insert(info_hash_bytes, file);
        self
    }

    #[must_use]
    pub fn build(self) -> Response {
        self.response
    }
}

#[derive(Debug)]
pub enum BencodeParseError {
    InvalidValueExpectedDict { value: Value },
    InvalidValueExpectedInt { value: Value },
    InvalidFileField { value: Value },
    MissingFileField { field_name: String },
}

/// It parses a bencoded scrape response into a `Response` struct.
///
/// For example:
///
/// ```text
/// d5:filesd20:xxxxxxxxxxxxxxxxxxxxd8:completei11e10:downloadedi13772e10:incompletei19e
/// 20:yyyyyyyyyyyyyyyyyyyyd8:completei21e10:downloadedi206e10:incompletei20eee
/// ```
///
/// Response (JSON encoded for readability):
///
/// ```text
/// {
///   'files': {
///     'xxxxxxxxxxxxxxxxxxxx': {'complete': 11, 'downloaded': 13772, 'incomplete': 19},
///     'yyyyyyyyyyyyyyyyyyyy': {'complete': 21, 'downloaded': 206, 'incomplete': 20}
///   }
/// }
fn parse_bencoded_response(value: &Value) -> Result<Response, BencodeParseError> {
    let mut files: HashMap<ByteArray20, File> = HashMap::new();

    match value {
        Value::Dict(dict) => {
            for file_element in dict {
                let info_hash_byte_vec = file_element.0;
                let file_value = file_element.1;

                let file = parse_bencoded_file(file_value).unwrap();

                files.insert(InfoHash::new(info_hash_byte_vec).bytes(), file);
            }
        }
        _ => return Err(BencodeParseError::InvalidValueExpectedDict { value: value.clone() }),
    }

    Ok(Response { files })
}

/// It parses a bencoded dictionary into a `File` struct.
///
/// For example:
///
///
/// ```text
/// d8:completei11e10:downloadedi13772e10:incompletei19ee
/// ```
///
/// into:
///
/// ```text
/// File {
///     complete: 11,
///     downloaded: 13772,
///     incomplete: 19,
/// }
/// ```
fn parse_bencoded_file(value: &Value) -> Result<File, BencodeParseError> {
    let file = match &value {
        Value::Dict(dict) => {
            let mut complete = None;
            let mut downloaded = None;
            let mut incomplete = None;

            for file_field in dict {
                let field_name = file_field.0;

                let field_value = match file_field.1 {
                    Value::Int(number) => Ok(*number),
                    _ => Err(BencodeParseError::InvalidValueExpectedInt {
                        value: file_field.1.clone(),
                    }),
                }?;

                if field_name == b"complete" {
                    complete = Some(field_value);
                } else if field_name == b"downloaded" {
                    downloaded = Some(field_value);
                } else if field_name == b"incomplete" {
                    incomplete = Some(field_value);
                } else {
                    return Err(BencodeParseError::InvalidFileField {
                        value: file_field.1.clone(),
                    });
                }
            }

            if complete.is_none() {
                return Err(BencodeParseError::MissingFileField {
                    field_name: "complete".to_string(),
                });
            }

            if downloaded.is_none() {
                return Err(BencodeParseError::MissingFileField {
                    field_name: "downloaded".to_string(),
                });
            }

            if incomplete.is_none() {
                return Err(BencodeParseError::MissingFileField {
                    field_name: "incomplete".to_string(),
                });
            }

            File {
                complete: complete.unwrap(),
                downloaded: downloaded.unwrap(),
                incomplete: incomplete.unwrap(),
            }
        }
        _ => return Err(BencodeParseError::InvalidValueExpectedDict { value: value.clone() }),
    };

    Ok(file)
}
