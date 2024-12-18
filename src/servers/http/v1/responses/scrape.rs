//! `Scrape` response for the HTTP tracker [`scrape`](crate::servers::http::v1::requests::scrape::Scrape) request.
//!
//! Data structures and logic to build the `scrape` response.
use std::borrow::Cow;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use torrust_tracker_contrib_bencode::{ben_int, ben_map, BMutAccess};

use crate::core::ScrapeData;

/// The `Scrape` response for the HTTP tracker.
///
/// ```text
/// use torrust_tracker::servers::http::v1::responses::scrape::Bencoded;
/// use bittorrent_primitives::info_hash::InfoHash;
/// use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;
/// use torrust_tracker::core::ScrapeData;
///
/// let info_hash = InfoHash::from_bytes(&[0x69; 20]);
/// let mut scrape_data = ScrapeData::empty();
/// scrape_data.add_file(
///     &info_hash,
///     SwarmMetadata {
///         complete: 1,
///         downloaded: 2,
///         incomplete: 3,
///     },
/// );
///
/// let response = Bencoded::from(scrape_data);
///
/// let bytes = response.body();
///
/// // cspell:disable-next-line
/// let expected_bytes = b"d5:filesd20:iiiiiiiiiiiiiiiiiiiid8:completei1e10:downloadedi2e10:incompletei3eeee";
///
/// assert_eq!(
///     String::from_utf8(bytes).unwrap(),
///     String::from_utf8(expected_bytes.to_vec()).unwrap()
/// );
/// ```
#[derive(Debug, PartialEq, Default)]
pub struct Bencoded {
    /// The scrape data to be bencoded.
    scrape_data: ScrapeData,
}

impl Bencoded {
    /// Returns the bencoded representation of the `Scrape` struct.
    ///
    /// # Panics
    ///
    /// Will return an error if it can't access the bencode as a mutable `BDictAccess`.    
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut scrape_list = ben_map!();

        let scrape_list_mut = scrape_list.dict_mut().unwrap();

        for (info_hash, value) in &self.scrape_data.files {
            scrape_list_mut.insert(
                Cow::from(info_hash.bytes().to_vec()),
                ben_map! {
                    "complete" => ben_int!(i64::from(value.complete)),
                    "downloaded" => ben_int!(i64::from(value.downloaded)),
                    "incomplete" => ben_int!(i64::from(value.incomplete))
                },
            );
        }

        (ben_map! {
            "files" => scrape_list
        })
        .encode()
    }
}

impl From<ScrapeData> for Bencoded {
    fn from(scrape_data: ScrapeData) -> Self {
        Self { scrape_data }
    }
}

impl IntoResponse for Bencoded {
    fn into_response(self) -> Response {
        (StatusCode::OK, self.body()).into_response()
    }
}

#[cfg(test)]
mod tests {

    mod scrape_response {
        use bittorrent_primitives::info_hash::InfoHash;
        use torrust_tracker_primitives::swarm_metadata::SwarmMetadata;

        use crate::core::ScrapeData;
        use crate::servers::http::v1::responses::scrape::Bencoded;

        fn sample_scrape_data() -> ScrapeData {
            let info_hash = InfoHash::from_bytes(&[0x69; 20]);
            let mut scrape_data = ScrapeData::empty();
            scrape_data.add_file(
                &info_hash,
                SwarmMetadata {
                    complete: 1,
                    downloaded: 2,
                    incomplete: 3,
                },
            );
            scrape_data
        }

        #[test]
        fn should_be_converted_from_scrape_data() {
            let response = Bencoded::from(sample_scrape_data());

            assert_eq!(
                response,
                Bencoded {
                    scrape_data: sample_scrape_data()
                }
            );
        }

        #[test]
        fn should_be_bencoded() {
            let response = Bencoded {
                scrape_data: sample_scrape_data(),
            };

            let bytes = response.body();

            // cspell:disable-next-line
            let expected_bytes = b"d5:filesd20:iiiiiiiiiiiiiiiiiiiid8:completei1e10:downloadedi2e10:incompletei3eeee";

            assert_eq!(
                String::from_utf8(bytes).unwrap(),
                String::from_utf8(expected_bytes.to_vec()).unwrap()
            );
        }
    }
}
