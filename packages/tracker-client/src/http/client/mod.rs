pub mod requests;
pub mod responses;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use derive_more::Display;
use hyper::StatusCode;
use requests::{announce, scrape};
use reqwest::{Response, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum Error {
    #[error("Failed to Build a Http Client: {err:?}")]
    ClientBuildingError { err: Arc<reqwest::Error> },
    #[error("Failed to get a response: {err:?}")]
    ResponseError { err: Arc<reqwest::Error> },
    #[error("Returned a non-success code: \"{code}\" with the response: \"{response:?}\"")]
    UnsuccessfulResponse { code: StatusCode, response: Arc<Response> },
}

/// HTTP Tracker Client
pub struct Client {
    client: reqwest::Client,
    base_url: Url,
    key: Option<Key>,
}

/// URL components in this context:
///
/// ```text
/// http://127.0.0.1:62304/announce/YZ....rJ?info_hash=%9C8B%22%13%E3%0B%FF%21%2B0%C3%60%D2o%9A%02%13d%22
/// \_____________________/\_______________/ \__________________________________________________________/
///            |                   |                                    |
///         base url              path                                query
/// ```
impl Client {
    /// # Errors
    ///
    /// This method fails if the client builder fails.
    pub fn new(base_url: Url, timeout: Duration) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| Error::ClientBuildingError { err: e.into() })?;

        Ok(Self {
            base_url,
            client,
            key: None,
        })
    }

    /// Creates the new client binding it to an specific local address.
    ///
    /// # Errors
    ///
    /// This method fails if the client builder fails.
    pub fn bind(base_url: Url, timeout: Duration, local_address: IpAddr) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .local_address(local_address)
            .build()
            .map_err(|e| Error::ClientBuildingError { err: e.into() })?;

        Ok(Self {
            base_url,
            client,
            key: None,
        })
    }

    /// # Errors
    ///
    /// This method fails if the client builder fails.
    pub fn authenticated(base_url: Url, timeout: Duration, key: Key) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| Error::ClientBuildingError { err: e.into() })?;

        Ok(Self {
            base_url,
            client,
            key: Some(key),
        })
    }

    /// # Errors
    ///
    /// This method fails if the returned response was not successful
    pub async fn announce(&self, query: &announce::Query) -> Result<Response, Error> {
        let response = self.get(&self.build_announce_path_and_query(query)).await?;

        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Error::UnsuccessfulResponse {
                code: response.status(),
                response: response.into(),
            })
        }
    }

    /// # Errors
    ///
    /// This method fails if the returned response was not successful
    pub async fn scrape(&self, query: &scrape::Query) -> Result<Response, Error> {
        let response = self.get(&self.build_scrape_path_and_query(query)).await?;

        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Error::UnsuccessfulResponse {
                code: response.status(),
                response: response.into(),
            })
        }
    }

    /// # Errors
    ///
    /// This method fails if the returned response was not successful
    pub async fn announce_with_header(&self, query: &announce::Query, key: &str, value: &str) -> Result<Response, Error> {
        let response = self
            .get_with_header(&self.build_announce_path_and_query(query), key, value)
            .await?;

        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Error::UnsuccessfulResponse {
                code: response.status(),
                response: response.into(),
            })
        }
    }

    /// # Errors
    ///
    /// This method fails if the returned response was not successful
    pub async fn health_check(&self) -> Result<Response, Error> {
        let response = self.get(&self.build_path("health_check")).await?;

        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Error::UnsuccessfulResponse {
                code: response.status(),
                response: response.into(),
            })
        }
    }

    /// # Errors
    ///
    /// This method fails if there was an error while sending request.
    pub async fn get(&self, path: &str) -> Result<Response, Error> {
        self.client
            .get(self.build_url(path))
            .send()
            .await
            .map_err(|e| Error::ResponseError { err: e.into() })
    }

    /// # Errors
    ///
    /// This method fails if there was an error while sending request.
    pub async fn get_with_header(&self, path: &str, key: &str, value: &str) -> Result<Response, Error> {
        self.client
            .get(self.build_url(path))
            .header(key, value)
            .send()
            .await
            .map_err(|e| Error::ResponseError { err: e.into() })
    }

    fn build_announce_path_and_query(&self, query: &announce::Query) -> String {
        format!("{}?{query}", self.build_path("announce"))
    }

    fn build_scrape_path_and_query(&self, query: &scrape::Query) -> String {
        format!("{}?{query}", self.build_path("scrape"))
    }

    fn build_path(&self, path: &str) -> String {
        match &self.key {
            Some(key) => format!("{path}/{key}"),
            None => path.to_string(),
        }
    }

    fn build_url(&self, path: &str) -> String {
        let base_url = self.base_url();
        format!("{base_url}{path}")
    }

    fn base_url(&self) -> String {
        self.base_url.to_string()
    }
}

/// A token used for authentication.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Display, Hash)]
pub struct Key(String);

impl Key {
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.0
    }
}
