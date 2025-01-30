use hyper::HeaderMap;
use reqwest::Response;
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::common::http::{Query, QueryParam, ReqwestQuery};
use crate::connection_info::ConnectionInfo;

/// API Client
pub struct Client {
    connection_info: ConnectionInfo,
    base_path: String,
}

impl Client {
    #[must_use]
    pub fn new(connection_info: ConnectionInfo) -> Self {
        Self {
            connection_info,
            base_path: "api/v1/".to_string(),
        }
    }

    pub async fn generate_auth_key(&self, seconds_valid: i32, headers: Option<HeaderMap>) -> Response {
        self.post_empty(&format!("key/{}", &seconds_valid), headers).await
    }

    pub async fn add_auth_key(&self, add_key_form: AddKeyForm, headers: Option<HeaderMap>) -> Response {
        self.post_form("keys", &add_key_form, headers).await
    }

    pub async fn delete_auth_key(&self, key: &str, headers: Option<HeaderMap>) -> Response {
        self.delete(&format!("key/{}", &key), headers).await
    }

    pub async fn reload_keys(&self, headers: Option<HeaderMap>) -> Response {
        self.get("keys/reload", Query::default(), headers).await
    }

    pub async fn whitelist_a_torrent(&self, info_hash: &str, headers: Option<HeaderMap>) -> Response {
        self.post_empty(&format!("whitelist/{}", &info_hash), headers).await
    }

    pub async fn remove_torrent_from_whitelist(&self, info_hash: &str, headers: Option<HeaderMap>) -> Response {
        self.delete(&format!("whitelist/{}", &info_hash), headers).await
    }

    pub async fn reload_whitelist(&self, headers: Option<HeaderMap>) -> Response {
        self.get("whitelist/reload", Query::default(), headers).await
    }

    pub async fn get_torrent(&self, info_hash: &str, headers: Option<HeaderMap>) -> Response {
        self.get(&format!("torrent/{}", &info_hash), Query::default(), headers).await
    }

    pub async fn get_torrents(&self, params: Query, headers: Option<HeaderMap>) -> Response {
        self.get("torrents", params, headers).await
    }

    pub async fn get_tracker_statistics(&self, headers: Option<HeaderMap>) -> Response {
        self.get("stats", Query::default(), headers).await
    }

    pub async fn get(&self, path: &str, params: Query, headers: Option<HeaderMap>) -> Response {
        let mut query: Query = params;

        if let Some(token) = &self.connection_info.api_token {
            query.add_param(QueryParam::new("token", token));
        }

        self.get_request_with_query(path, query, headers).await
    }

    /// # Panics
    ///
    /// Will panic if the request can't be sent
    pub async fn post_empty(&self, path: &str, headers: Option<HeaderMap>) -> Response {
        let builder = reqwest::Client::new()
            .post(self.base_url(path).clone())
            .query(&ReqwestQuery::from(self.query_with_token()));

        let builder = match headers {
            Some(headers) => builder.headers(headers),
            None => builder,
        };

        builder.send().await.unwrap()
    }

    /// # Panics
    ///
    /// Will panic if the request can't be sent
    pub async fn post_form<T: Serialize + ?Sized>(&self, path: &str, form: &T, headers: Option<HeaderMap>) -> Response {
        let builder = reqwest::Client::new()
            .post(self.base_url(path).clone())
            .query(&ReqwestQuery::from(self.query_with_token()))
            .json(&form);

        let builder = match headers {
            Some(headers) => builder.headers(headers),
            None => builder,
        };

        builder.send().await.unwrap()
    }

    /// # Panics
    ///
    /// Will panic if the request can't be sent
    async fn delete(&self, path: &str, headers: Option<HeaderMap>) -> Response {
        let builder = reqwest::Client::new()
            .delete(self.base_url(path).clone())
            .query(&ReqwestQuery::from(self.query_with_token()));

        let builder = match headers {
            Some(headers) => builder.headers(headers),
            None => builder,
        };

        builder.send().await.unwrap()
    }

    pub async fn get_request_with_query(&self, path: &str, params: Query, headers: Option<HeaderMap>) -> Response {
        get(self.base_url(path), Some(params), headers).await
    }

    pub async fn get_request(&self, path: &str) -> Response {
        get(self.base_url(path), None, None).await
    }

    fn query_with_token(&self) -> Query {
        match &self.connection_info.api_token {
            Some(token) => Query::params([QueryParam::new("token", token)].to_vec()),
            None => Query::default(),
        }
    }

    fn base_url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{}{path}", &self.connection_info.origin, &self.base_path)).unwrap()
    }
}

/// # Panics
///
/// Will panic if the request can't be sent
pub async fn get(path: Url, query: Option<Query>, headers: Option<HeaderMap>) -> Response {
    let builder = reqwest::Client::builder().build().unwrap();

    let builder = match query {
        Some(params) => builder.get(path).query(&ReqwestQuery::from(params)),
        None => builder.get(path),
    };

    let builder = match headers {
        Some(headers) => builder.headers(headers),
        None => builder,
    };

    builder.send().await.unwrap()
}

/// Returns a `HeaderMap` with a request id header
///
/// # Panics
///
/// Will panic if the request ID can't be parsed into a string.
#[must_use]
pub fn headers_with_request_id(request_id: Uuid) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", request_id.to_string().parse().unwrap());
    headers
}

#[derive(Serialize, Debug)]
pub struct AddKeyForm {
    #[serde(rename = "key")]
    pub opt_key: Option<String>,
    pub seconds_valid: Option<u64>,
}
