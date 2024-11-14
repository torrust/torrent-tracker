use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::StatusCode;
use reqwest::{Client as HttpClient, Response};
use serde::Serialize;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Error, Serialize)]
#[serde(into = "String")]
pub enum Error {
    #[error("Failed to Build a Http Client: {err:?}")]
    ClientBuildingError { err: Arc<reqwest::Error> },
    #[error("Heath check failed to get a response: {err:?}")]
    ResponseError { err: Arc<reqwest::Error> },
    #[error("Http check returned a non-success code: \"{code}\" with the response: \"{response:?}\"")]
    UnsuccessfulResponse { code: StatusCode, response: Arc<Response> },
}

impl From<Error> for String {
    fn from(value: Error) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Checks {
    url: Url,
    result: Result<String, Error>,
}

pub async fn run(health_checks: Vec<Url>, timeout: Duration) -> Vec<Result<Checks, Checks>> {
    let mut results = Vec::default();

    tracing::debug!("Health checks ...");

    for url in health_checks {
        let result = match run_health_check(url.clone(), timeout).await {
            Ok(response) => Ok(response.status().to_string()),
            Err(err) => Err(err),
        };

        let check = Checks { url, result };

        if check.result.is_err() {
            results.push(Err(check));
        } else {
            results.push(Ok(check));
        }
    }

    results
}

async fn run_health_check(url: Url, timeout: Duration) -> Result<Response, Error> {
    let client = HttpClient::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| Error::ClientBuildingError { err: e.into() })?;

    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| Error::ResponseError { err: e.into() })?;

    if response.status().is_success() {
        Ok(response)
    } else {
        Err(Error::UnsuccessfulResponse {
            code: response.status(),
            response: response.into(),
        })
    }
}
