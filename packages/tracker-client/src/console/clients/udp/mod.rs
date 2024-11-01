use std::net::SocketAddr;

use aquatic_udp_protocol::Response;
use serde::Serialize;
use thiserror::Error;

use crate::udp;

pub mod app;
pub mod checker;
pub mod responses;

#[derive(Error, Debug, Clone, Serialize)]
#[serde(into = "String")]
pub enum Error {
    #[error("Failed to Connect to: {remote_addr}, with error: {err}")]
    UnableToBindAndConnect { remote_addr: SocketAddr, err: udp::Error },

    #[error("Failed to send a connection request, with error: {err}")]
    UnableToSendConnectionRequest { err: udp::Error },

    #[error("Failed to receive a connect response, with error: {err}")]
    UnableToReceiveConnectResponse { err: udp::Error },

    #[error("Failed to send a announce request, with error: {err}")]
    UnableToSendAnnounceRequest { err: udp::Error },

    #[error("Failed to receive a announce response, with error: {err}")]
    UnableToReceiveAnnounceResponse { err: udp::Error },

    #[error("Failed to send a scrape request, with error: {err}")]
    UnableToSendScrapeRequest { err: udp::Error },

    #[error("Failed to receive a scrape response, with error: {err}")]
    UnableToReceiveScrapeResponse { err: udp::Error },

    #[error("Failed to receive a response, with error: {err}")]
    UnableToReceiveResponse { err: udp::Error },

    #[error("Failed to get local address for connection: {err}")]
    UnableToGetLocalAddr { err: udp::Error },

    #[error("Failed to get a connection response: {response:?}")]
    UnexpectedConnectionResponse { response: Response },
}

impl From<Error> for String {
    fn from(value: Error) -> Self {
        value.to_string()
    }
}
