use std::net::SocketAddr;
use std::sync::Arc;

use aquatic_udp_protocol::Request;
use thiserror::Error;
use torrust_tracker_located_error::DynError;

pub mod client;

/// The maximum number of bytes in a UDP packet.
pub const MAX_PACKET_SIZE: usize = 1496;
/// A magic 64-bit integer constant defined in the protocol that is used to
/// identify the protocol.
pub const PROTOCOL_ID: i64 = 0x0417_2710_1980;

#[derive(Debug, Clone, Error)]
pub enum Error {
    #[error("Timeout while waiting for socket to bind: {addr:?}")]
    TimeoutWhileBindingToSocket { addr: SocketAddr },

    #[error("Failed to bind to socket: {addr:?}, with error: {err:?}")]
    UnableToBindToSocket { err: Arc<std::io::Error>, addr: SocketAddr },

    #[error("Timeout while waiting for connection to remote: {remote_addr:?}")]
    TimeoutWhileConnectingToRemote { remote_addr: SocketAddr },

    #[error("Failed to connect to remote: {remote_addr:?}, with error: {err:?}")]
    UnableToConnectToRemote {
        err: Arc<std::io::Error>,
        remote_addr: SocketAddr,
    },

    #[error("Timeout while waiting for the socket to become writable.")]
    TimeoutWaitForWriteableSocket,

    #[error("Failed to get writable socket: {err:?}")]
    UnableToGetWritableSocket { err: Arc<std::io::Error> },

    #[error("Timeout while trying to send data: {data:?}")]
    TimeoutWhileSendingData { data: Vec<u8> },

    #[error("Failed to send data: {data:?}, with error: {err:?}")]
    UnableToSendData { err: Arc<std::io::Error>, data: Vec<u8> },

    #[error("Timeout while waiting for the socket to become readable.")]
    TimeoutWaitForReadableSocket,

    #[error("Failed to get readable socket: {err:?}")]
    UnableToGetReadableSocket { err: Arc<std::io::Error> },

    #[error("Timeout while trying to receive data.")]
    TimeoutWhileReceivingData,

    #[error("Failed to receive data: {err:?}")]
    UnableToReceivingData { err: Arc<std::io::Error> },

    #[error("Failed to get data from request: {request:?}, with error: {err:?}")]
    UnableToWriteDataFromRequest { err: Arc<std::io::Error>, request: Request },

    #[error("Failed to parse response: {response:?}, with error: {err:?}")]
    UnableToParseResponse { err: Arc<std::io::Error>, response: Vec<u8> },
}

impl From<Error> for DynError {
    fn from(e: Error) -> Self {
        Arc::new(Box::new(e))
    }
}
