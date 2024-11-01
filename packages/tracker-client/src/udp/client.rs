use core::result::Result::{Err, Ok};
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use aquatic_udp_protocol::{ConnectRequest, Request, Response, TransactionId};
use tokio::net::UdpSocket;
use tokio::time;
use torrust_tracker_configuration::DEFAULT_TIMEOUT;
use zerocopy::network_endian::I32;

use super::Error;
use crate::udp::MAX_PACKET_SIZE;

pub const UDP_CLIENT_LOG_TARGET: &str = "UDP CLIENT";

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct UdpClient {
    /// The socket to connect to
    pub socket: Arc<UdpSocket>,

    /// Timeout for sending and receiving packets
    pub timeout: Duration,
}

impl UdpClient {
    /// Creates a new `UdpClient` bound to the default port and ipv6 address
    ///
    /// # Errors
    ///
    /// Will return error if unable to bind to any port or ip address.
    ///
    async fn bound_to_default_ipv4(timeout: Duration) -> Result<Self, Error> {
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);

        Self::bound(addr, timeout).await
    }

    /// Creates a new `UdpClient` bound to the default port and ipv6 address
    ///
    /// # Errors
    ///
    /// Will return error if unable to bind to any port or ip address.
    ///
    async fn bound_to_default_ipv6(timeout: Duration) -> Result<Self, Error> {
        let addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0);

        Self::bound(addr, timeout).await
    }

    /// Creates a new `UdpClient` connected to a Udp server
    ///
    /// # Errors
    ///
    /// Will return any errors present in the call stack
    ///
    pub async fn connected(remote_addr: SocketAddr, timeout: Duration) -> Result<Self, Error> {
        let client = if remote_addr.is_ipv4() {
            Self::bound_to_default_ipv4(timeout).await?
        } else {
            Self::bound_to_default_ipv6(timeout).await?
        };

        client.connect(remote_addr).await?;
        Ok(client)
    }

    /// Creates a `[UdpClient]` bound to a Socket.
    ///
    /// # Panics
    ///
    /// Panics if unable to get the `local_addr` of the bound socket.
    ///
    /// # Errors
    ///
    /// This function will return an error if the binding takes to long
    /// or if there is an underlying OS error.
    pub async fn bound(addr: SocketAddr, timeout: Duration) -> Result<Self, Error> {
        tracing::trace!(target: UDP_CLIENT_LOG_TARGET, "binding to socket: {addr:?} ...");

        let socket = time::timeout(timeout, UdpSocket::bind(addr))
            .await
            .map_err(|_| Error::TimeoutWhileBindingToSocket { addr })?
            .map_err(|e| Error::UnableToBindToSocket { err: e.into(), addr })?;

        let addr = socket.local_addr().expect("it should get the local address");

        tracing::debug!(target: UDP_CLIENT_LOG_TARGET, "bound to socket: {addr:?}.");

        let udp_client = Self {
            socket: Arc::new(socket),
            timeout,
        };

        Ok(udp_client)
    }

    /// # Errors
    ///
    /// Will return error if can't connect to the socket.
    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<(), Error> {
        tracing::trace!(target: UDP_CLIENT_LOG_TARGET, "connecting to remote: {remote_addr:?} ...");

        let () = time::timeout(self.timeout, self.socket.connect(remote_addr))
            .await
            .map_err(|_| Error::TimeoutWhileConnectingToRemote { remote_addr })?
            .map_err(|e| Error::UnableToConnectToRemote {
                err: e.into(),
                remote_addr,
            })?;

        tracing::debug!(target: UDP_CLIENT_LOG_TARGET, "connected to remote: {remote_addr:?}.");

        Ok(())
    }

    /// # Errors
    ///
    /// Will return error if:
    ///
    /// - Can't write to the socket.
    /// - Can't send data.
    pub async fn send(&self, bytes: &[u8]) -> Result<usize, Error> {
        tracing::trace!(target: UDP_CLIENT_LOG_TARGET, "sending {bytes:?} ...");

        let () = time::timeout(self.timeout, self.socket.writable())
            .await
            .map_err(|_| Error::TimeoutWaitForWriteableSocket)?
            .map_err(|e| Error::UnableToGetWritableSocket { err: e.into() })?;

        let sent_bytes = time::timeout(self.timeout, self.socket.send(bytes))
            .await
            .map_err(|_| Error::TimeoutWhileSendingData { data: bytes.to_vec() })?
            .map_err(|e| Error::UnableToSendData {
                err: e.into(),
                data: bytes.to_vec(),
            })?;

        tracing::debug!(target: UDP_CLIENT_LOG_TARGET, "sent {sent_bytes} bytes to remote.");

        Ok(sent_bytes)
    }

    /// # Errors
    ///
    /// Will return error if:
    ///
    /// - Can't read from the socket.
    /// - Can't receive data.
    ///
    /// # Panics
    ///
    pub async fn receive(&self) -> Result<Vec<u8>, Error> {
        tracing::trace!(target: UDP_CLIENT_LOG_TARGET, "receiving ...");

        let mut buffer = [0u8; MAX_PACKET_SIZE];

        let () = time::timeout(self.timeout, self.socket.readable())
            .await
            .map_err(|_| Error::TimeoutWaitForReadableSocket)?
            .map_err(|e| Error::UnableToGetReadableSocket { err: e.into() })?;

        let received_bytes = time::timeout(self.timeout, self.socket.recv(&mut buffer))
            .await
            .map_err(|_| Error::TimeoutWhileReceivingData)?
            .map_err(|e| Error::UnableToReceivingData { err: e.into() })?;

        let mut received: Vec<u8> = buffer.to_vec();
        Vec::truncate(&mut received, received_bytes);

        tracing::debug!(target: UDP_CLIENT_LOG_TARGET, "received {received_bytes} bytes: {received:?}");

        Ok(received)
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct UdpTrackerClient {
    pub client: UdpClient,
}

impl UdpTrackerClient {
    /// Creates a new `UdpTrackerClient` connected to a Udp Tracker server
    ///
    /// # Errors
    ///
    /// If unable to connect to the remote address.
    ///
    pub async fn new(remote_addr: SocketAddr, timeout: Duration) -> Result<UdpTrackerClient, Error> {
        let client = UdpClient::connected(remote_addr, timeout).await?;
        Ok(UdpTrackerClient { client })
    }

    /// # Errors
    ///
    /// Will return error if can't write request to bytes.
    pub async fn send(&self, request: Request) -> Result<usize, Error> {
        tracing::trace!(target: UDP_CLIENT_LOG_TARGET, "sending request {request:?} ...");

        // Write request into a buffer
        // todo: optimize the pre-allocated amount based upon request type.
        let mut writer = Cursor::new(Vec::with_capacity(200));
        let () = request
            .write_bytes(&mut writer)
            .map_err(|e| Error::UnableToWriteDataFromRequest { err: e.into(), request })?;

        self.client.send(writer.get_ref()).await
    }

    /// # Errors
    ///
    /// Will return error if can't create response from the received payload (bytes buffer).
    pub async fn receive(&self) -> Result<Response, Error> {
        let response = self.client.receive().await?;

        tracing::debug!(target: UDP_CLIENT_LOG_TARGET, "received {} bytes: {response:?}", response.len());

        Response::parse_bytes(&response, true).map_err(|e| Error::UnableToParseResponse { err: e.into(), response })
    }
}

/// Helper Function to Check if a UDP Service is Connectable
///
/// # Panics
///
/// It will return an error if unable to connect to the UDP service.
///
/// # Errors
///
pub async fn check(remote_addr: &SocketAddr) -> Result<String, String> {
    tracing::debug!("Checking Service (detail): {remote_addr:?}.");

    match UdpTrackerClient::new(*remote_addr, DEFAULT_TIMEOUT).await {
        Ok(client) => {
            let connect_request = ConnectRequest {
                transaction_id: TransactionId(I32::new(123)),
            };

            // client.send() return usize, but doesn't use here
            match client.send(connect_request.into()).await {
                Ok(_) => (),
                Err(e) => tracing::debug!("Error: {e:?}."),
            };

            let process = move |response| {
                if matches!(response, Response::Connect(_connect_response)) {
                    Ok("Connected".to_string())
                } else {
                    Err("Did not Connect".to_string())
                }
            };

            let sleep = time::sleep(Duration::from_millis(2000));
            tokio::pin!(sleep);

            tokio::select! {
                () = &mut sleep => {
                      Err("Timed Out".to_string())
                }
                response = client.receive() => {
                      process(response.unwrap())
                }
            }
        }
        Err(e) => Err(format!("{e:?}")),
    }
}
