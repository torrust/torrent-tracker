use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

use aquatic_udp_protocol::Response;
use torrust_tracker_clock::clock::Time as _;
use tracing::{instrument, Level};

use super::bound_socket::BoundSocket;
use crate::core::Tracker;
use crate::servers::udp::{handlers, RawRequest};
use crate::CurrentClock;

pub struct Processor {
    socket: Arc<BoundSocket>,
    tracker: Arc<Tracker>,
    cookie_lifetime: f64,
}

impl Processor {
    pub fn new(socket: Arc<BoundSocket>, tracker: Arc<Tracker>, cookie_lifetime: f64) -> Self {
        Self {
            socket,
            tracker,
            cookie_lifetime,
        }
    }

    #[instrument(skip(self, request))]
    pub async fn process_request(self, request: RawRequest) {
        let cookie_issue_time = CurrentClock::now().as_secs_f64();
        let cookie_expiry_time = cookie_issue_time - self.cookie_lifetime - 1.0;
        let cookie_tolerance_max_time = cookie_issue_time + 1.0;

        let from = request.from;
        let response = handlers::handle_packet(
            request,
            &self.tracker,
            self.socket.address(),
            cookie_issue_time,
            cookie_expiry_time,
            cookie_tolerance_max_time,
        )
        .await;
        self.send_response(from, response).await;
    }

    #[instrument(skip(self))]
    async fn send_response(self, target: SocketAddr, response: Response) {
        tracing::debug!("send response");

        let response_type = match &response {
            Response::Connect(_) => "Connect".to_string(),
            Response::AnnounceIpv4(_) => "AnnounceIpv4".to_string(),
            Response::AnnounceIpv6(_) => "AnnounceIpv6".to_string(),
            Response::Scrape(_) => "Scrape".to_string(),
            Response::Error(e) => format!("Error: {e:?}"),
        };

        let mut writer = Cursor::new(Vec::with_capacity(200));

        match response.write_bytes(&mut writer) {
            Ok(()) => {
                let bytes_count = writer.get_ref().len();
                let payload = writer.get_ref();

                let () = match self.send_packet(&target, payload).await {
                    Ok(sent_bytes) => {
                        if tracing::event_enabled!(Level::TRACE) {
                            tracing::debug!(%bytes_count, %sent_bytes, ?payload, "sent {response_type}");
                        } else {
                            tracing::debug!(%bytes_count, %sent_bytes, "sent {response_type}");
                        }
                    }
                    Err(error) => tracing::warn!(%bytes_count, %error, ?payload, "failed to send"),
                };
            }
            Err(e) => {
                tracing::error!(%e, "error");
            }
        }
    }

    #[instrument(skip(self))]
    async fn send_packet(&self, target: &SocketAddr, payload: &[u8]) -> std::io::Result<usize> {
        tracing::trace!("send packet");

        // doesn't matter if it reaches or not
        self.socket.send_to(payload, target).await
    }
}
