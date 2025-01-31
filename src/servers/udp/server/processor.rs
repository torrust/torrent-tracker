use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use aquatic_udp_protocol::Response;
use packages::statistics;
use packages::statistics::event::UdpResponseKind;
use tokio::time::Instant;
use tracing::{instrument, Level};

use super::bound_socket::BoundSocket;
use crate::container::UdpTrackerContainer;
use crate::packages;
use crate::servers::udp::handlers::CookieTimeValues;
use crate::servers::udp::{handlers, RawRequest};

pub struct Processor {
    socket: Arc<BoundSocket>,
    udp_tracker_container: Arc<UdpTrackerContainer>,
    cookie_lifetime: f64,
}

impl Processor {
    pub fn new(socket: Arc<BoundSocket>, udp_tracker_container: Arc<UdpTrackerContainer>, cookie_lifetime: f64) -> Self {
        Self {
            socket,
            udp_tracker_container,
            cookie_lifetime,
        }
    }

    #[instrument(skip(self, request))]
    pub async fn process_request(self, request: RawRequest) {
        let from = request.from;

        let start_time = Instant::now();

        let response = handlers::handle_packet(
            request,
            self.udp_tracker_container.clone(),
            self.socket.address(),
            CookieTimeValues::new(self.cookie_lifetime),
        )
        .await;

        let elapsed_time = start_time.elapsed();

        self.send_response(from, response, elapsed_time).await;
    }

    #[instrument(skip(self))]
    async fn send_response(self, target: SocketAddr, response: Response, req_processing_time: Duration) {
        tracing::debug!("send response");

        let response_type = match &response {
            Response::Connect(_) => "Connect".to_string(),
            Response::AnnounceIpv4(_) => "AnnounceIpv4".to_string(),
            Response::AnnounceIpv6(_) => "AnnounceIpv6".to_string(),
            Response::Scrape(_) => "Scrape".to_string(),
            Response::Error(e) => format!("Error: {e:?}"),
        };

        let response_kind = match &response {
            Response::Connect(_) => UdpResponseKind::Connect,
            Response::AnnounceIpv4(_) | Response::AnnounceIpv6(_) => UdpResponseKind::Announce,
            Response::Scrape(_) => UdpResponseKind::Scrape,
            Response::Error(_e) => UdpResponseKind::Error,
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

                        if let Some(stats_event_sender) = self.udp_tracker_container.stats_event_sender.as_deref() {
                            match target.ip() {
                                IpAddr::V4(_) => {
                                    stats_event_sender
                                        .send_event(statistics::event::Event::Udp4Response {
                                            kind: response_kind,
                                            req_processing_time,
                                        })
                                        .await;
                                }
                                IpAddr::V6(_) => {
                                    stats_event_sender
                                        .send_event(statistics::event::Event::Udp6Response {
                                            kind: response_kind,
                                            req_processing_time,
                                        })
                                        .await;
                                }
                            }
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
