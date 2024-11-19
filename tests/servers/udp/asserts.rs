use aquatic_udp_protocol::{Response, TransactionId};

pub fn get_error_response_message(response: &Response) -> Option<String> {
    match response {
        Response::Error(error_response) => Some(error_response.message.to_string()),
        _ => None,
    }
}

pub fn is_connect_response(response: &Response, transaction_id: TransactionId) -> bool {
    match response {
        Response::Connect(connect_response) => connect_response.transaction_id == transaction_id,
        _ => false,
    }
}

pub fn is_ipv4_announce_response(response: &Response) -> bool {
    matches!(response, Response::AnnounceIpv4(_))
}

pub fn is_scrape_response(response: &Response) -> bool {
    matches!(response, Response::Scrape(_))
}
