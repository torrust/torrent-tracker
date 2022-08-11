use std::{net::SocketAddr, time::SystemTime};
use aquatic_udp_protocol::ConnectionId;

/// It generates a connection id needed for the BitTorrent UDP Tracker Protocol
pub fn get_connection_id(remote_address: &SocketAddr, current_timestamp: u64) -> ConnectionId {
    ConnectionId(((current_timestamp / 3600) | ((remote_address.port() as u64) << 36)) as i64)
}

pub fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH).unwrap()
        .as_secs()
}

/// Serializer for `std::time::Instant` type.
/// Before serializing, it converts the instant to time elapse since that instant in milliseconds.
///
/// You can use it like this:
///
/// ```text
/// #[serde(serialize_with = "ser_instant")]
/// pub updated: std::time::Instant,
/// ```
///
pub fn ser_instant<S: serde::Serializer>(inst: &std::time::Instant, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_u64(inst.elapsed().as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use std::{time::Instant, net::{SocketAddr, IpAddr, Ipv4Addr}};

    #[test]
    fn connection_id_is_generated_based_on_remote_client_port_an_hours_passed_since_unix_epoch() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0001);

        let timestamp = 946684800u64; // GTM: Sat Jan 01 2000 00:00:00 GMT+0000

        // Timestamp in hours 946684800u64 / 3600 = 262968 = 0x_0000_0000_0004_0338 = 262968
        // Port 0001                                       = 0x_0000_0000_0000_0001 = 1
        // Port 0001 << 36                                 = 0x_0000_0010_0000_0000 = 68719476736
        //
        // 0x_0000_0000_0004_0338 | 0x_0000_0010_0000_0000 = 0x_0000_0010_0004_0338 = 68719739704
        //
        // HEX                      BIN                                         DEC
        // --------------------------------------------------------------------------------
        // 0x_0000_0000_0004_0338 = ... 0000000000000000001000000001100111000 =      262968
        //         OR
        // 0x_0000_0010_0000_0000 = ... 1000000000000000000000000000000000000 = 68719476736
        // -------------------------------------------------------------------
        // 0x_0000_0010_0004_0338 = ... 1000000000000000001000000001100111000 = 68719739704

        // Assert intermediary values
        assert_eq!(timestamp / 3600, 0x_0000_0000_0004_0338);
        assert_eq!((client_addr.port() as u64), 1);
        assert_eq!(((client_addr.port() as u64) << 36), 0x_0000_0010_0000_0000); // 68719476736
        assert_eq!((0x_0000_0000_0004_0338u64 | 0x_0000_0010_0000_0000u64), 0x_0000_0010_0004_0338u64); // 68719739704
        assert_eq!(0x_0000_0010_0004_0338u64 as i64, 68719739704); // 68719739704

        let connection_id = super::get_connection_id(&client_addr, timestamp);

        assert_eq!(connection_id, ConnectionId(68719739704));
    }

    #[test]
    fn connection_id_in_udp_tracker_should_be_the_same_for_one_client_during_one_hour() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let now = 946684800u64;

        let connection_id = get_connection_id(&client_addr, now);

        let in_one_hour = now + 3600 - 1;

        let connection_id_after_one_hour = get_connection_id(&client_addr, in_one_hour);

        assert_eq!(connection_id, connection_id_after_one_hour);
    }

    #[test]
    fn connection_id_in_udp_tracker_should_change_for_the_same_client_and_port_after_one_hour() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let now = 946684800u64;

        let connection_id = get_connection_id(&client_addr, now);

        let after_one_hour = now + 3600;

        let connection_id_after_one_hour = get_connection_id(&client_addr, after_one_hour);

        assert_ne!(connection_id, connection_id_after_one_hour);
    }    

    #[test]
    fn connection_id_in_udp_tracker_should_be_different_for_each_client_at_the_same_time_if_they_use_a_different_port() {
        let client_1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0001);
        let client_2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0002);

        let now = 946684800u64;

        let connection_id_for_client_1 = get_connection_id(&client_1_addr, now);
        let connection_id_for_client_2 = get_connection_id(&client_2_addr, now);

        assert_ne!(connection_id_for_client_1, connection_id_for_client_2);
    }

    #[test]
    fn connection_id_in_udp_tracker_should_expire_after_one_hour() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let now = 946684800u64;

        let connection_id_1 = get_connection_id(&client_addr, now);

        let in_one_hour = now + 3600;

        let connection_id_2 = get_connection_id(&client_addr, in_one_hour);

        assert_ne!(connection_id_1, connection_id_2);
    }

    use aquatic_udp_protocol::ConnectionId;
    use serde::Serialize;

    use crate::protocol::utils::get_connection_id;

    #[warn(unused_imports)]
    use super::ser_instant;

    #[derive(PartialEq, Eq, Debug, Clone, Serialize)]
    struct S {
        #[serde(serialize_with = "ser_instant")]
        pub time: Instant,
    }

    #[test]
    fn instant_types_can_be_serialized_as_elapsed_time_since_that_instant_in_milliseconds() {

        use std::{thread, time};

        let t1 = time::Instant::now();

        let s = S { time: t1 };

        // Sleep 10 milliseconds
        let ten_millis = time::Duration::from_millis(10);
        thread::sleep(ten_millis);

        let json_serialized_value = serde_json::to_string(&s).unwrap();

        // Json contains time duration since t1 instant in milliseconds
        assert_eq!(json_serialized_value, r#"{"time":10}"#);
    }
}