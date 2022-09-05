use std::net::SocketAddr;

use aquatic_udp_protocol::ConnectionId;

use super::{cypher::{BlowfishCypher, Cypher}, secret::Secret, timestamp_64::Timestamp64, client_id::ClientId, timestamp_32::Timestamp32};

pub trait ConnectionIdIssuer {
    type Error;

    fn new_connection_id(&self, remote_address: &SocketAddr, current_timestamp: Timestamp64) -> ConnectionId;
    
    fn verify_connection_id(&self, connection_id: ConnectionId, remote_address: &SocketAddr, current_timestamp: Timestamp64) -> Result<(), Self::Error>;
}

/// An implementation of a ConnectionIdIssuer by encrypting the connection id
pub struct EncryptedConnectionIdIssuer {
    cypher: BlowfishCypher
}

impl EncryptedConnectionIdIssuer {

    pub fn new(secret: Secret) -> Self {
        let cypher = BlowfishCypher::new(secret);
        Self {
            cypher
        }
    }
}

impl ConnectionIdIssuer for EncryptedConnectionIdIssuer {
    type Error = &'static str;

    fn new_connection_id(&self, remote_address: &SocketAddr, current_timestamp: Timestamp64) -> ConnectionId {
        let client_id = ClientId::from_socket_address(remote_address).to_bytes();

        let expiration_timestamp: Timestamp32 = (current_timestamp + 120).try_into().unwrap();
    
        let connection_id = concat(client_id, expiration_timestamp.to_le_bytes());
    
        let encrypted_connection_id = self.cypher.encrypt(&connection_id);
    
        ConnectionId(byte_array_to_i64(encrypted_connection_id))
    }

    fn verify_connection_id(&self, connection_id: ConnectionId, remote_address: &SocketAddr, current_timestamp: Timestamp64) -> Result<(), Self::Error> {
        let encrypted_connection_id = connection_id.0.to_le_bytes();

        let decrypted_connection_id = self.cypher.decrypt(&encrypted_connection_id);
    
        let client_id = extract_client_id(&decrypted_connection_id);
    
        let expected_client_id = ClientId::from_socket_address(remote_address);
        if client_id != expected_client_id {
            return Err("Invalid client id")
        }
    
        let expiration_timestamp = extract_timestamp(&decrypted_connection_id);
    
        if expiration_timestamp < current_timestamp {
            return Err("Expired connection id")
        }
    
        Ok(())
    }
}

/// Contact two 4-byte arrays
fn concat(remote_id: [u8; 4], timestamp: [u8; 4]) -> [u8; 8] {
    let connection_id: Vec<u8> = [
        remote_id.as_slice(),
        timestamp.as_slice(),
    ].concat();

    let connection_as_array: [u8; 8] = connection_id.try_into().unwrap();

    connection_as_array
}

fn extract_timestamp(decrypted_connection_id: &[u8; 8]) -> Timestamp64 {
    let timestamp_bytes = &decrypted_connection_id[4..];
    let timestamp = Timestamp32::from_le_bytes(timestamp_bytes);
    timestamp.into()
}

fn extract_client_id(decrypted_connection_id: &[u8; 8]) -> ClientId {
    ClientId::from_slice(&decrypted_connection_id[..4])
}

fn byte_array_to_i64(connection_id: [u8;8]) -> i64 {
    i64::from_le_bytes(connection_id)
}

#[cfg(test)]
mod tests {
    use crate::udp::connection::{secret::Secret, connection_id_issuer::{EncryptedConnectionIdIssuer, ConnectionIdIssuer}};
    
    use std::{net::{SocketAddr, IpAddr, Ipv4Addr}};

    fn cypher_secret_for_testing() -> Secret {
        Secret::new([0u8;32])
    }

    fn new_issuer() -> EncryptedConnectionIdIssuer {
        let issuer = EncryptedConnectionIdIssuer::new(cypher_secret_for_testing());
        issuer
    }

    #[test]
    fn it_should_be_valid_for_two_minutes_after_the_generation() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let now = 946684800u64; // 01-01-2000 00:00:00

        let issuer = new_issuer();

        let connection_id = issuer.new_connection_id(&client_addr, now);

        assert_eq!(issuer.verify_connection_id(connection_id, &client_addr, now), Ok(()));

        let after_two_minutes = now + (2*60) - 1;

        assert_eq!(issuer.verify_connection_id(connection_id, &client_addr, after_two_minutes), Ok(()));
    }

    #[test]
    fn it_should_expire_after_two_minutes_from_the_generation() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let now = 946684800u64;

        let issuer = new_issuer();

        let connection_id = issuer.new_connection_id(&client_addr, now);

        let after_more_than_two_minutes = now + (2*60) + 1;

        assert_eq!(issuer.verify_connection_id(connection_id, &client_addr, after_more_than_two_minutes), Err("Expired connection id"));
    }    

    #[test]
    fn it_should_change_for_the_same_client_ip_and_port_after_two_minutes() {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let now = 946684800u64;

        let issuer = new_issuer();

        let connection_id = issuer.new_connection_id( &client_addr, now);

        let after_two_minutes = now + 120;

        let connection_id_after_two_minutes = issuer.new_connection_id(&client_addr, after_two_minutes);

        assert_ne!(connection_id, connection_id_after_two_minutes);
    }

    #[test]
    fn it_should_be_different_for_each_client_at_the_same_time_if_they_use_a_different_ip() {
        let client_1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0001);
        let client_2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0001);

        let now = 946684800u64;

        let issuer = new_issuer();

        let connection_id_for_client_1 = issuer.new_connection_id(&client_1_addr, now);
        let connection_id_for_client_2 = issuer.new_connection_id(&client_2_addr, now);

        assert_ne!(connection_id_for_client_1, connection_id_for_client_2);
    }

    #[test]
    fn it_should_be_different_for_each_client_at_the_same_time_if_they_use_a_different_port() {
        let client_1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0001);
        let client_2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0002);

        let now = 946684800u64;

        let issuer = new_issuer();

        let connection_id_for_client_1 = issuer.new_connection_id(&client_1_addr, now);
        let connection_id_for_client_2 = issuer.new_connection_id(&client_2_addr, now);

        assert_ne!(connection_id_for_client_1, connection_id_for_client_2);
    }
}