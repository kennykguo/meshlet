//! A one-client UDP relay that forwards opaque datagrams.
//!
//! The relay learns the client's observed endpoint from the first datagram and
//! forwards bytes between that endpoint and one configured upstream peer. It
//! never parses Meshlet handshake or encrypted-packet contents.

use std::net::{SocketAddr, UdpSocket};

const MAX_DATAGRAM_BYTES: usize = 2_048;
const DATAGRAMS_IN_ONE_SECURE_ECHO: usize = 4;

struct RelayState {
    upstream: SocketAddr,
    client: Option<SocketAddr>,
}

impl RelayState {
    fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            client: None,
        }
    }

    fn destination_for(&mut self, source: SocketAddr) -> Result<SocketAddr, String> {
        if source == self.upstream {
            return self
                .client
                .ok_or_else(|| "upstream sent data before a client appeared".to_string());
        }

        match self.client {
            None => {
                self.client = Some(source);
                Ok(self.upstream)
            }
            Some(client) if source == client => Ok(self.upstream),
            Some(client) => Err(format!(
                "one-session relay already serves {client}; rejected {source}"
            )),
        }
    }
}

pub fn run(bind_address: &str, upstream_address: &str) {
    let socket = UdpSocket::bind(bind_address).expect("failed to bind UDP relay socket");
    let upstream: SocketAddr = upstream_address
        .parse()
        .expect("relay upstream must be an IP address and port");
    let mut state = RelayState::new(upstream);
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];

    println!("relay endpoint: {}", socket.local_addr().unwrap());
    println!("upstream peer: {upstream}");
    println!("payload handling: opaque forwarding only");

    for number in 1..=DATAGRAMS_IN_ONE_SECURE_ECHO {
        let (bytes_received, source) = socket
            .recv_from(&mut buffer)
            .expect("failed to receive relayed UDP datagram");
        if bytes_received > MAX_DATAGRAM_BYTES {
            panic!("relayed datagram exceeds {MAX_DATAGRAM_BYTES}-byte limit");
        }

        let destination = state
            .destination_for(source)
            .unwrap_or_else(|error| panic!("cannot route relayed datagram: {error}"));
        socket
            .send_to(&buffer[..bytes_received], destination)
            .expect("failed to forward UDP datagram");

        println!(
            "forwarded {number}/{DATAGRAMS_IN_ONE_SECURE_ECHO}: {source} -> {destination}, {bytes_received} bytes"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_client_and_upstream_are_routed_to_each_other() {
        let client = SocketAddr::from(([203, 0, 113, 1], 50_000));
        let upstream = SocketAddr::from(([192, 0, 2, 20], 7_000));
        let mut relay = RelayState::new(upstream);

        assert_eq!(relay.destination_for(client), Ok(upstream));
        assert_eq!(relay.destination_for(upstream), Ok(client));
        assert_eq!(relay.destination_for(client), Ok(upstream));
    }

    #[test]
    fn one_session_relay_rejects_a_second_client() {
        let client = SocketAddr::from(([203, 0, 113, 1], 50_000));
        let other_client = SocketAddr::from(([203, 0, 113, 2], 50_001));
        let upstream = SocketAddr::from(([192, 0, 2, 20], 7_000));
        let mut relay = RelayState::new(upstream);
        assert_eq!(relay.destination_for(client), Ok(upstream));

        assert!(relay.destination_for(other_client).is_err());
    }
}
