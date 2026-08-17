use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const PROTOCOL_VERSION: &str = "MESHLET/1";
const MAX_DATAGRAM_BYTES: usize = 1_024;
const MAX_NODE_ID_BYTES: usize = 64;
const MAX_LEASE_SECONDS: u64 = 300;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Eq, PartialEq)]
enum Request {
    Register { node_id: String, lease: Duration },
    Lookup { node_id: String },
}

#[derive(Debug, Eq, PartialEq)]
enum Response {
    Registered {
        node_id: String,
        observed_endpoint: SocketAddr,
        lease: Duration,
    },
    Found {
        node_id: String,
        observed_endpoint: SocketAddr,
    },
    NotFound {
        node_id: String,
    },
    Error(String),
}

impl Response {
    fn encode(&self) -> String {
        match self {
            Self::Registered {
                node_id,
                observed_endpoint,
                lease,
            } => format!(
                "{PROTOCOL_VERSION} REGISTERED {node_id} {observed_endpoint} {}",
                lease.as_secs()
            ),
            Self::Found {
                node_id,
                observed_endpoint,
            } => format!("{PROTOCOL_VERSION} FOUND {node_id} {observed_endpoint}"),
            Self::NotFound { node_id } => {
                format!("{PROTOCOL_VERSION} NOT_FOUND {node_id}")
            }
            Self::Error(message) => format!("{PROTOCOL_VERSION} ERROR {message}"),
        }
    }
}

#[derive(Debug)]
struct Registration {
    observed_endpoint: SocketAddr,
    expires_at: Instant,
}

#[derive(Default)]
struct Registry {
    registrations: HashMap<String, Registration>,
}

impl Registry {
    fn handle(&mut self, request: Request, source: SocketAddr, now: Instant) -> Response {
        self.remove_expired(now);

        match request {
            Request::Register { node_id, lease } => {
                let expires_at = now
                    .checked_add(lease)
                    .expect("registration expiration is outside Instant's range");

                self.registrations.insert(
                    node_id.clone(),
                    Registration {
                        observed_endpoint: source,
                        expires_at,
                    },
                );

                Response::Registered {
                    node_id,
                    observed_endpoint: source,
                    lease,
                }
            }
            Request::Lookup { node_id } => match self.registrations.get(&node_id) {
                Some(registration) => Response::Found {
                    node_id,
                    observed_endpoint: registration.observed_endpoint,
                },
                None => Response::NotFound { node_id },
            },
        }
    }

    fn remove_expired(&mut self, now: Instant) {
        self.registrations
            .retain(|_, registration| registration.expires_at > now);
    }
}

fn valid_node_id(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id.len() <= MAX_NODE_ID_BYTES
        && node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn parse_request(message: &[u8]) -> Result<Request, String> {
    let message = std::str::from_utf8(message).map_err(|_| "request is not UTF-8".to_string())?;
    let fields: Vec<_> = message.split_ascii_whitespace().collect();

    match fields.as_slice() {
        [version, "REGISTER", node_id, lease_seconds] if *version == PROTOCOL_VERSION => {
            if !valid_node_id(node_id) {
                return Err("node ID must use 1-64 ASCII letters, digits, '.', '-' or '_'".into());
            }

            let lease_seconds: u64 = lease_seconds
                .parse()
                .map_err(|_| "lease must be an integer number of seconds".to_string())?;

            if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
                return Err(format!(
                    "lease must be between 1 and {MAX_LEASE_SECONDS} seconds"
                ));
            }

            Ok(Request::Register {
                node_id: (*node_id).to_string(),
                lease: Duration::from_secs(lease_seconds),
            })
        }
        [version, "LOOKUP", node_id] if *version == PROTOCOL_VERSION => {
            if !valid_node_id(node_id) {
                return Err("node ID must use 1-64 ASCII letters, digits, '.', '-' or '_'".into());
            }

            Ok(Request::Lookup {
                node_id: (*node_id).to_string(),
            })
        }
        [version, ..] if *version != PROTOCOL_VERSION => {
            Err(format!("unsupported protocol version '{version}'"))
        }
        _ => Err(
            "expected 'MESHLET/1 REGISTER NODE_ID LEASE_SECONDS' or 'MESHLET/1 LOOKUP NODE_ID'"
                .into(),
        ),
    }
}

pub fn run_server(bind_address: &str) {
    let socket = UdpSocket::bind(bind_address).expect("failed to bind coordinator UDP socket");
    let mut registry = Registry::default();
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];

    println!("coordinator listening: {}", socket.local_addr().unwrap());
    println!("authentication: disabled (learning stage)");
    println!("press Ctrl-C to stop");

    loop {
        let (bytes_received, source) = socket
            .recv_from(&mut buffer)
            .expect("failed to receive coordinator request");

        let response = if bytes_received > MAX_DATAGRAM_BYTES {
            Response::Error(format!("request exceeds {MAX_DATAGRAM_BYTES}-byte limit"))
        } else {
            match parse_request(&buffer[..bytes_received]) {
                Ok(request) => registry.handle(request, source, Instant::now()),
                Err(message) => Response::Error(message),
            }
        };

        let encoded = response.encode();
        socket
            .send_to(encoded.as_bytes(), source)
            .expect("failed to send coordinator response");

        println!("source: {source}");
        println!("response: {encoded}");
    }
}

fn exchange(bind_address: &str, server_address: &str, request: &str) {
    let socket = UdpSocket::bind(bind_address).expect("failed to bind coordinator client socket");
    socket
        .connect(server_address)
        .expect("failed to select coordinator server");
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("failed to set coordinator response timeout");

    println!("local: {}", socket.local_addr().unwrap());
    println!("coordinator: {}", socket.peer_addr().unwrap());
    println!("request: {request}");

    socket
        .send(request.as_bytes())
        .expect("failed to send coordinator request");

    let mut response = [0_u8; MAX_DATAGRAM_BYTES];
    let bytes_received = socket
        .recv(&mut response)
        .expect("failed to receive coordinator response within two seconds");
    let response = std::str::from_utf8(&response[..bytes_received])
        .expect("coordinator response is not UTF-8");

    println!("response: {response}");
}

pub fn register(bind_address: &str, server_address: &str, node_id: &str, lease_seconds: u64) {
    let request = format!("{PROTOCOL_VERSION} REGISTER {node_id} {lease_seconds}");
    exchange(bind_address, server_address, &request);
}

pub fn lookup(bind_address: &str, server_address: &str, node_id: &str) {
    let request = format!("{PROTOCOL_VERSION} LOOKUP {node_id}");
    exchange(bind_address, server_address, &request);
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT_A: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40_000);
    const ENDPOINT_B: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40_001);

    #[test]
    fn parses_versioned_register_request() {
        assert_eq!(
            parse_request(b"MESHLET/1 REGISTER mesh-a 30"),
            Ok(Request::Register {
                node_id: "mesh-a".into(),
                lease: Duration::from_secs(30),
            })
        );
    }

    #[test]
    fn register_records_observed_source_endpoint() {
        let now = Instant::now();
        let mut registry = Registry::default();

        let response = registry.handle(
            Request::Register {
                node_id: "mesh-a".into(),
                lease: Duration::from_secs(30),
            },
            ENDPOINT_A,
            now,
        );

        assert_eq!(
            response,
            Response::Registered {
                node_id: "mesh-a".into(),
                observed_endpoint: ENDPOINT_A,
                lease: Duration::from_secs(30),
            }
        );
        assert_eq!(
            registry.handle(
                Request::Lookup {
                    node_id: "mesh-a".into(),
                },
                ENDPOINT_B,
                now,
            ),
            Response::Found {
                node_id: "mesh-a".into(),
                observed_endpoint: ENDPOINT_A,
            }
        );
    }

    #[test]
    fn registration_is_absent_at_expiration_boundary() {
        let now = Instant::now();
        let lease = Duration::from_secs(30);
        let mut registry = Registry::default();

        registry.handle(
            Request::Register {
                node_id: "mesh-a".into(),
                lease,
            },
            ENDPOINT_A,
            now,
        );

        assert_eq!(
            registry.handle(
                Request::Lookup {
                    node_id: "mesh-a".into(),
                },
                ENDPOINT_B,
                now + lease,
            ),
            Response::NotFound {
                node_id: "mesh-a".into(),
            }
        );
    }

    #[test]
    fn repeated_registration_refreshes_location_and_deadline() {
        let now = Instant::now();
        let lease = Duration::from_secs(30);
        let mut registry = Registry::default();

        registry.handle(
            Request::Register {
                node_id: "mesh-a".into(),
                lease,
            },
            ENDPOINT_A,
            now,
        );
        registry.handle(
            Request::Register {
                node_id: "mesh-a".into(),
                lease,
            },
            ENDPOINT_B,
            now + Duration::from_secs(20),
        );

        assert_eq!(
            registry.handle(
                Request::Lookup {
                    node_id: "mesh-a".into(),
                },
                ENDPOINT_A,
                now + Duration::from_secs(45),
            ),
            Response::Found {
                node_id: "mesh-a".into(),
                observed_endpoint: ENDPOINT_B,
            }
        );
    }

    #[test]
    fn rejects_invalid_node_id_and_lease() {
        assert!(parse_request(b"MESHLET/1 REGISTER mesh/a 30").is_err());
        assert!(parse_request(b"MESHLET/1 REGISTER mesh-a 0").is_err());
        assert!(parse_request(b"MESHLET/1 REGISTER mesh-a 301").is_err());
    }

    #[test]
    fn rejects_unknown_protocol_version() {
        assert_eq!(
            parse_request(b"MESHLET/2 LOOKUP mesh-a"),
            Err("unsupported protocol version 'MESHLET/2'".into())
        );
    }
}
