//! UDP control-plane registration, endpoint lookup, and route advertisement.
//!
//! `MESHLET/1` is the unauthenticated learning protocol. `MESHLET/2` adds a
//! one-use signed challenge for node registration while retaining endpoint lookup.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use ed25519_dalek::Signature;

#[cfg(test)]
use crate::identity::Identity;
use crate::identity::{self, Authorizations};
use crate::routing::{Ipv4Prefix, RouteRegistry};

const PROTOCOL_VERSION: &str = "MESHLET/1";
const AUTH_PROTOCOL_VERSION: &str = "MESHLET/2";
const MAX_DATAGRAM_BYTES: usize = 1_024;
const MAX_NODE_ID_BYTES: usize = 64;
const MAX_LEASE_SECONDS: u64 = 300;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
const CHALLENGE_BYTES: usize = 32;
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(10);

#[derive(Debug, Eq, PartialEq)]
enum Request {
    Register {
        node_id: String,
        lease: Duration,
    },
    Lookup {
        node_id: String,
    },
    AdvertiseRoute {
        node_id: String,
        prefix: Ipv4Prefix,
        lease: Duration,
    },
    RouteLookup {
        destination: Ipv4Addr,
    },
}

#[derive(Debug)]
enum AuthRequest {
    Challenge {
        node_id: String,
    },
    Register {
        node_id: String,
        lease: Duration,
        challenge: [u8; CHALLENGE_BYTES],
        signature: Signature,
    },
    Lookup {
        node_id: String,
    },
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
    RouteAdvertised {
        node_id: String,
        prefix: Ipv4Prefix,
        lease: Duration,
    },
    RouteFound {
        destination: Ipv4Addr,
        prefix: Ipv4Prefix,
        node_id: String,
    },
    RouteNotFound {
        destination: Ipv4Addr,
    },
    Error(String),
}

#[derive(Debug, Eq, PartialEq)]
enum AuthResponse {
    Challenge {
        node_id: String,
        challenge: [u8; CHALLENGE_BYTES],
    },
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

impl AuthResponse {
    /// Serializes one authenticated coordinator response into protocol text.
    /// Called by `run_authenticated_server` immediately before sending a reply.
    fn encode(&self) -> String {
        match self {
            Self::Challenge { node_id, challenge } => format!(
                "{AUTH_PROTOCOL_VERSION} CHALLENGE {node_id} {}",
                identity::encode_hex(challenge)
            ),
            Self::Registered {
                node_id,
                observed_endpoint,
                lease,
            } => format!(
                "{AUTH_PROTOCOL_VERSION} REGISTERED {node_id} {observed_endpoint} {}",
                lease.as_secs()
            ),
            Self::Found {
                node_id,
                observed_endpoint,
            } => format!("{AUTH_PROTOCOL_VERSION} FOUND {node_id} {observed_endpoint}"),
            Self::NotFound { node_id } => {
                format!("{AUTH_PROTOCOL_VERSION} NOT_FOUND {node_id}")
            }
            Self::Error(message) => format!("{AUTH_PROTOCOL_VERSION} ERROR {message}"),
        }
    }
}

impl Response {
    /// Serializes one learning-protocol coordinator response into protocol text.
    /// Called by `run_server` immediately before sending a reply.
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
            Self::RouteAdvertised {
                node_id,
                prefix,
                lease,
            } => format!(
                "{PROTOCOL_VERSION} ROUTE_ADVERTISED {node_id} {prefix} {}",
                lease.as_secs()
            ),
            Self::RouteFound {
                destination,
                prefix,
                node_id,
            } => format!("{PROTOCOL_VERSION} ROUTE_FOUND {destination} {prefix} {node_id}"),
            Self::RouteNotFound { destination } => {
                format!("{PROTOCOL_VERSION} ROUTE_NOT_FOUND {destination}")
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
    routes: RouteRegistry,
}

impl Registry {
    /// Applies one parsed registration, lookup, advertisement, or route lookup.
    /// Called by `run_server` for each request and directly by registry tests.
    fn handle(&mut self, request: Request, source: SocketAddr, now: Instant) -> Response {
        self.remove_expired(now);

        match request {
            Request::Register { node_id, lease } => {
                let expires_at = now
                    .checked_add(lease)
                    .expect("registration expiration is outside Instant's range");

                // Record the UDP source observed by the server, not an address
                // claimed inside the request, so NAT translation is visible.
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
            Request::AdvertiseRoute {
                node_id,
                prefix,
                lease,
            } => {
                self.routes.advertise(&node_id, prefix, lease, now);
                Response::RouteAdvertised {
                    node_id,
                    prefix,
                    lease,
                }
            }
            Request::RouteLookup { destination } => match self.routes.lookup(destination, now) {
                Some(route) => Response::RouteFound {
                    destination,
                    prefix: route.prefix,
                    node_id: route.node_id,
                },
                None => Response::RouteNotFound { destination },
            },
        }
    }

    /// Deletes node registrations whose lease deadline is at or before `now`.
    /// Called by `handle` and authenticated coordinator expiration cleanup.
    fn remove_expired(&mut self, now: Instant) {
        self.registrations
            .retain(|_, registration| registration.expires_at > now);
    }
}

#[derive(Debug)]
struct PendingChallenge {
    value: [u8; CHALLENGE_BYTES],
    expires_at: Instant,
}

struct AuthenticatedCoordinator {
    registry: Registry,
    authorizations: Authorizations,
    challenges: HashMap<(String, SocketAddr), PendingChallenge>,
}

impl AuthenticatedCoordinator {
    /// Creates authenticated coordinator state from a trusted public-key set.
    /// Called by `run_authenticated_server` and authenticated test fixtures.
    fn new(authorizations: Authorizations) -> Self {
        Self {
            registry: Registry::default(),
            authorizations,
            challenges: HashMap::new(),
        }
    }

    /// Stores a short-lived challenge bound to one node ID and source endpoint.
    /// Called by `run_authenticated_server` and authentication tests.
    fn issue_challenge(
        &mut self,
        node_id: String,
        source: SocketAddr,
        now: Instant,
        challenge: [u8; CHALLENGE_BYTES],
    ) -> AuthResponse {
        self.remove_expired(now);

        if self.authorizations.get(&node_id).is_none() {
            return AuthResponse::Error("node ID is not authorized".into());
        }

        let expires_at = now
            .checked_add(CHALLENGE_LIFETIME)
            .expect("challenge expiration is outside Instant's range");
        self.challenges.insert(
            (node_id.clone(), source),
            PendingChallenge {
                value: challenge,
                expires_at,
            },
        );

        AuthResponse::Challenge { node_id, challenge }
    }

    /// Verifies and consumes a challenge before recording the observed endpoint.
    /// Called by `run_authenticated_server` and authentication tests.
    fn register(
        &mut self,
        node_id: String,
        lease: Duration,
        challenge: [u8; CHALLENGE_BYTES],
        signature: Signature,
        source: SocketAddr,
        now: Instant,
    ) -> AuthResponse {
        self.remove_expired(now);

        // Removing before verification makes every issued challenge one-use,
        // including a failed attempt, rather than leaving replayable state.
        let Some(pending) = self.challenges.remove(&(node_id.clone(), source)) else {
            return AuthResponse::Error(
                "no unexpired challenge exists for this node and source endpoint".into(),
            );
        };

        if pending.value != challenge {
            return AuthResponse::Error("challenge does not match the issued value".into());
        }

        let Some(verifying_key) = self.authorizations.get(&node_id) else {
            return AuthResponse::Error("node ID is not authorized".into());
        };
        let signed_message = registration_signing_message(&node_id, lease, &challenge);
        if verifying_key
            .verify_strict(&signed_message, &signature)
            .is_err()
        {
            return AuthResponse::Error("signature verification failed".into());
        }

        let expires_at = now
            .checked_add(lease)
            .expect("registration expiration is outside Instant's range");
        self.registry.registrations.insert(
            node_id.clone(),
            Registration {
                observed_endpoint: source,
                expires_at,
            },
        );

        AuthResponse::Registered {
            node_id,
            observed_endpoint: source,
            lease,
        }
    }

    /// Returns an authenticated node's current unexpired observed endpoint.
    /// Called by `run_authenticated_server` and authentication tests.
    fn lookup(&mut self, node_id: String, now: Instant) -> AuthResponse {
        self.remove_expired(now);

        match self.registry.registrations.get(&node_id) {
            Some(registration) => AuthResponse::Found {
                node_id,
                observed_endpoint: registration.observed_endpoint,
            },
            None => AuthResponse::NotFound { node_id },
        }
    }

    /// Deletes expired registrations and pending authentication challenges.
    /// Called before authenticated challenge issuance, registration, and lookup.
    fn remove_expired(&mut self, now: Instant) {
        self.registry.remove_expired(now);
        self.challenges
            .retain(|_, challenge| challenge.expires_at > now);
    }
}

/// Reports whether a node ID fits the protocol's bounded ASCII grammar.
/// Called by coordinator parsers plus identity and handshake validation.
pub(crate) fn valid_node_id(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id.len() <= MAX_NODE_ID_BYTES
        && node_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Parses one `MESHLET/1` datagram into a typed control-plane request.
/// Called by `run_server` and unauthenticated protocol tests.
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
        [version, "ADVERTISE_ROUTE", node_id, prefix, lease_seconds]
            if *version == PROTOCOL_VERSION =>
        {
            validate_node_id(node_id)?;
            let prefix = prefix.parse()?;
            let lease = parse_lease(lease_seconds)?;
            Ok(Request::AdvertiseRoute {
                node_id: (*node_id).to_string(),
                prefix,
                lease,
            })
        }
        [version, "ROUTE_LOOKUP", destination] if *version == PROTOCOL_VERSION => {
            let destination = destination
                .parse()
                .map_err(|_| "route destination must be an IPv4 address".to_string())?;
            Ok(Request::RouteLookup { destination })
        }
        [version, ..] if *version != PROTOCOL_VERSION => {
            Err(format!("unsupported protocol version '{version}'"))
        }
        _ => Err(
            "expected a node registration, node lookup, route advertisement, or route lookup"
                .into(),
        ),
    }
}

/// Parses one `MESHLET/2` datagram into a typed authenticated request.
/// Called by `run_authenticated_server` before dispatching each datagram.
fn parse_auth_request(message: &[u8]) -> Result<AuthRequest, String> {
    let message = std::str::from_utf8(message).map_err(|_| "request is not UTF-8".to_string())?;
    let fields: Vec<_> = message.split_ascii_whitespace().collect();

    match fields.as_slice() {
        [version, "CHALLENGE", node_id] if *version == AUTH_PROTOCOL_VERSION => {
            validate_node_id(node_id)?;
            Ok(AuthRequest::Challenge {
                node_id: (*node_id).to_string(),
            })
        }
        [
            version,
            "REGISTER",
            node_id,
            lease_seconds,
            challenge_hex,
            signature_hex,
        ] if *version == AUTH_PROTOCOL_VERSION => {
            validate_node_id(node_id)?;
            let lease = parse_lease(lease_seconds)?;
            let challenge = identity::decode_hex_array::<CHALLENGE_BYTES>(challenge_hex)?;
            let signature_bytes = identity::decode_hex_array::<64>(signature_hex)?;
            let signature = Signature::try_from(signature_bytes.as_slice())
                .map_err(|error| format!("invalid signature encoding: {error}"))?;

            Ok(AuthRequest::Register {
                node_id: (*node_id).to_string(),
                lease,
                challenge,
                signature,
            })
        }
        [version, "LOOKUP", node_id] if *version == AUTH_PROTOCOL_VERSION => {
            validate_node_id(node_id)?;
            Ok(AuthRequest::Lookup {
                node_id: (*node_id).to_string(),
            })
        }
        [version, ..] if *version != AUTH_PROTOCOL_VERSION => Err(format!(
            "unsupported authenticated protocol version '{version}'"
        )),
        _ => Err(format!(
            "expected '{AUTH_PROTOCOL_VERSION} CHALLENGE NODE_ID', '{AUTH_PROTOCOL_VERSION} REGISTER NODE_ID LEASE_SECONDS CHALLENGE_HEX SIGNATURE_HEX', or '{AUTH_PROTOCOL_VERSION} LOOKUP NODE_ID'"
        )),
    }
}

/// Converts the node-ID predicate into a descriptive `Result` error.
/// Called by request parsers and the route-advertisement client.
fn validate_node_id(node_id: &str) -> Result<(), String> {
    if valid_node_id(node_id) {
        Ok(())
    } else {
        Err("node ID must use 1-64 ASCII letters, digits, '.', '-' or '_'".into())
    }
}

/// Parses and bounds a lease duration expressed as decimal seconds.
/// Called by both protocol parsers and registration/advertisement clients.
fn parse_lease(lease_seconds: &str) -> Result<Duration, String> {
    let lease_seconds: u64 = lease_seconds
        .parse()
        .map_err(|_| "lease must be an integer number of seconds".to_string())?;

    if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
        return Err(format!(
            "lease must be between 1 and {MAX_LEASE_SECONDS} seconds"
        ));
    }

    Ok(Duration::from_secs(lease_seconds))
}

/// Builds the canonical bytes covered by an authenticated registration signature.
/// Called by authenticated client/server registration and authentication tests.
fn registration_signing_message(
    node_id: &str,
    lease: Duration,
    challenge: &[u8; CHALLENGE_BYTES],
) -> Vec<u8> {
    format!(
        "MESHLET-REGISTER-SIGNATURE/2\nnode-id:{node_id}\nlease-seconds:{}\nchallenge:{}\n",
        lease.as_secs(),
        identity::encode_hex(challenge)
    )
    .into_bytes()
}

/// Runs the unauthenticated UDP coordinator request loop.
/// Called by `main` for `coordinator-server` and `coordinator-route-server`.
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

/// Runs the challenge-based authenticated UDP coordinator request loop.
/// Called by `main` for the `coordinator-server-auth` command.
pub fn run_authenticated_server(bind_address: &str, authorization_path: &str) {
    let socket =
        UdpSocket::bind(bind_address).expect("failed to bind authenticated coordinator UDP socket");
    let authorizations = Authorizations::load(authorization_path)
        .unwrap_or_else(|error| panic!("failed to load coordinator authorizations: {error}"));
    let authorized_nodes = authorizations.len();
    let mut coordinator = AuthenticatedCoordinator::new(authorizations);
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];

    println!(
        "authenticated coordinator: {}",
        socket.local_addr().unwrap()
    );
    println!("authorized nodes: {authorized_nodes}");
    println!(
        "challenge lifetime: {} seconds",
        CHALLENGE_LIFETIME.as_secs()
    );
    println!("press Ctrl-C to stop");

    loop {
        let (bytes_received, source) = socket
            .recv_from(&mut buffer)
            .expect("failed to receive authenticated coordinator request");
        let now = Instant::now();

        let response = if bytes_received > MAX_DATAGRAM_BYTES {
            AuthResponse::Error(format!("request exceeds {MAX_DATAGRAM_BYTES}-byte limit"))
        } else {
            match parse_auth_request(&buffer[..bytes_received]) {
                Ok(AuthRequest::Challenge { node_id }) => {
                    let mut challenge = [0_u8; CHALLENGE_BYTES];
                    match getrandom::fill(&mut challenge) {
                        Ok(()) => coordinator.issue_challenge(node_id, source, now, challenge),
                        Err(error) => AuthResponse::Error(format!(
                            "operating system failed to generate a challenge: {error}"
                        )),
                    }
                }
                Ok(AuthRequest::Register {
                    node_id,
                    lease,
                    challenge,
                    signature,
                }) => coordinator.register(node_id, lease, challenge, signature, source, now),
                Ok(AuthRequest::Lookup { node_id }) => coordinator.lookup(node_id, now),
                Err(message) => AuthResponse::Error(message),
            }
        };

        let encoded = response.encode();
        socket
            .send_to(encoded.as_bytes(), source)
            .expect("failed to send authenticated coordinator response");

        println!("source: {source}");
        println!("response: {encoded}");
    }
}

/// Sends one textual UDP request and prints its textual response.
/// Called by simple registration, lookup, and route client wrappers.
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

/// Sends an unauthenticated leased endpoint registration request.
/// Called by `main` for the `coordinator-register` command.
pub fn register(bind_address: &str, server_address: &str, node_id: &str, lease_seconds: u64) {
    let request = format!("{PROTOCOL_VERSION} REGISTER {node_id} {lease_seconds}");
    exchange(bind_address, server_address, &request);
}

/// Sends an unauthenticated lookup request for a node's observed endpoint.
/// Called by `main` for the `coordinator-lookup` command.
pub fn lookup(bind_address: &str, server_address: &str, node_id: &str) {
    let request = format!("{PROTOCOL_VERSION} LOOKUP {node_id}");
    exchange(bind_address, server_address, &request);
}

/// Completes challenge-response registration using a node's private identity.
/// Called by `main` for the `coordinator-register-auth` command.
pub fn register_authenticated(
    bind_address: &str,
    server_address: &str,
    node_id: &str,
    lease_seconds: u64,
    identity_path: &str,
) {
    let identity = identity::load_identity(identity_path)
        .unwrap_or_else(|error| panic!("failed to load node identity: {error}"));
    assert_eq!(
        identity.node_id(),
        node_id,
        "command node ID does not match identity file"
    );

    let lease = parse_lease(&lease_seconds.to_string())
        .unwrap_or_else(|error| panic!("invalid lease: {error}"));
    let socket = UdpSocket::bind(bind_address)
        .expect("failed to bind authenticated coordinator client socket");
    socket
        .connect(server_address)
        .expect("failed to select authenticated coordinator server");
    socket
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .expect("failed to set authenticated coordinator response timeout");

    println!("local: {}", socket.local_addr().unwrap());
    println!("coordinator: {}", socket.peer_addr().unwrap());

    let challenge_request = format!("{AUTH_PROTOCOL_VERSION} CHALLENGE {node_id}");
    println!("challenge request: {challenge_request}");
    socket
        .send(challenge_request.as_bytes())
        .expect("failed to send coordinator challenge request");

    let challenge_response = receive_connected(&socket, "challenge response");
    println!("challenge response: {challenge_response}");
    let challenge = parse_challenge_response(&challenge_response, node_id)
        .unwrap_or_else(|error| panic!("invalid coordinator challenge response: {error}"));

    let signed_message = registration_signing_message(node_id, lease, &challenge);
    let signature = identity.sign(&signed_message);
    let register_request = format!(
        "{AUTH_PROTOCOL_VERSION} REGISTER {node_id} {} {} {}",
        lease.as_secs(),
        identity::encode_hex(&challenge),
        identity::encode_hex(&signature.to_bytes())
    );
    println!(
        "signed registration: node={node_id} lease={}s",
        lease.as_secs()
    );
    socket
        .send(register_request.as_bytes())
        .expect("failed to send signed coordinator registration");

    let registration_response = receive_connected(&socket, "registration response");
    println!("registration response: {registration_response}");
}

/// Sends a `MESHLET/2` lookup request without changing coordinator state.
/// Called by `main` for the `coordinator-lookup-auth` command.
pub fn lookup_authenticated(bind_address: &str, server_address: &str, node_id: &str) {
    let request = format!("{AUTH_PROTOCOL_VERSION} LOOKUP {node_id}");
    exchange(bind_address, server_address, &request);
}

/// Validates and sends a leased node-to-IPv4-prefix advertisement.
/// Called by `main` for the `coordinator-advertise-route` command.
pub fn advertise_route(
    bind_address: &str,
    server_address: &str,
    node_id: &str,
    prefix: &str,
    lease_seconds: u64,
) {
    validate_node_id(node_id).unwrap_or_else(|error| panic!("invalid node ID: {error}"));
    let prefix: Ipv4Prefix = prefix
        .parse()
        .unwrap_or_else(|error| panic!("invalid advertised prefix: {error}"));
    let lease = parse_lease(&lease_seconds.to_string())
        .unwrap_or_else(|error| panic!("invalid route lease: {error}"));
    let request = format!(
        "{PROTOCOL_VERSION} ADVERTISE_ROUTE {node_id} {prefix} {}",
        lease.as_secs()
    );
    exchange(bind_address, server_address, &request);
}

/// Validates and sends a route lookup for one IPv4 destination.
/// Called by `main` for the `coordinator-route-lookup` command.
pub fn route_lookup(bind_address: &str, server_address: &str, destination: &str) {
    let destination: Ipv4Addr = destination
        .parse()
        .unwrap_or_else(|_| panic!("route destination must be an IPv4 address"));
    let request = format!("{PROTOCOL_VERSION} ROUTE_LOOKUP {destination}");
    exchange(bind_address, server_address, &request);
}

/// Receives one bounded UTF-8 datagram from an already connected UDP socket.
/// Called twice by `register_authenticated` for challenge and registration replies.
fn receive_connected(socket: &UdpSocket, description: &str) -> String {
    let mut response = [0_u8; MAX_DATAGRAM_BYTES];
    let bytes_received = socket.recv(&mut response).unwrap_or_else(|error| {
        panic!("failed to receive {description} within two seconds: {error}")
    });
    std::str::from_utf8(&response[..bytes_received])
        .unwrap_or_else(|error| panic!("{description} is not UTF-8: {error}"))
        .to_string()
}

/// Validates a challenge response and extracts its fixed-size random value.
/// Called by `register_authenticated` before constructing signed registration bytes.
fn parse_challenge_response(
    response: &str,
    expected_node_id: &str,
) -> Result<[u8; CHALLENGE_BYTES], String> {
    let fields: Vec<_> = response.split_ascii_whitespace().collect();
    let [version, "CHALLENGE", node_id, challenge_hex] = fields.as_slice() else {
        return Err("expected an authenticated CHALLENGE response".into());
    };

    if *version != AUTH_PROTOCOL_VERSION {
        return Err(format!("unexpected protocol version '{version}'"));
    }
    if *node_id != expected_node_id {
        return Err(format!(
            "challenge belongs to node '{node_id}', not '{expected_node_id}'"
        ));
    }

    identity::decode_hex_array::<CHALLENGE_BYTES>(challenge_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT_A: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40_000);
    const ENDPOINT_B: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40_001);

    /// Builds matching deterministic identity and coordinator authorization state.
    /// Called by every authenticated coordinator unit test in this module.
    fn authenticated_coordinator() -> (Identity, AuthenticatedCoordinator) {
        let identity = Identity::from_secret_bytes("mesh-a", [7_u8; 32]);
        let authorizations = Authorizations::from_key("mesh-a", identity.verifying_key());
        (identity, AuthenticatedCoordinator::new(authorizations))
    }

    /// Verifies that a route advertisement is returned by destination lookup.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn advertised_route_is_selected_for_its_destination() {
        let now = Instant::now();
        let prefix: Ipv4Prefix = "10.30.0.0/24".parse().unwrap();
        let lease = Duration::from_secs(30);
        let mut registry = Registry::default();

        assert_eq!(
            registry.handle(
                Request::AdvertiseRoute {
                    node_id: "mesh-b".into(),
                    prefix,
                    lease,
                },
                ENDPOINT_B,
                now,
            ),
            Response::RouteAdvertised {
                node_id: "mesh-b".into(),
                prefix,
                lease,
            }
        );
        assert_eq!(
            registry.handle(
                Request::RouteLookup {
                    destination: Ipv4Addr::new(10, 30, 0, 2),
                },
                ENDPOINT_A,
                now,
            ),
            Response::RouteFound {
                destination: Ipv4Addr::new(10, 30, 0, 2),
                prefix,
                node_id: "mesh-b".into(),
            }
        );
    }

    /// Verifies parsing of a well-formed versioned registration request.
    /// Called automatically by Rust's test harness during `cargo test`.
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

    /// Verifies that registration stores the UDP source observed by the server.
    /// Called automatically by Rust's test harness during `cargo test`.
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

    /// Verifies that a registration is absent exactly at its lease deadline.
    /// Called automatically by Rust's test harness during `cargo test`.
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

    /// Verifies that re-registration refreshes both endpoint and expiration time.
    /// Called automatically by Rust's test harness during `cargo test`.
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

    /// Verifies rejection of malformed node IDs and out-of-range leases.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn rejects_invalid_node_id_and_lease() {
        assert!(parse_request(b"MESHLET/1 REGISTER mesh/a 30").is_err());
        assert!(parse_request(b"MESHLET/1 REGISTER mesh-a 0").is_err());
        assert!(parse_request(b"MESHLET/1 REGISTER mesh-a 301").is_err());
    }

    /// Verifies that the unauthenticated parser rejects another protocol version.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn rejects_unknown_protocol_version() {
        assert_eq!(
            parse_request(b"MESHLET/2 LOOKUP mesh-a"),
            Err("unsupported protocol version 'MESHLET/2'".into())
        );
    }

    /// Verifies that a valid challenge signature records the observed endpoint.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn valid_challenge_signature_registers_observed_endpoint() {
        let now = Instant::now();
        let lease = Duration::from_secs(30);
        let challenge = [9_u8; CHALLENGE_BYTES];
        let (identity, mut coordinator) = authenticated_coordinator();

        assert_eq!(
            coordinator.issue_challenge("mesh-a".into(), ENDPOINT_A, now, challenge),
            AuthResponse::Challenge {
                node_id: "mesh-a".into(),
                challenge,
            }
        );
        let signed_message = registration_signing_message("mesh-a", lease, &challenge);
        let signature = identity.sign(&signed_message);

        assert_eq!(
            coordinator.register(
                "mesh-a".into(),
                lease,
                challenge,
                signature,
                ENDPOINT_A,
                now,
            ),
            AuthResponse::Registered {
                node_id: "mesh-a".into(),
                observed_endpoint: ENDPOINT_A,
                lease,
            }
        );
        assert_eq!(
            coordinator.lookup("mesh-a".into(), now),
            AuthResponse::Found {
                node_id: "mesh-a".into(),
                observed_endpoint: ENDPOINT_A,
            }
        );
    }

    /// Verifies that consuming a challenge prevents registration replay.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn signed_registration_cannot_be_replayed() {
        let now = Instant::now();
        let lease = Duration::from_secs(30);
        let challenge = [10_u8; CHALLENGE_BYTES];
        let (identity, mut coordinator) = authenticated_coordinator();
        coordinator.issue_challenge("mesh-a".into(), ENDPOINT_A, now, challenge);
        let signed_message = registration_signing_message("mesh-a", lease, &challenge);

        assert!(matches!(
            coordinator.register(
                "mesh-a".into(),
                lease,
                challenge,
                identity.sign(&signed_message),
                ENDPOINT_A,
                now,
            ),
            AuthResponse::Registered { .. }
        ));
        assert_eq!(
            coordinator.register(
                "mesh-a".into(),
                lease,
                challenge,
                identity.sign(&signed_message),
                ENDPOINT_A,
                now,
            ),
            AuthResponse::Error(
                "no unexpired challenge exists for this node and source endpoint".into()
            )
        );
    }

    /// Verifies that a challenge cannot be used from a different source endpoint.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn challenge_is_bound_to_observed_source_endpoint() {
        let now = Instant::now();
        let lease = Duration::from_secs(30);
        let challenge = [11_u8; CHALLENGE_BYTES];
        let (identity, mut coordinator) = authenticated_coordinator();
        coordinator.issue_challenge("mesh-a".into(), ENDPOINT_A, now, challenge);
        let signed_message = registration_signing_message("mesh-a", lease, &challenge);

        assert_eq!(
            coordinator.register(
                "mesh-a".into(),
                lease,
                challenge,
                identity.sign(&signed_message),
                ENDPOINT_B,
                now,
            ),
            AuthResponse::Error(
                "no unexpired challenge exists for this node and source endpoint".into()
            )
        );
    }

    /// Verifies that altering the signed lease invalidates registration.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn signature_covers_lease_and_challenge() {
        let now = Instant::now();
        let signed_lease = Duration::from_secs(30);
        let changed_lease = Duration::from_secs(300);
        let challenge = [12_u8; CHALLENGE_BYTES];
        let (identity, mut coordinator) = authenticated_coordinator();
        coordinator.issue_challenge("mesh-a".into(), ENDPOINT_A, now, challenge);
        let signed_message = registration_signing_message("mesh-a", signed_lease, &challenge);

        assert_eq!(
            coordinator.register(
                "mesh-a".into(),
                changed_lease,
                challenge,
                identity.sign(&signed_message),
                ENDPOINT_A,
                now,
            ),
            AuthResponse::Error("signature verification failed".into())
        );
    }

    /// Verifies that an unauthorized private key cannot claim an authorized ID.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn different_private_key_cannot_claim_authorized_node_id() {
        let now = Instant::now();
        let lease = Duration::from_secs(30);
        let challenge = [14_u8; CHALLENGE_BYTES];
        let (_authorized_identity, mut coordinator) = authenticated_coordinator();
        let attacker_identity = Identity::from_secret_bytes("mesh-a", [8_u8; 32]);
        coordinator.issue_challenge("mesh-a".into(), ENDPOINT_A, now, challenge);
        let signed_message = registration_signing_message("mesh-a", lease, &challenge);

        assert_eq!(
            coordinator.register(
                "mesh-a".into(),
                lease,
                challenge,
                attacker_identity.sign(&signed_message),
                ENDPOINT_A,
                now,
            ),
            AuthResponse::Error("signature verification failed".into())
        );
    }

    /// Verifies that an expired challenge cannot authorize registration.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn expired_challenge_cannot_authorize_registration() {
        let now = Instant::now();
        let lease = Duration::from_secs(30);
        let challenge = [13_u8; CHALLENGE_BYTES];
        let (identity, mut coordinator) = authenticated_coordinator();
        coordinator.issue_challenge("mesh-a".into(), ENDPOINT_A, now, challenge);
        let signed_message = registration_signing_message("mesh-a", lease, &challenge);

        assert_eq!(
            coordinator.register(
                "mesh-a".into(),
                lease,
                challenge,
                identity.sign(&signed_message),
                ENDPOINT_A,
                now + CHALLENGE_LIFETIME,
            ),
            AuthResponse::Error(
                "no unexpired challenge exists for this node and source endpoint".into()
            )
        );
    }
}
