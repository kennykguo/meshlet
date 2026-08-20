//! A minimal authenticated, one-round-trip UDP handshake.
//!
//! Long-term Ed25519 keys prove node identity. Short-lived X25519 keys create
//! shared material. HKDF turns that material into one key per direction.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use ed25519_dalek::Signature;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

#[cfg(test)]
use crate::identity::Identity;
use crate::identity::{self, Authorizations};
use crate::secure_packet::{Direction, PacketReceiver, PacketSender};

const PROTOCOL_VERSION: &str = "MESHLET/3";
const EXCHANGE_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const SESSION_KEY_BYTES: usize = 32;
const MAX_DATAGRAM_BYTES: usize = 1_024;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const DIRECT_PATH_TIMEOUT: Duration = Duration::from_millis(250);
const LEARNING_MESSAGE: &[u8] = b"hello from encrypted meshlet\n";

struct ClientHello {
    initiator_id: String,
    responder_id: String,
    exchange_public: [u8; EXCHANGE_KEY_BYTES],
    signature: Signature,
}

struct ServerHello {
    initiator_id: String,
    responder_id: String,
    client_exchange_public: [u8; EXCHANGE_KEY_BYTES],
    server_exchange_public: [u8; EXCHANGE_KEY_BYTES],
    signature: Signature,
}

#[derive(Eq, PartialEq)]
struct SessionKeys {
    client_to_server: [u8; SESSION_KEY_BYTES],
    server_to_client: [u8; SESSION_KEY_BYTES],
}

struct ClientSession {
    socket: UdpSocket,
    authenticated_peer: String,
    transcript: Vec<u8>,
    keys: SessionKeys,
    handshake_elapsed: Duration,
}

#[derive(Debug, Eq, PartialEq)]
enum ClientAttemptError {
    Local(String),
    Unreachable(String),
    Rejected(String),
}

impl ClientAttemptError {
    fn message(&self) -> &str {
        match self {
            Self::Local(message) | Self::Unreachable(message) | Self::Rejected(message) => message,
        }
    }

    fn permits_fallback(&self) -> bool {
        matches!(self, Self::Unreachable(_))
    }
}

pub fn run_secure_echo_server(bind_address: &str, identity_path: &str, authorization_path: &str) {
    let identity = identity::load_identity(identity_path)
        .unwrap_or_else(|error| panic!("failed to load server identity: {error}"));
    let authorizations = Authorizations::load(authorization_path)
        .unwrap_or_else(|error| panic!("failed to load peer authorizations: {error}"));
    let socket = UdpSocket::bind(bind_address).expect("failed to bind peer handshake UDP socket");

    println!("handshake server: {}", socket.local_addr().unwrap());
    println!("local node: {}", identity.node_id());
    println!("waiting for one handshake");

    // Packet 1: the client sends a signed, short-lived public exchange key.
    let (message, source) = receive_from(&socket, "client hello");
    let client = parse_client_hello(&message)
        .unwrap_or_else(|error| panic!("invalid client hello: {error}"));
    if client.responder_id != identity.node_id() {
        panic!(
            "handshake targets node '{}', but this server is '{}'",
            client.responder_id,
            identity.node_id()
        );
    }

    let crypto_start = Instant::now();
    verify_signature(
        &authorizations,
        &client.initiator_id,
        &client_signing_message(
            &client.initiator_id,
            &client.responder_id,
            &client.exchange_public,
        ),
        &client.signature,
    )
    .unwrap_or_else(|error| panic!("client authentication failed: {error}"));

    let server_exchange_secret = EphemeralSecret::random();
    let server_exchange_public = PublicKey::from(&server_exchange_secret).to_bytes();
    let server_signature = identity.sign(&server_signing_message(&client, &server_exchange_public));
    let server = ServerHello {
        initiator_id: client.initiator_id.clone(),
        responder_id: client.responder_id.clone(),
        client_exchange_public: client.exchange_public,
        server_exchange_public,
        signature: server_signature,
    };

    let client_exchange_public = PublicKey::from(client.exchange_public);
    let shared_secret = server_exchange_secret.diffie_hellman(&client_exchange_public);
    let transcript = handshake_transcript(&client, &server);
    let keys = derive_session_keys(&shared_secret, &transcript)
        .unwrap_or_else(|error| panic!("failed to derive session keys: {error}"));
    let crypto_elapsed = crypto_start.elapsed();

    // Packet 2: the server signs both temporary public keys and replies to the
    // source endpoint from which packet 1 actually arrived.
    socket
        .send_to(encode_server_hello(&server).as_bytes(), source)
        .expect("failed to send server hello");

    print_success("server", &client.initiator_id, source, &transcript, &keys);
    println!(
        "server cryptographic work: {:.3} us",
        crypto_elapsed.as_secs_f64() * 1_000_000.0
    );

    socket
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .expect("failed to set encrypted-packet timeout");
    let (encrypted_request, request_source) = receive_bytes_from(&socket, "encrypted request");
    if request_source != source {
        panic!("encrypted request arrived from {request_source}, but handshake came from {source}");
    }

    let data_start = Instant::now();
    let mut receiver = PacketReceiver::new(keys.client_to_server, Direction::ClientToServer);
    let plaintext = receiver
        .open(&encrypted_request)
        .unwrap_or_else(|error| panic!("failed to open encrypted request: {error}"));
    let mut sender = PacketSender::new(keys.server_to_client, Direction::ServerToClient);
    let encrypted_response = sender
        .seal(&plaintext)
        .unwrap_or_else(|error| panic!("failed to seal encrypted response: {error}"));
    let data_crypto_elapsed = data_start.elapsed();

    socket
        .send_to(&encrypted_response, source)
        .expect("failed to send encrypted echo");
    println!("client-to-server key confirmed by encrypted packet");
    println!("decrypted request bytes: {}", plaintext.len());
    println!("decrypted request: {}", String::from_utf8_lossy(&plaintext));
    println!("encrypted echo bytes: {}", encrypted_response.len());
    println!(
        "server data cryptography: {:.3} us",
        data_crypto_elapsed.as_secs_f64() * 1_000_000.0
    );
}

pub fn run_secure_echo_client(
    bind_address: &str,
    server_address: &str,
    identity_path: &str,
    peer_node_id: &str,
    authorization_path: &str,
) {
    let (identity, authorizations) = load_client_material(identity_path, authorization_path);
    require_authorized(&authorizations, peer_node_id);
    let session = establish_client_session(
        bind_address,
        server_address,
        &identity,
        &authorizations,
        peer_node_id,
        RESPONSE_TIMEOUT,
    )
    .unwrap_or_else(|error| panic!("secure handshake failed: {}", error.message()));

    complete_client_exchange(session, identity.node_id(), peer_node_id);
}

pub fn run_secure_echo_client_auto(
    bind_address: &str,
    direct_address: &str,
    relay_address: &str,
    identity_path: &str,
    peer_node_id: &str,
    authorization_path: &str,
) {
    let (identity, authorizations) = load_client_material(identity_path, authorization_path);
    require_authorized(&authorizations, peer_node_id);

    println!("path policy: try direct, then relay after a reachability failure");
    println!("direct candidate: {direct_address}");
    let selection_start = Instant::now();
    let direct = establish_client_session(
        bind_address,
        direct_address,
        &identity,
        &authorizations,
        peer_node_id,
        DIRECT_PATH_TIMEOUT,
    );

    let (selected_path, session) = match direct {
        Ok(session) => ("direct", session),
        Err(error) if error.permits_fallback() => {
            println!("direct candidate unavailable: {}", error.message());
            println!("relay candidate: {relay_address}");
            let session = establish_client_session(
                bind_address,
                relay_address,
                &identity,
                &authorizations,
                peer_node_id,
                RESPONSE_TIMEOUT,
            )
            .unwrap_or_else(|relay_error| {
                panic!("relay handshake failed: {}", relay_error.message())
            });
            ("relay", session)
        }
        Err(error) => panic!(
            "direct candidate failed without trying the relay: {}",
            error.message()
        ),
    };

    println!("selected path: {selected_path}");
    println!(
        "path selection and handshake: {:.3} us",
        selection_start.elapsed().as_secs_f64() * 1_000_000.0
    );
    complete_client_exchange(session, identity.node_id(), peer_node_id);
}

fn load_client_material(
    identity_path: &str,
    authorization_path: &str,
) -> (identity::Identity, Authorizations) {
    let identity = identity::load_identity(identity_path)
        .unwrap_or_else(|error| panic!("failed to load client identity: {error}"));
    let authorizations = Authorizations::load(authorization_path)
        .unwrap_or_else(|error| panic!("failed to load peer authorizations: {error}"));
    (identity, authorizations)
}

fn establish_client_session(
    bind_address: &str,
    peer_address: &str,
    identity: &identity::Identity,
    authorizations: &Authorizations,
    peer_node_id: &str,
    timeout: Duration,
) -> Result<ClientSession, ClientAttemptError> {
    let socket = UdpSocket::bind(bind_address).map_err(|error| {
        ClientAttemptError::Local(format!("failed to bind client socket: {error}"))
    })?;
    socket.connect(peer_address).map_err(|error| {
        ClientAttemptError::Unreachable(format!("failed to select {peer_address}: {error}"))
    })?;
    socket.set_read_timeout(Some(timeout)).map_err(|error| {
        ClientAttemptError::Local(format!("failed to set handshake timeout: {error}"))
    })?;

    let handshake_start = Instant::now();
    let client_exchange_secret = EphemeralSecret::random();
    let client_exchange_public = PublicKey::from(&client_exchange_secret).to_bytes();
    let client_signature = identity.sign(&client_signing_message(
        identity.node_id(),
        peer_node_id,
        &client_exchange_public,
    ));
    let client = ClientHello {
        initiator_id: identity.node_id().to_string(),
        responder_id: peer_node_id.to_string(),
        exchange_public: client_exchange_public,
        signature: client_signature,
    };
    socket
        .send(encode_client_hello(&client).as_bytes())
        .map_err(|error| {
            ClientAttemptError::Unreachable(format!("failed to send client hello: {error}"))
        })?;

    let message = try_receive_connected(&socket, "server hello").map_err(|error| {
        ClientAttemptError::Unreachable(format!(
            "no server hello from {peer_address} within {} ms: {error}",
            timeout.as_millis()
        ))
    })?;
    let server = parse_server_hello(&message)
        .map_err(|error| ClientAttemptError::Rejected(format!("invalid server hello: {error}")))?;
    validate_server_hello(&server, &client).map_err(|error| {
        ClientAttemptError::Rejected(format!(
            "server hello does not match this handshake: {error}"
        ))
    })?;
    verify_signature(
        authorizations,
        &server.responder_id,
        &server_signing_message(&client, &server.server_exchange_public),
        &server.signature,
    )
    .map_err(|error| {
        ClientAttemptError::Rejected(format!("server authentication failed: {error}"))
    })?;

    let server_exchange_public = PublicKey::from(server.server_exchange_public);
    let shared_secret = client_exchange_secret.diffie_hellman(&server_exchange_public);
    let transcript = handshake_transcript(&client, &server);
    let keys = derive_session_keys(&shared_secret, &transcript).map_err(|error| {
        ClientAttemptError::Rejected(format!("failed to derive session keys: {error}"))
    })?;
    let handshake_elapsed = handshake_start.elapsed();

    Ok(ClientSession {
        socket,
        authenticated_peer: server.responder_id,
        transcript,
        keys,
        handshake_elapsed,
    })
}

fn complete_client_exchange(
    session: ClientSession,
    local_node_id: &str,
    expected_peer_node_id: &str,
) {
    let ClientSession {
        socket,
        authenticated_peer,
        transcript,
        keys,
        handshake_elapsed,
    } = session;

    println!("local: {}", socket.local_addr().unwrap());
    println!("peer: {}", socket.peer_addr().unwrap());
    println!("local node: {local_node_id}");
    println!("expected peer node: {expected_peer_node_id}");
    print_success(
        "client",
        &authenticated_peer,
        socket.peer_addr().unwrap(),
        &transcript,
        &keys,
    );
    println!(
        "complete handshake: {:.3} us (one network round trip)",
        handshake_elapsed.as_secs_f64() * 1_000_000.0
    );

    let data_start = Instant::now();
    let mut sender = PacketSender::new(keys.client_to_server, Direction::ClientToServer);
    let encrypted_request = sender
        .seal(LEARNING_MESSAGE)
        .unwrap_or_else(|error| panic!("failed to seal encrypted request: {error}"));
    socket
        .send(&encrypted_request)
        .expect("failed to send encrypted request");

    let encrypted_response = receive_connected_bytes(&socket, "encrypted echo");
    let mut receiver = PacketReceiver::new(keys.server_to_client, Direction::ServerToClient);
    let plaintext = receiver
        .open(&encrypted_response)
        .unwrap_or_else(|error| panic!("failed to open encrypted echo: {error}"));
    let data_elapsed = data_start.elapsed();
    if plaintext != LEARNING_MESSAGE {
        panic!("encrypted echo plaintext did not match the request");
    }

    println!("plaintext request bytes: {}", LEARNING_MESSAGE.len());
    println!("encrypted request bytes: {}", encrypted_request.len());
    println!("server-to-client key confirmed by encrypted echo");
    println!("decrypted echo: {}", String::from_utf8_lossy(&plaintext));
    println!(
        "encrypted echo round trip: {:.3} us",
        data_elapsed.as_secs_f64() * 1_000_000.0
    );
}

fn encode_client_hello(hello: &ClientHello) -> String {
    format!(
        "{PROTOCOL_VERSION} CLIENT_HELLO {} {} {} {}",
        hello.initiator_id,
        hello.responder_id,
        identity::encode_hex(&hello.exchange_public),
        identity::encode_hex(&hello.signature.to_bytes())
    )
}

fn parse_client_hello(message: &str) -> Result<ClientHello, String> {
    let fields: Vec<_> = message.split_ascii_whitespace().collect();
    let [
        version,
        "CLIENT_HELLO",
        initiator_id,
        responder_id,
        exchange_public,
        signature,
    ] = fields.as_slice()
    else {
        return Err(
            "expected 'MESHLET/3 CLIENT_HELLO INITIATOR RESPONDER PUBLIC_KEY SIGNATURE'".into(),
        );
    };
    require_version(version)?;
    validate_node_id(initiator_id)?;
    validate_node_id(responder_id)?;
    Ok(ClientHello {
        initiator_id: (*initiator_id).to_string(),
        responder_id: (*responder_id).to_string(),
        exchange_public: identity::decode_hex_array::<EXCHANGE_KEY_BYTES>(exchange_public)?,
        signature: parse_signature(signature)?,
    })
}

fn encode_server_hello(hello: &ServerHello) -> String {
    format!(
        "{PROTOCOL_VERSION} SERVER_HELLO {} {} {} {} {}",
        hello.initiator_id,
        hello.responder_id,
        identity::encode_hex(&hello.client_exchange_public),
        identity::encode_hex(&hello.server_exchange_public),
        identity::encode_hex(&hello.signature.to_bytes())
    )
}

fn parse_server_hello(message: &str) -> Result<ServerHello, String> {
    let fields: Vec<_> = message.split_ascii_whitespace().collect();
    let [
        version,
        "SERVER_HELLO",
        initiator_id,
        responder_id,
        client_exchange_public,
        server_exchange_public,
        signature,
    ] = fields.as_slice()
    else {
        return Err(
            "expected 'MESHLET/3 SERVER_HELLO INITIATOR RESPONDER CLIENT_KEY SERVER_KEY SIGNATURE'"
                .into(),
        );
    };
    require_version(version)?;
    validate_node_id(initiator_id)?;
    validate_node_id(responder_id)?;
    Ok(ServerHello {
        initiator_id: (*initiator_id).to_string(),
        responder_id: (*responder_id).to_string(),
        client_exchange_public: identity::decode_hex_array::<EXCHANGE_KEY_BYTES>(
            client_exchange_public,
        )?,
        server_exchange_public: identity::decode_hex_array::<EXCHANGE_KEY_BYTES>(
            server_exchange_public,
        )?,
        signature: parse_signature(signature)?,
    })
}

fn client_signing_message(
    initiator_id: &str,
    responder_id: &str,
    exchange_public: &[u8; EXCHANGE_KEY_BYTES],
) -> Vec<u8> {
    format!(
        "MESHLET-HANDSHAKE-CLIENT/1\nprotocol:{PROTOCOL_VERSION}\ninitiator:{initiator_id}\nresponder:{responder_id}\nexchange-public:{}\n",
        identity::encode_hex(exchange_public)
    )
    .into_bytes()
}

fn server_signing_message(
    client: &ClientHello,
    server_exchange_public: &[u8; EXCHANGE_KEY_BYTES],
) -> Vec<u8> {
    format!(
        "MESHLET-HANDSHAKE-SERVER/1\nprotocol:{PROTOCOL_VERSION}\ninitiator:{}\nresponder:{}\nclient-exchange-public:{}\nclient-signature:{}\nserver-exchange-public:{}\n",
        client.initiator_id,
        client.responder_id,
        identity::encode_hex(&client.exchange_public),
        identity::encode_hex(&client.signature.to_bytes()),
        identity::encode_hex(server_exchange_public)
    )
    .into_bytes()
}

fn handshake_transcript(client: &ClientHello, server: &ServerHello) -> Vec<u8> {
    let client_message = client_signing_message(
        &client.initiator_id,
        &client.responder_id,
        &client.exchange_public,
    );
    let server_message = server_signing_message(client, &server.server_exchange_public);
    let mut transcript =
        Vec::with_capacity(client_message.len() + server_message.len() + (SIGNATURE_BYTES * 2));
    transcript.extend_from_slice(&client_message);
    transcript.extend_from_slice(&client.signature.to_bytes());
    transcript.extend_from_slice(&server_message);
    transcript.extend_from_slice(&server.signature.to_bytes());
    transcript
}

fn derive_session_keys(shared: &SharedSecret, transcript: &[u8]) -> Result<SessionKeys, String> {
    if !shared.was_contributory() {
        return Err("peer exchange key produced an unsafe all-zero shared secret".into());
    }

    let transcript_hash = Sha256::digest(transcript);
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash.as_slice()), shared.as_bytes());
    let mut client_to_server = [0_u8; SESSION_KEY_BYTES];
    let mut server_to_client = [0_u8; SESSION_KEY_BYTES];
    hkdf.expand(
        b"MESHLET/3 client-to-server encryption key",
        &mut client_to_server,
    )
    .map_err(|_| "failed to derive client-to-server key".to_string())?;
    hkdf.expand(
        b"MESHLET/3 server-to-client encryption key",
        &mut server_to_client,
    )
    .map_err(|_| "failed to derive server-to-client key".to_string())?;

    Ok(SessionKeys {
        client_to_server,
        server_to_client,
    })
}

fn validate_server_hello(server: &ServerHello, client: &ClientHello) -> Result<(), String> {
    if server.initiator_id != client.initiator_id
        || server.responder_id != client.responder_id
        || server.client_exchange_public != client.exchange_public
    {
        return Err("server did not echo the client's exact handshake values".into());
    }
    Ok(())
}

fn verify_signature(
    authorizations: &Authorizations,
    node_id: &str,
    message: &[u8],
    signature: &Signature,
) -> Result<(), String> {
    let public_key = authorizations
        .get(node_id)
        .ok_or_else(|| format!("node '{node_id}' has no authorized public key"))?;
    public_key
        .verify_strict(message, signature)
        .map_err(|_| format!("signature from node '{node_id}' is invalid"))
}

fn require_authorized(authorizations: &Authorizations, node_id: &str) {
    if authorizations.get(node_id).is_none() {
        panic!("node '{node_id}' has no authorized public key");
    }
}

fn require_version(version: &str) -> Result<(), String> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(format!(
            "unsupported handshake protocol version '{version}'"
        ))
    }
}

fn validate_node_id(node_id: &str) -> Result<(), String> {
    if crate::coordinator::valid_node_id(node_id) {
        Ok(())
    } else {
        Err("node ID must use 1-64 ASCII letters, digits, '.', '-' or '_'".into())
    }
}

fn parse_signature(encoded: &str) -> Result<Signature, String> {
    let bytes = identity::decode_hex_array::<SIGNATURE_BYTES>(encoded)?;
    Signature::try_from(bytes.as_slice()).map_err(|error| format!("invalid signature: {error}"))
}

fn receive_from(socket: &UdpSocket, description: &str) -> (String, SocketAddr) {
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];
    let (bytes_received, source) = socket
        .recv_from(&mut buffer)
        .unwrap_or_else(|error| panic!("failed to receive {description}: {error}"));
    if bytes_received > MAX_DATAGRAM_BYTES {
        panic!("{description} exceeds {MAX_DATAGRAM_BYTES}-byte limit");
    }
    let message = std::str::from_utf8(&buffer[..bytes_received])
        .unwrap_or_else(|error| panic!("{description} is not UTF-8: {error}"));
    (message.to_string(), source)
}

fn try_receive_connected(socket: &UdpSocket, description: &str) -> Result<String, String> {
    let bytes = try_receive_connected_bytes(socket, description)?;
    String::from_utf8(bytes).map_err(|error| format!("{description} is not UTF-8: {error}"))
}

fn receive_bytes_from(socket: &UdpSocket, description: &str) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];
    let (bytes_received, source) = socket
        .recv_from(&mut buffer)
        .unwrap_or_else(|error| panic!("failed to receive {description}: {error}"));
    if bytes_received > MAX_DATAGRAM_BYTES {
        panic!("{description} exceeds {MAX_DATAGRAM_BYTES}-byte limit");
    }
    (buffer[..bytes_received].to_vec(), source)
}

fn receive_connected_bytes(socket: &UdpSocket, description: &str) -> Vec<u8> {
    try_receive_connected_bytes(socket, description).unwrap_or_else(|error| {
        panic!("failed to receive {description} within two seconds: {error}")
    })
}

fn try_receive_connected_bytes(socket: &UdpSocket, description: &str) -> Result<Vec<u8>, String> {
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES + 1];
    let bytes_received = socket
        .recv(&mut buffer)
        .map_err(|error| format!("failed to receive {description}: {error}"))?;
    if bytes_received > MAX_DATAGRAM_BYTES {
        return Err(format!(
            "{description} exceeds {MAX_DATAGRAM_BYTES}-byte limit"
        ));
    }
    Ok(buffer[..bytes_received].to_vec())
}

fn print_success(
    role: &str,
    peer_node_id: &str,
    peer_endpoint: SocketAddr,
    transcript: &[u8],
    keys: &SessionKeys,
) {
    let session_id = Sha256::digest(transcript);
    println!("handshake role: {role}");
    println!("authenticated peer: {peer_node_id}");
    println!("peer endpoint: {peer_endpoint}");
    println!("session ID: {}", identity::encode_hex(&session_id[..8]));
    println!(
        "directional keys derived: client->server {} bytes, server->client {} bytes",
        keys.client_to_server.len(),
        keys.server_to_client.len()
    );
    println!("key status: derived locally; not yet confirmed by encrypted traffic");
    println!("shared secret and encryption keys are intentionally not printed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_is_only_allowed_for_reachability_failures() {
        let unreachable = ClientAttemptError::Unreachable("timed out".into());
        let local = ClientAttemptError::Local("cannot bind".into());
        let rejected = ClientAttemptError::Rejected("invalid signature".into());

        assert!(unreachable.permits_fallback());
        assert!(!local.permits_fallback());
        assert!(!rejected.permits_fallback());
    }

    #[test]
    fn both_peers_derive_the_same_directional_keys() {
        let client_secret = EphemeralSecret::random();
        let client_public = PublicKey::from(&client_secret);
        let server_secret = EphemeralSecret::random();
        let server_public = PublicKey::from(&server_secret);

        let client_shared = client_secret.diffie_hellman(&server_public);
        let server_shared = server_secret.diffie_hellman(&client_public);
        let transcript = b"one exact authenticated Meshlet handshake";

        let client_keys = derive_session_keys(&client_shared, transcript).unwrap();
        let server_keys = derive_session_keys(&server_shared, transcript).unwrap();

        assert!(client_keys == server_keys);
        assert_ne!(client_keys.client_to_server, client_keys.server_to_client);
    }

    #[test]
    fn complete_authenticated_handshake_derives_matching_keys() {
        let client_identity = Identity::from_secret_bytes("mesh-a", [7_u8; 32]);
        let server_identity = Identity::from_secret_bytes("mesh-b", [9_u8; 32]);
        let server_authorizations =
            Authorizations::from_key("mesh-a", client_identity.verifying_key());
        let client_authorizations =
            Authorizations::from_key("mesh-b", server_identity.verifying_key());

        let client_secret = EphemeralSecret::random();
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let client_signature =
            client_identity.sign(&client_signing_message("mesh-a", "mesh-b", &client_public));
        let sent_client = ClientHello {
            initiator_id: "mesh-a".into(),
            responder_id: "mesh-b".into(),
            exchange_public: client_public,
            signature: client_signature,
        };

        let received_client = parse_client_hello(&encode_client_hello(&sent_client)).unwrap();
        verify_signature(
            &server_authorizations,
            &received_client.initiator_id,
            &client_signing_message(
                &received_client.initiator_id,
                &received_client.responder_id,
                &received_client.exchange_public,
            ),
            &received_client.signature,
        )
        .unwrap();

        let server_secret = EphemeralSecret::random();
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let server_signature =
            server_identity.sign(&server_signing_message(&received_client, &server_public));
        let sent_server = ServerHello {
            initiator_id: received_client.initiator_id.clone(),
            responder_id: received_client.responder_id.clone(),
            client_exchange_public: received_client.exchange_public,
            server_exchange_public: server_public,
            signature: server_signature,
        };

        let received_server = parse_server_hello(&encode_server_hello(&sent_server)).unwrap();
        validate_server_hello(&received_server, &sent_client).unwrap();
        verify_signature(
            &client_authorizations,
            &received_server.responder_id,
            &server_signing_message(&sent_client, &received_server.server_exchange_public),
            &received_server.signature,
        )
        .unwrap();

        let client_shared =
            client_secret.diffie_hellman(&PublicKey::from(received_server.server_exchange_public));
        let server_shared =
            server_secret.diffie_hellman(&PublicKey::from(received_client.exchange_public));
        let client_transcript = handshake_transcript(&sent_client, &received_server);
        let server_transcript = handshake_transcript(&received_client, &sent_server);
        let client_keys = derive_session_keys(&client_shared, &client_transcript).unwrap();
        let server_keys = derive_session_keys(&server_shared, &server_transcript).unwrap();

        assert_eq!(client_transcript, server_transcript);
        assert!(client_keys == server_keys);
    }
}
