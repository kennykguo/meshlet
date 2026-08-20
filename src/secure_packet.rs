//! The encrypted data packet used after a successful peer handshake.
//!
//! A small visible header carries the direction and packet number. The payload
//! is encrypted, and ChaCha20-Poly1305 also authenticates the visible header.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};

const MAGIC: [u8; 4] = *b"MSH3";
const HEADER_BYTES: usize = 13;
const AUTHENTICATION_TAG_BYTES: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    fn wire_value(self) -> u8 {
        match self {
            Self::ClientToServer => 0,
            Self::ServerToClient => 1,
        }
    }

    fn from_wire(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::ClientToServer),
            1 => Ok(Self::ServerToClient),
            _ => Err(format!("unknown encrypted-packet direction {value}")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ClientToServer => "client-to-server",
            Self::ServerToClient => "server-to-client",
        }
    }
}

pub(crate) struct PacketSender {
    cipher: ChaCha20Poly1305,
    direction: Direction,
    next_packet_number: u64,
}

impl PacketSender {
    pub(crate) fn new(key: [u8; 32], direction: Direction) -> Self {
        let key = Key::from(key);
        Self {
            cipher: ChaCha20Poly1305::new(&key),
            direction,
            next_packet_number: 0,
        }
    }

    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let packet_number = self.next_packet_number;
        let next_packet_number = packet_number
            .checked_add(1)
            .ok_or_else(|| "outbound packet number exhausted".to_string())?;
        let header = packet_header(self.direction, packet_number);
        let nonce = packet_nonce(self.direction, packet_number);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| "failed to encrypt packet".to_string())?;

        self.next_packet_number = next_packet_number;

        let mut packet = Vec::with_capacity(header.len() + ciphertext.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
}

pub(crate) struct PacketReceiver {
    cipher: ChaCha20Poly1305,
    direction: Direction,
    next_packet_number: u64,
}

impl PacketReceiver {
    pub(crate) fn new(key: [u8; 32], direction: Direction) -> Self {
        let key = Key::from(key);
        Self {
            cipher: ChaCha20Poly1305::new(&key),
            direction,
            next_packet_number: 0,
        }
    }

    pub(crate) fn open(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        if packet.len() < HEADER_BYTES + AUTHENTICATION_TAG_BYTES {
            return Err("encrypted packet is too short".into());
        }
        if packet[..MAGIC.len()] != MAGIC {
            return Err("encrypted packet has the wrong protocol marker".into());
        }

        let direction = Direction::from_wire(packet[4])?;
        if direction != self.direction {
            return Err(format!(
                "expected a {} packet, received {}",
                self.direction.label(),
                direction.label()
            ));
        }

        let packet_number = u64::from_be_bytes(
            packet[5..HEADER_BYTES]
                .try_into()
                .expect("packet-number header has a fixed size"),
        );
        if packet_number != self.next_packet_number {
            return Err(format!(
                "expected packet number {}, received {packet_number}",
                self.next_packet_number
            ));
        }
        let next_packet_number = packet_number
            .checked_add(1)
            .ok_or_else(|| "inbound packet number exhausted".to_string())?;

        let nonce = packet_nonce(direction, packet_number);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &packet[HEADER_BYTES..],
                    aad: &packet[..HEADER_BYTES],
                },
            )
            .map_err(|_| "encrypted packet authentication failed".to_string())?;

        self.next_packet_number = next_packet_number;
        Ok(plaintext)
    }
}

fn packet_header(direction: Direction, packet_number: u64) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[..MAGIC.len()].copy_from_slice(&MAGIC);
    header[4] = direction.wire_value();
    header[5..].copy_from_slice(&packet_number.to_be_bytes());
    header
}

fn packet_nonce(direction: Direction, packet_number: u64) -> Nonce {
    let mut nonce = [0_u8; 12];
    nonce[0] = direction.wire_value();
    nonce[4..].copy_from_slice(&packet_number.to_be_bytes());
    Nonce::from(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_packet_round_trips_and_replay_is_rejected() {
        let key = [7_u8; 32];
        let mut sender = PacketSender::new(key, Direction::ClientToServer);
        let mut receiver = PacketReceiver::new(key, Direction::ClientToServer);
        let packet = sender.seal(b"secret payload").unwrap();

        assert_eq!(receiver.open(&packet).unwrap(), b"secret payload");
        assert!(receiver.open(&packet).is_err());
    }

    #[test]
    fn modified_ciphertext_is_rejected_without_advancing_receiver() {
        let key = [9_u8; 32];
        let mut sender = PacketSender::new(key, Direction::ServerToClient);
        let mut receiver = PacketReceiver::new(key, Direction::ServerToClient);
        let packet = sender.seal(b"secret payload").unwrap();
        let mut modified = packet.clone();
        let last = modified.last_mut().unwrap();
        *last ^= 1;

        assert!(receiver.open(&modified).is_err());
        assert_eq!(receiver.open(&packet).unwrap(), b"secret payload");
    }
}
