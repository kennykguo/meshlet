use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const PRIVATE_FILE_VERSION: &str = "MESHLET-IDENTITY/1";
const PUBLIC_FILE_VERSION: &str = "MESHLET-AUTHORIZATION/1";

pub struct Identity {
    node_id: String,
    signing_key: SigningKey,
}

impl Identity {
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    #[cfg(test)]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    #[cfg(test)]
    pub fn from_secret_bytes(node_id: &str, secret: [u8; 32]) -> Self {
        Self {
            node_id: node_id.to_string(),
            signing_key: SigningKey::from_bytes(&secret),
        }
    }
}

pub struct Authorizations {
    keys: HashMap<String, VerifyingKey>,
}

impl Authorizations {
    pub fn load(path: &str) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|error| format!("failed to read authorization file '{path}': {error}"))?;
        let mut keys: HashMap<String, VerifyingKey> = HashMap::new();

        for (index, line) in contents.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let [version, node_id, public_hex] = fields.as_slice() else {
                return Err(format!(
                    "authorization line {} must be '{PUBLIC_FILE_VERSION} NODE_ID PUBLIC_KEY_HEX'",
                    index + 1
                ));
            };

            if *version != PUBLIC_FILE_VERSION {
                return Err(format!(
                    "unsupported authorization version '{version}' on line {}",
                    index + 1
                ));
            }
            if !crate::coordinator::valid_node_id(node_id) {
                return Err(format!(
                    "invalid node ID on authorization line {}",
                    index + 1
                ));
            }

            let public_bytes = decode_hex_array::<32>(public_hex)
                .map_err(|message| format!("authorization line {}: {message}", index + 1))?;
            let verifying_key = VerifyingKey::from_bytes(&public_bytes)
                .map_err(|error| format!("invalid public key on line {}: {error}", index + 1))?;

            if keys.insert((*node_id).to_string(), verifying_key).is_some() {
                return Err(format!(
                    "duplicate node ID '{node_id}' in authorization file"
                ));
            }
        }

        if keys.is_empty() {
            return Err("authorization file contains no node keys".into());
        }

        Ok(Self { keys })
    }

    pub fn get(&self, node_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(node_id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[cfg(test)]
    pub fn from_key(node_id: &str, verifying_key: VerifyingKey) -> Self {
        Self {
            keys: HashMap::from([(node_id.to_string(), verifying_key)]),
        }
    }
}

pub fn generate(node_id: &str, private_path: &str, public_path: &str) -> Result<(), String> {
    if !crate::coordinator::valid_node_id(node_id) {
        return Err("node ID must use 1-64 ASCII letters, digits, '.', '-' or '_'".into());
    }
    if Path::new(private_path) == Path::new(public_path) {
        return Err("private and public key paths must be different".into());
    }

    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| format!("operating system failed to generate a secret key: {error}"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key = signing_key.verifying_key();

    let private_contents = format!(
        "{PRIVATE_FILE_VERSION} {node_id} {}\n",
        encode_hex(signing_key.as_bytes())
    );
    let public_contents = format!(
        "{PUBLIC_FILE_VERSION} {node_id} {}\n",
        encode_hex(public_key.as_bytes())
    );

    write_new(private_path, private_contents.as_bytes(), 0o600)?;
    if let Err(error) = write_new(public_path, public_contents.as_bytes(), 0o644) {
        return Err(format!(
            "{error}; private key was created at '{private_path}' and was not removed"
        ));
    }

    println!("node ID: {node_id}");
    println!("private identity: {private_path} (mode 0600; keep secret)");
    println!("public authorization: {public_path} (safe to distribute)");
    println!("public key: {}", encode_hex(public_key.as_bytes()));

    Ok(())
}

pub fn load_identity(path: &str) -> Result<Identity, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read identity file '{path}': {error}"))?;
    let fields: Vec<_> = contents.split_ascii_whitespace().collect();
    let [version, node_id, secret_hex] = fields.as_slice() else {
        return Err(format!(
            "identity file must be '{PRIVATE_FILE_VERSION} NODE_ID SECRET_KEY_HEX'"
        ));
    };

    if *version != PRIVATE_FILE_VERSION {
        return Err(format!("unsupported identity version '{version}'"));
    }
    if !crate::coordinator::valid_node_id(node_id) {
        return Err("identity file contains an invalid node ID".into());
    }

    let secret = decode_hex_array::<32>(secret_hex)?;
    Ok(Identity {
        node_id: (*node_id).to_string(),
        signing_key: SigningKey::from_bytes(&secret),
    })
}

fn write_new(path: &str, contents: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| format!("refused to create '{path}': {error}"))?;
    file.write_all(contents)
        .map_err(|error| format!("failed to write '{path}': {error}"))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync '{path}': {error}"))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }

    encoded
}

pub fn decode_hex_array<const N: usize>(encoded: &str) -> Result<[u8; N], String> {
    if encoded.len() != N * 2 {
        return Err(format!("expected {} hexadecimal characters", N * 2));
    }

    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        decoded[index] = (high << 4) | low;
    }

    Ok(decoded)
}

fn decode_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!(
            "invalid hexadecimal character '{}'",
            char::from(byte)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00, 0x12, 0xab, 0xff];
        assert_eq!(encode_hex(&bytes), "0012abff");
        assert_eq!(decode_hex_array::<4>("0012ABff"), Ok(bytes));
    }

    #[test]
    fn identity_signs_with_corresponding_public_key() {
        let identity = Identity::from_secret_bytes("mesh-a", [7_u8; 32]);
        let message = b"meshlet authentication test";
        let signature = identity.sign(message);

        assert!(
            identity
                .signing_key
                .verifying_key()
                .verify_strict(message, &signature)
                .is_ok()
        );
        assert!(
            identity
                .signing_key
                .verifying_key()
                .verify_strict(b"tampered", &signature)
                .is_err()
        );
    }
}
