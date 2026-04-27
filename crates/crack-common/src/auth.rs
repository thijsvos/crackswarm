//! Noise IK identity handling: keypair generation, on-disk storage, and
//! handshake builders for the coord (responder) and agent (initiator).
//!
//! Trust model: the coord publishes its static public key out-of-band
//! (encoded in `EnrollmentToken`). The agent must know that key to
//! initiate IK; the coord recognizes the agent by the static public key
//! it presents in the first handshake message and matches it against
//! the `workers` table.
//!
//! On-disk layout under a data directory: `private.key` + `public.key`.
//! Private key files are created with mode `0o600` on Unix; the `Drop`
//! impl on `Keypair` zeroizes private-key memory.

use std::path::{Path, PathBuf};

use base64::Engine;
use snow::params::NoiseParams;
use zeroize::Zeroize;

use crate::error::{CrackError, Result};

/// Noise protocol pattern: IK (initiator knows responder's static key).
/// This provides mutual authentication: the worker proves its identity,
/// and the coordinator is authenticated by its known static key.
pub static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Parse [`NOISE_PATTERN`] into a [`NoiseParams`].
///
/// # Panics
/// Panics if [`NOISE_PATTERN`] is not a valid Noise descriptor — but the
/// string is a compile-time constant, so this is a programmer error, not
/// a runtime concern.
pub fn noise_params() -> NoiseParams {
    NOISE_PATTERN.parse().expect("valid noise pattern")
}

/// A Curve25519 keypair backing one party's Noise IK identity. Holds
/// raw key bytes; `Drop` zeroizes `private_key` to keep secret material
/// out of freed allocations. `public_key` is safe to share/serialize.
pub struct Keypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl Keypair {
    /// Generate a new Curve25519 keypair.
    ///
    /// # Errors
    /// Returns `CrackError::Noise` if the underlying snow builder fails
    /// to produce a keypair (e.g. the OS RNG is unavailable).
    pub fn generate() -> Result<Self> {
        let builder = snow::Builder::new(noise_params());
        let dh = builder.generate_keypair().map_err(CrackError::Noise)?;
        Ok(Self {
            private_key: dh.private.to_vec(),
            public_key: dh.public.to_vec(),
        })
    }

    /// Encode the public key as base64 for display/sharing.
    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.public_key)
    }

    /// Persist this keypair under `dir` as `private.key` + `public.key`.
    ///
    /// On Unix, `private.key` is created with mode `0o600` atomically
    /// (single `OpenOptions::open` call) so it is never world-readable
    /// in between creation and a separate chmod. On non-Unix platforms
    /// permissions follow the process umask — harden the parent
    /// directory's ACLs if that matters in your deployment.
    /// `public.key` is written without restricted permissions.
    ///
    /// # Errors
    /// Any `std::io::Error` from `create_dir_all`, `OpenOptions::open`,
    /// or `write` propagates unchanged.
    pub fn save_to_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;

        let priv_path = dir.join("private.key");
        let pub_path = dir.join("public.key");

        // Write private key with restrictive permissions.
        // On Unix, create the file with mode 0o600 atomically to avoid a
        // window where the key is world-readable.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&priv_path)?;
            f.write_all(&self.private_key)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&priv_path, &self.private_key)?;
        }

        std::fs::write(&pub_path, &self.public_key)?;

        Ok(())
    }

    /// Load a keypair previously saved by `save_to_dir`. Reads
    /// `dir/private.key` and `dir/public.key` and returns the
    /// reconstructed `Keypair`. The private key is wiped on `Drop`.
    ///
    /// # Errors
    /// - `CrackError::Config` when either key file is absent (suggests
    ///   the user run `init` first).
    /// - Any `std::io::Error` from `std::fs::read` if the files exist
    ///   but can't be read.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let priv_path = dir.join("private.key");
        let pub_path = dir.join("public.key");

        if !priv_path.exists() || !pub_path.exists() {
            return Err(CrackError::Config(format!(
                "keypair not found in {}. Run 'init' first.",
                dir.display()
            )));
        }

        let private_key = std::fs::read(&priv_path)?;
        let public_key = std::fs::read(&pub_path)?;

        Ok(Self {
            private_key,
            public_key,
        })
    }
}

/// Decode a base64-encoded public key.
///
/// # Errors
/// Returns `CrackError::Base64` if `b64` is not valid base64.
pub fn decode_public_key(b64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(CrackError::Base64)
}

/// Encode a public key to base64.
pub fn encode_public_key(key: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Short, stable identifier for a Curve25519 public key, suitable for
/// log files. Returns the first 16 hex chars of `SHA-256(b64_pubkey)`.
///
/// Logs end up on disk under default umask; the full base64 pubkey is
/// the unique correlator across log rotations and a stronger fingerprint
/// than IP address. Persist the full key only in the audit_log table
/// (access-controlled) and use this short form in tracing macros.
pub fn pubkey_fingerprint(pubkey_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pubkey_b64.as_bytes());
    let mut s = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Get the default data directory for the coordinator.
pub fn coordinator_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("crack-coord")
}

/// Get the default data directory for the agent.
pub fn agent_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("crack-agent")
}

/// Persist a peer's static public key under `dir/filename`.
///
/// Used by the coord to remember each authorized worker's key
/// (`<workers_dir>/<worker_id>.pub`) and by the agent to remember the
/// coord's key (`coordinator.pub`). Public keys carry no secret material
/// so no special permissions are applied.
///
/// # Errors
/// Any `std::io::Error` from `create_dir_all` or `write` propagates
/// unchanged.
pub fn save_remote_key(dir: &Path, filename: &str, key: &[u8]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(filename);
    std::fs::write(&path, key)?;
    Ok(())
}

/// Load a remote public key previously stored under `dir/filename`.
///
/// # Errors
/// - `CrackError::Config` if the file does not exist.
/// - Any `std::io::Error` from `std::fs::read`.
pub fn load_remote_key(dir: &Path, filename: &str) -> Result<Vec<u8>> {
    let path = dir.join(filename);
    if !path.exists() {
        return Err(CrackError::Config(format!(
            "key file not found: {}",
            path.display()
        )));
    }
    Ok(std::fs::read(&path)?)
}

/// Build a Noise IK responder (coordinator side) using `keypair` as the
/// local static. The responder learns the initiator's static public key
/// from the first handshake message — this is how the coord
/// authenticates the worker.
///
/// # Errors
/// Returns `CrackError::Noise` if snow rejects the supplied private key
/// or fails to construct the responder state.
pub fn build_responder(keypair: &Keypair) -> Result<snow::HandshakeState> {
    snow::Builder::new(noise_params())
        .local_private_key(&keypair.private_key)
        .map_err(CrackError::Noise)?
        .build_responder()
        .map_err(CrackError::Noise)
}

/// Build a Noise IK initiator (worker side).
///
/// The worker must know `remote_static` (the coord's static public key,
/// distributed via `EnrollmentToken`) before initiating — the IK pattern
/// offers no in-band way to discover it. Mismatched keys cause the
/// handshake to fail at `read_message` time.
///
/// # Errors
/// Returns `CrackError::Noise` if snow rejects either key (wrong length
/// or invalid encoding) or fails to construct the initiator state.
pub fn build_initiator(keypair: &Keypair, remote_static: &[u8]) -> Result<snow::HandshakeState> {
    snow::Builder::new(noise_params())
        .local_private_key(&keypair.private_key)
        .map_err(CrackError::Noise)?
        .remote_public_key(remote_static)
        .map_err(CrackError::Noise)?
        .build_initiator()
        .map_err(CrackError::Noise)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_short() {
        let fp = pubkey_fingerprint("AAAAAAAA");
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fp, pubkey_fingerprint("AAAAAAAA"));
    }

    #[test]
    fn fingerprint_distinguishes_keys() {
        let a = pubkey_fingerprint("AAAAAAAA");
        let b = pubkey_fingerprint("BBBBBBBB");
        assert_ne!(a, b);
    }

    #[test]
    fn test_keypair_generate_and_encode() {
        let kp = Keypair::generate().unwrap();
        assert_eq!(kp.public_key.len(), 32);
        assert_eq!(kp.private_key.len(), 32);
        let b64 = kp.public_key_b64();
        let decoded = decode_public_key(&b64).unwrap();
        assert_eq!(decoded, kp.public_key);
    }

    #[test]
    fn test_noise_handshake() {
        let server_kp = Keypair::generate().unwrap();
        let client_kp = Keypair::generate().unwrap();

        let mut server = build_responder(&server_kp).unwrap();
        let mut client = build_initiator(&client_kp, &server_kp.public_key).unwrap();

        // IK: initiator sends first message (e, es, s, ss)
        let mut buf = vec![0u8; 65535];
        let len = client.write_message(&[], &mut buf).unwrap();
        let msg1 = buf[..len].to_vec();

        // Server reads first message
        let len = server.read_message(&msg1, &mut buf).unwrap();
        assert_eq!(len, 0); // no payload

        // Server sends second message (e, ee, se)
        let len = server.write_message(&[], &mut buf).unwrap();
        let msg2 = buf[..len].to_vec();

        // Client reads second message
        let _len = client.read_message(&msg2, &mut buf).unwrap();

        // Both should be ready for transport
        assert!(client.is_handshake_finished());
        assert!(server.is_handshake_finished());

        // Verify the server can see the client's static key
        let client_static = server.get_remote_static().unwrap();
        assert_eq!(client_static, &client_kp.public_key[..]);

        // Transport test
        let mut client_transport = client.into_transport_mode().unwrap();
        let mut server_transport = server.into_transport_mode().unwrap();

        let test_msg = b"hello encrypted world";
        let len = client_transport.write_message(test_msg, &mut buf).unwrap();
        let cipher = buf[..len].to_vec();

        let len = server_transport.read_message(&cipher, &mut buf).unwrap();
        assert_eq!(&buf[..len], test_msg);
    }
}
