use std::path::{Path, PathBuf};

use base64::Engine;
use snow::params::NoiseParams;
use zeroize::Zeroize;

use crate::error::{CrackError, Result};

/// Noise protocol pattern: IK (initiator knows responder's static key).
/// This provides mutual authentication: the worker proves its identity,
/// and the coordinator is authenticated by its known static key.
pub static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Parse the noise pattern string.
pub fn noise_params() -> NoiseParams {
    NOISE_PATTERN.parse().expect("valid noise pattern")
}

/// A keypair for Noise protocol identity.
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

    /// Save keypair to a directory (private.key + public.key files).
    pub fn save_to_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;

        let priv_path = dir.join("private.key");
        let pub_path = dir.join("public.key");

        // Write private key with restrictive permissions
        std::fs::write(&priv_path, &self.private_key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::write(&pub_path, &self.public_key)?;

        Ok(())
    }

    /// Load keypair from a directory.
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
pub fn decode_public_key(b64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(CrackError::Base64)
}

/// Encode a public key to base64.
pub fn encode_public_key(key: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
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

/// Save a remote public key (coordinator's key on agent, or authorized worker key on coordinator).
pub fn save_remote_key(dir: &Path, filename: &str, key: &[u8]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(filename);
    std::fs::write(&path, key)?;
    Ok(())
}

/// Load a remote public key.
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

/// Build a Noise responder (coordinator side) for IK handshake.
pub fn build_responder(keypair: &Keypair) -> Result<snow::HandshakeState> {
    snow::Builder::new(noise_params())
        .local_private_key(&keypair.private_key)
        .map_err(CrackError::Noise)?
        .build_responder()
        .map_err(CrackError::Noise)
}

/// Build a Noise initiator (worker side) for IK handshake.
/// The worker must know the coordinator's static public key (IK pattern).
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
