//! Admin-token gating for the local REST API.
//!
//! Until this module landed the REST API was accessible to *any* local
//! process that could reach 127.0.0.1 — the audit's C4 finding. Now
//! coord generates a 32-byte random token at first start, persists it
//! at `<data-dir>/admin.token` with mode 0600, and an axum middleware
//! requires every request to carry it as `Authorization: Bearer <hex>`.
//!
//! The chmod-600 file is the trust gate: only processes that can read
//! the operator's data directory get the token, and on Unix the kernel
//! enforces that. crackctl reads the same file (or accepts the token
//! via `--token` / `CRACKCTL_TOKEN`).
//!
//! Comparison is constant-time so a remote (or even local) attacker
//! can't binary-search the token via timing.
//!
//! On non-Unix platforms file permissions follow the process umask;
//! operators on those should harden the parent directory's ACLs.

use std::path::Path;

use anyhow::{Context, Result};
use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

const TOKEN_BYTES: usize = 32;
const TOKEN_FILENAME: &str = "admin.token";

/// 32-byte secret persisted under `<data-dir>/admin.token`.
///
/// Stored hex-encoded so it's easy to copy, paste, and pass through
/// shells. The on-disk file is `chmod 0600` on Unix.
pub struct AdminToken {
    hex: String,
}

impl AdminToken {
    /// Load the existing token, or generate + persist a fresh one.
    ///
    /// Idempotent: on subsequent calls the token file is read as-is.
    /// Whitespace around the hex string is tolerated so an operator
    /// editing the file in a text editor that adds a trailing newline
    /// doesn't break login.
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(TOKEN_FILENAME);
        if path.exists() {
            let hex = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?
                .trim()
                .to_string();
            if hex.len() != TOKEN_BYTES * 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!(
                    "{} is not a valid {}-byte hex token; delete it to regenerate",
                    path.display(),
                    TOKEN_BYTES
                );
            }
            return Ok(Self { hex });
        }

        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating {}", data_dir.display()))?;

        // 32 bytes from `rand::random` is OsRng-seeded — same source the
        // existing enrollment-nonce path uses. 32 random bytes covers the
        // 256-bit security margin we want.
        let bytes: [u8; TOKEN_BYTES] = rand::random();
        let mut hex = String::with_capacity(TOKEN_BYTES * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }

        write_token_file(&path, &hex).with_context(|| format!("writing {}", path.display()))?;

        tracing::info!(path = %path.display(), "generated new REST admin token");
        Ok(Self { hex })
    }

    /// Hex form, used by `Authorization: Bearer <hex>`. Currently only
    /// the test suite reads this directly — production reads the token
    /// out of the on-disk file. Kept public so future tooling (an
    /// admin-only "show token" endpoint, embedded crackctl) doesn't
    /// have to reach into the file path.
    #[allow(dead_code)]
    pub fn as_hex(&self) -> &str {
        &self.hex
    }

    /// Constant-time comparison against a presented bearer token.
    pub fn matches(&self, presented: &str) -> bool {
        constant_time_eq(self.hex.as_bytes(), presented.as_bytes())
    }
}

/// Atomic-ish write: create with restrictive permissions on Unix,
/// fall back to the platform default elsewhere.
fn write_token_file(path: &Path, hex: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(hex.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, hex)?;
    }
    Ok(())
}

/// `a.len() == b.len()` AND every byte equal — no early-exit on mismatch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Axum middleware that fails any request lacking a matching bearer token.
///
/// `Authorization: Bearer <hex>` is the only accepted form. Missing
/// header, wrong prefix, or wrong token all return 401 with no body —
/// no oracle on the difference between "missing" and "mismatched".
pub async fn require_admin_token(
    State(token): State<Arc<AdminToken>>,
    request: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    let header_value = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let presented = header_value
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !token.matches(presented) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("crack-coord-token-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn generates_64_hex_chars_on_first_start() {
        let dir = TempDir::new();
        let t = AdminToken::load_or_create(&dir.path).unwrap();
        let hex = t.as_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn second_call_reuses_persisted_token() {
        let dir = TempDir::new();
        let t1 = AdminToken::load_or_create(&dir.path).unwrap();
        let t2 = AdminToken::load_or_create(&dir.path).unwrap();
        assert_eq!(t1.as_hex(), t2.as_hex());
    }

    #[test]
    fn matches_constant_time_equality() {
        let dir = TempDir::new();
        let t = AdminToken::load_or_create(&dir.path).unwrap();
        let good = t.as_hex().to_string();
        assert!(t.matches(&good));
        // Trailing whitespace is rejected (caller must trim before).
        let mut bad_with_trail = good.clone();
        bad_with_trail.push(' ');
        assert!(!t.matches(&bad_with_trail));
        // Mismatched-length and zero-length get rejected.
        assert!(!t.matches(""));
        assert!(!t.matches(&good[..good.len() - 1]));
    }

    #[test]
    fn rejects_garbage_token_file() {
        let dir = TempDir::new();
        std::fs::write(dir.path.join("admin.token"), "not-hex!").unwrap();
        assert!(AdminToken::load_or_create(&dir.path).is_err());
    }

    #[test]
    fn tolerates_trailing_newline_in_token_file() {
        let dir = TempDir::new();
        let canonical = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(dir.path.join("admin.token"), format!("{canonical}\n")).unwrap();
        let t = AdminToken::load_or_create(&dir.path).unwrap();
        assert_eq!(t.as_hex(), canonical);
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_chmod_600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let _ = AdminToken::load_or_create(&dir.path).unwrap();
        let meta = std::fs::metadata(dir.path.join("admin.token")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }

    #[test]
    fn constant_time_eq_handles_all_branches() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
