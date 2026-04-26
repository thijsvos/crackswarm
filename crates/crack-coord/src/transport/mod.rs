pub mod handler;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, warn};

use crate::state::AppState;

/// Per-IP cap on attempted handshakes within `WINDOW`. Loopback addresses
/// are exempt — `--with-agent` colocates the agent with the coord and
/// would otherwise burn this limit during testing.
const HANDSHAKE_RATE_PER_WINDOW: u32 = 30;
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Rate-limit table is GC'd this often to keep the map bounded.
const RATE_GC_INTERVAL: Duration = Duration::from_secs(300);

/// Hard cap on concurrent in-progress handshakes across the listener.
/// The Noise IK handshake is cheap-ish but the pre-auth path runs DB
/// calls and allocates 192 KiB-per-conn, so flooders can pin connections
/// and pool slots. A semaphore limits the work-in-flight.
const MAX_CONCURRENT_HANDSHAKES: usize = 64;

/// In-memory token bucket per source IP. `(window_start, count)` per IP;
/// when `count` exceeds [`HANDSHAKE_RATE_PER_WINDOW`] within
/// [`RATE_WINDOW`], new connections are dropped before the handshake
/// runs.
struct PerIpRateLimit {
    entries: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl PerIpRateLimit {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the connection from `ip` is allowed to proceed.
    /// Loopback IPs always pass.
    async fn check(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        let entry = entries.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) > RATE_WINDOW {
            *entry = (now, 1);
            true
        } else {
            entry.1 = entry.1.saturating_add(1);
            entry.1 <= HANDSHAKE_RATE_PER_WINDOW
        }
    }

    /// Drop entries whose window has fully elapsed; called by a
    /// background ticker.
    async fn gc(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_, (window_start, _)| now.duration_since(*window_start) <= RATE_WINDOW);
    }
}

/// Start the Noise-encrypted transport listener.
///
/// Binds a TCP listener on `bind_addr` and spawns a dedicated tokio task for
/// each incoming connection, gated by a per-IP token bucket and a global
/// concurrent-handshake semaphore. The per-connection handler performs a
/// Noise IK handshake (coordinator as responder), verifies the worker's
/// public key against the database, and then runs an encrypted message
/// loop.
pub async fn start_transport(state: Arc<AppState>, bind_addr: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!(addr = %bind_addr, "noise transport listening");

    let rate_limit = Arc::new(PerIpRateLimit::new());
    let handshake_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES));

    // Background GC for the rate-limit map. Keeps the table bounded
    // when a NAT'd source repeatedly probes.
    let rl_gc = Arc::clone(&rate_limit);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RATE_GC_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            rl_gc.gc().await;
        }
    });

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let ip = peer_addr.ip();

                if !rate_limit.check(ip).await {
                    warn!(%peer_addr, "rate-limit drop");
                    drop(stream);
                    continue;
                }

                // try_acquire_owned avoids parking the accept loop behind
                // a saturated handshake stage. Dropping the stream is the
                // intended response — caller will reconnect.
                let permit = match Arc::clone(&handshake_slots).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(%peer_addr, "handshake-slot drop (max concurrent)");
                        drop(stream);
                        continue;
                    }
                };

                debug!(%peer_addr, "incoming worker connection");
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handler::handle_connection(state, stream, peer_addr).await;
                    drop(permit); // release the handshake slot
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept connection");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn rate_limit_lets_loopback_through_unboundedly() {
        let rl = PerIpRateLimit::new();
        let lo = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        for _ in 0..(HANDSHAKE_RATE_PER_WINDOW * 5) {
            assert!(rl.check(lo).await);
        }
    }

    #[tokio::test]
    async fn rate_limit_drops_after_threshold_for_remote_ip() {
        let rl = PerIpRateLimit::new();
        let remote = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        for _ in 0..HANDSHAKE_RATE_PER_WINDOW {
            assert!(rl.check(remote).await);
        }
        // Next one should be denied.
        assert!(!rl.check(remote).await);
    }

    #[tokio::test]
    async fn rate_limit_isolates_distinct_ips() {
        let rl = PerIpRateLimit::new();
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        for _ in 0..HANDSHAKE_RATE_PER_WINDOW {
            assert!(rl.check(a).await);
        }
        // a is now exhausted, but b is fresh.
        assert!(!rl.check(a).await);
        assert!(rl.check(b).await);
    }

    #[tokio::test]
    async fn rate_limit_gc_drops_expired_windows() {
        let rl = PerIpRateLimit::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        rl.check(ip).await;
        // Force-age the entry past the window.
        {
            let mut e = rl.entries.lock().await;
            let v = e.get_mut(&ip).unwrap();
            v.0 = Instant::now() - RATE_WINDOW - Duration::from_secs(1);
        }
        rl.gc().await;
        assert!(rl.entries.lock().await.is_empty());
    }
}
