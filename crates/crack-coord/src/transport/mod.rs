pub mod handler;

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing::{error, info};

use crate::state::AppState;

/// Start the Noise-encrypted transport listener.
///
/// Binds a TCP listener on `bind_addr` and spawns a dedicated tokio task for
/// each incoming connection. The per-connection handler performs a Noise IK
/// handshake (coordinator as responder), verifies the worker's public key
/// against the database, and then runs an encrypted message loop.
pub async fn start_transport(state: Arc<AppState>, bind_addr: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!(addr = %bind_addr, "noise transport listening");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!(%peer_addr, "incoming worker connection");
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    handler::handle_connection(state, stream, peer_addr).await;
                });
            }
            Err(e) => {
                error!(error = %e, "failed to accept connection");
            }
        }
    }
}
