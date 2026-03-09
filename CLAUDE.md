# Distributed Hashcat Orchestration Tool

## Architecture

Coordinator–Worker model with three binaries in a Cargo workspace:

| Binary | Role | Transport |
|--------|------|-----------|
| `crack-coord` | Coordinator server + ratatui TUI dashboard | REST (127.0.0.1) + Noise-encrypted TCP (workers) |
| `crack-agent` | Worker agent, runs hashcat, reports results | Noise-encrypted TCP client |
| `crackctl` | Operator CLI for task/worker management | HTTP client to REST API |

Shared library: `crack-common` (models, protocol, auth, hashcat constants).

## Project Structure

```
crates/
├── crack-common/src/     # Shared types + Noise auth helpers
│   ├── models.rs         # Task, Chunk, Worker, CrackedHash, etc.
│   ├── protocol.rs       # CoordMessage / WorkerMessage + wire framing
│   ├── auth.rs           # Keypair gen/load, Noise IK builders
│   ├── hashcat.rs        # Hash mode constants, --status-json parsing
│   └── error.rs
├── crack-coord/src/      # Coordinator server
│   ├── main.rs           # CLI (init/run), spawns all subsystems
│   ├── config.rs         # clap CLI definition
│   ├── state.rs          # Arc<AppState> shared between server/TUI
│   ├── api/              # REST endpoints (axum, 127.0.0.1 only)
│   ├── transport/        # Noise TCP listener + per-connection handler
│   ├── scheduler/        # chunker (keyspace math) + assigner (dispatch)
│   ├── storage/          # db.rs (SQLite via sqlx) + files.rs (disk)
│   ├── monitor.rs        # Heartbeat checks + chunk reassignment
│   └── tui/              # Ratatui dashboard (Catppuccin Mocha theme)
│       ├── app.rs        # TUI state, tab/focus management
│       ├── event.rs      # Terminal event reader
│       ├── keys.rs       # Vim keybindings
│       ├── layout.rs     # Split-pane layout
│       ├── theme.rs      # Catppuccin Mocha palette
│       └── views/        # tasks, workers, results, audit, help
├── crack-agent/src/      # Worker agent
│   ├── main.rs           # CLI (init/run)
│   ├── config.rs         # clap CLI + RunConfig
│   ├── connection.rs     # Noise TCP client + reconnect loop
│   ├── runner.rs         # Hashcat process management
│   └── status.rs         # --status-json parsing, hashcat detection
└── crackctl/src/         # Operator CLI
    ├── main.rs           # clap subcommands
    ├── client.rs         # reqwest HTTP client
    └── display.rs        # Terminal table formatting
```

## Key Technical Decisions

- **Noise_IK protocol** (via `snow` crate) for transport encryption — WireGuard-grade, mutual authentication via Curve25519 static keys
- **SQLite** (via `sqlx`) for persistence — WAL mode, embedded schema in db.rs
- **No plaintext fallback** — all worker↔coordinator traffic encrypted
- **Cursor-based chunking** — no pre-splitting, workers pull chunks on demand
- **Adaptive chunk sizing** — based on worker benchmark speed (10-min target)
- REST API on 127.0.0.1 only — no auth needed (same-machine access)

## Database

SQLite at `<data-dir>/crack-coord.db`. Schema embedded in `storage/db.rs` (INIT_SQL constant). Tables: files, tasks, chunks, cracked_hashes, workers, worker_benchmarks, audit_log.

## Running

```bash
# Initialize
crack-coord init --data-dir ./data
crack-agent init --coord-key <pubkey> --data-dir ~/.crack-agent

# Authorize worker
crackctl worker authorize --pubkey <worker-pubkey> --name "Alice"

# Start
crack-coord run --bind 0.0.0.0:8443 --with-agent
crack-agent run --server <coord-ip>:8443

# Create task
crackctl file upload ntds.txt --type hash
crackctl task create --name "NTDS brute" --hash-mode 1000 --hash-file <id> --mask '?a?a?a?a?a?a'
```

## Post-MVP TODOs

- Wordlist attacks (mode 0) + rules support
- Hybrid attacks (modes 6, 7)
- Wordlist file distribution + SHA-256 caching on workers
- `crackctl task show --watch` live terminal refresh
- Web UI dashboard
- Multi-task priority scheduling
- Graceful shutdown with worker draining
- Integration tests with mock workers
- Cloud worker support (AWS/GCP GPU instances)
- Encrypted SQLite via sqlcipher
- Encrypted file storage on disk
- Memory zeroing on all secret-holding structs (partially done via zeroize on Keypair)
- Hashcat outfile written to tmpfs/ramdisk
- Auto-expiry for old results
