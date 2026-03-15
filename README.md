# crack-orchestrate

Distributed hashcat orchestration tool. Splits cracking work across GPU workers with encrypted transport, live TUI dashboards, and multi-phase campaign support.

## Architecture

```
                    crackctl (CLI)
                        |
                    REST API (127.0.0.1)
                        |
  ┌─────────────────────┴─────────────────────┐
  │            crack-coord                     │
  │  ┌────────┐ ┌──────────┐ ┌─────────────┐  │
  │  │Scheduler│ │ SQLite DB│ │ TUI Dashboard│  │
  │  └────┬───┘ └──────────┘ └─────────────┘  │
  │       │                                    │
  │    Noise IK encrypted TCP                  │
  └───────┼────────────────┬───────────────────┘
          │                │
    ┌─────┴─────┐    ┌─────┴─────┐
    │crack-agent│    │crack-agent│    ...
    │  hashcat  │    │  hashcat  │
    │  GPU(s)   │    │  GPU(s)   │
    └───────────┘    └───────────┘
```

| Binary | Role |
|--------|------|
| `crack-coord` | Coordinator server with ratatui TUI dashboard |
| `crack-agent` | Worker agent — runs hashcat, reports results |
| `crackctl` | Operator CLI for task/worker/campaign management |

## Quick Start

### Prerequisites

- Rust 1.70+
- hashcat installed and in PATH

### Build

```bash
cargo build --release
```

Binaries are in `target/release/`: `crack-coord`, `crack-agent`, `crackctl`.

### Single-Machine Setup

The fastest way to get started — coordinator and agent on the same box:

```bash
# Start coordinator with built-in agent
crack-coord run --with-agent

# Upload a hash file
crackctl file upload hashes.txt --type hash

# Create a task
crackctl task create \
  --name "NTLM brute" \
  --hash-mode 1000 \
  --hash-file <file-id> \
  --mask '?a?a?a?a?a?a'
```

The coordinator TUI shows live progress across all tabs (Tasks, Workers, Results, Audit Log, Campaigns).

### Multi-Machine Setup

**On the coordinator:**

```bash
# Initialize and start
crack-coord run --bind 0.0.0.0:8443

# Generate an enrollment token for a worker
crackctl worker enroll --name "gpu-server-1"
```

**On each worker:**

```bash
# Enroll using the token (server address is embedded)
crack-agent enroll --token '<token>'

# Or for subsequent runs after enrollment:
crack-agent run --server <coord-ip>:8443
```

The agent shows a mini TUI dashboard with connection status, chunk progress, and cracked hashes. Use `--headless` for log-only output.

## Campaigns

Campaigns chain multiple attack phases together — brute-force sweeps of increasing length, mask attacks from plaintext analysis, and more. Uncracked hashes automatically carry forward between phases.

```bash
# Create a campaign from a built-in template
crackctl campaign create \
  --name "Full NTLM audit" \
  --hash-mode 1000 \
  --hash-file-path ntds_hashes.txt \
  --template ntlm-standard \
  --auto-start

# List available templates
crackctl campaign templates

# Monitor progress
crackctl campaign show <id>
```

## Commands

### crackctl

```
crackctl task create    Create a cracking task
crackctl task list      List all tasks
crackctl task show      Show task details with chunks
crackctl task results   Show cracked hashes
crackctl task cancel    Cancel a running task

crackctl file upload    Upload a hash file
crackctl file list      List uploaded files

crackctl worker list    List all workers
crackctl worker authorize   Pre-authorize by public key
crackctl worker enroll      Generate enrollment token

crackctl campaign create    Create a multi-phase campaign
crackctl campaign list      List all campaigns
crackctl campaign show      Show campaign with phases
crackctl campaign start     Start a draft campaign
crackctl campaign results   Show all cracked hashes
crackctl campaign templates List built-in templates

crackctl potfile stats  Show potfile statistics
crackctl potfile export Export cracked plaintexts
crackctl status         System overview
```

### crack-coord

```
crack-coord init        Initialize coordinator (generate keys)
crack-coord run         Start the coordinator
  --bind                Worker transport address (default: 0.0.0.0:8443)
  --api-bind            REST API address (default: 127.0.0.1:9443)
  --with-agent          Also run a local worker agent
  --headless            No TUI, log output only
  --hashcat-path        Path to hashcat binary
```

### crack-agent

```
crack-agent init        Initialize agent (generate keys)
crack-agent enroll      Enroll via token from coordinator
  --token               Enrollment token (required)
  --server              Override server address from token
crack-agent run         Connect and process work
  --server              Coordinator address (required)
  --headless            No TUI, log output only
  --hashcat-path        Path to hashcat binary
```

## Security

- **Noise IK protocol** (via `snow`) for all worker-coordinator traffic — mutual authentication with Curve25519 static keys, forward secrecy, no plaintext fallback
- **REST API binds to 127.0.0.1 only** — same-machine access, no authentication needed
- **Token-based enrollment** — time-limited tokens with embedded coordinator public key
- **SQLite with WAL mode** — embedded, no network-exposed database

## How It Works

1. **Hash file upload** — operator uploads hashes via `crackctl`, stored on coordinator disk
2. **Task/campaign creation** — defines hash mode, attack parameters, and priority
3. **Keyspace computation** — coordinator runs `hashcat --keyspace` to determine total work
4. **Adaptive chunking** — chunks sized based on worker benchmark speed (~10 min target)
5. **Chunk dispatch** — coordinator assigns chunks to idle workers over encrypted channel
6. **Hashcat execution** — agent runs hashcat with `--status-json`, streams progress back
7. **Result collection** — cracked hashes reported in real-time, stored in SQLite
8. **Campaign advancement** — when a phase exhausts, uncracked hashes roll into the next phase

## Project Structure

```
crates/
├── crack-common/     Shared types, Noise auth, protocol, hashcat helpers
├── crack-coord/      Coordinator server
│   ├── api/          REST endpoints (axum)
│   ├── campaign/     Multi-phase campaign engine + templates
│   ├── scheduler/    Keyspace chunking + chunk assignment
│   ├── storage/      SQLite persistence + file storage
│   ├── transport/    Noise TCP listener + handler
│   └── tui/          Ratatui dashboard (Catppuccin Mocha theme)
├── crack-agent/      Worker agent
│   ├── connection    Noise TCP client + reconnect loop
│   ├── runner        Hashcat process management
│   └── tui           Mini dashboard
└── crackctl/         Operator CLI
```

## License

MIT
