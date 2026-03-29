# crackswarm

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/thijsvos/crackswarm/actions/workflows/ci.yml/badge.svg)](https://github.com/thijsvos/crackswarm/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/thijsvos/crackswarm)](https://github.com/thijsvos/crackswarm/releases)

Distributed hashcat orchestration tool. Splits cracking work across GPU workers with encrypted transport, live TUI dashboards, and multi-phase campaign support.

## Features

- **Distributed cracking** -- coordinate hashcat across multiple GPU workers from a single dashboard
- **Multiple attack modes** -- brute-force/mask, dictionary, and dictionary+rules attacks
- **Bundled rules** -- includes [OneRuleToRuleThemStill](https://github.com/stealthsploit/OneRuleToRuleThemStill) (48K rules by [Will Hunt](https://github.com/stealthsploit), MIT license)
- **Noise IK encryption** -- all worker traffic is end-to-end encrypted (WireGuard-grade, via `snow`)
- **Live TUI dashboards** -- real-time progress on both coordinator and agents with vim keybindings
- **Multi-phase campaigns** -- chain attack phases together; uncracked hashes roll forward automatically
- **Pattern analyzer** -- examines cracked passwords to generate targeted masks for subsequent phases
- **Adaptive chunking** -- chunk sizes tuned to worker GPU speed (~10 min target per chunk)
- **Token-based enrollment** -- onboard new workers with a single command, no manual key exchange
- **Automatic failover** -- heartbeat monitoring with chunk reassignment on worker disconnect

## Architecture

```
                 crackctl (CLI)
                      |
              REST API (127.0.0.1)
                      |
  ┌───────────────────┴───────────────────┐
  │            crack-coord                │
  │                                       │
  │  ┌───────────┐ ┌────────┐ ┌─────────┐ │
  │  │ Scheduler │ │ SQLite │ │   TUI   │ │
  │  └───────────┘ └────────┘ └─────────┘ │
  │                                       │
  │        Noise IK encrypted TCP         │
  └──────────┬───────────────┬────────────┘
             │               │
     ┌───────┴───────┐ ┌─────┴─────────┐
     │  crack-agent  │ │  crack-agent  │  ...
     │    hashcat    │ │    hashcat    │
     │    GPU(s)     │ │    GPU(s)     │
     └───────────────┘ └───────────────┘
```

| Binary | Role |
|--------|------|
| `crack-coord` | Coordinator server with TUI dashboard |
| `crack-agent` | Worker agent -- runs hashcat, reports results |
| `crackctl` | Operator CLI for task/worker/campaign management |

## Quick Start

### Prerequisites

- **Rust toolchain** -- install via [rustup](https://rustup.rs/)
- **hashcat** -- installed and in PATH ([hashcat.net](https://hashcat.net/hashcat/))
- GPU drivers appropriate for your hardware (NVIDIA, AMD, etc.)

### Build

```bash
cargo build --release
```

Binaries are in `target/release/`: `crack-coord`, `crack-agent`, `crackctl`.

Pre-built binaries for Linux, macOS, and Windows are available on the [releases page](https://github.com/thijsvos/crackswarm/releases).

### Single-Machine Setup

The fastest way to get started -- coordinator and agent on the same box:

```bash
# Start coordinator with a built-in local agent
crack-coord run --with-agent

# Upload a hash file
crackctl file upload hashes.txt

# Create a brute-force task
crackctl task create \
  --name "NTLM brute" \
  --hash-mode 1000 \
  --hash-file <file-id> \
  --mask '?a?a?a?a?a?a'
```

The coordinator TUI shows live progress across five tabs: Tasks, Workers, Results, Audit Log, and Campaigns.

### Multi-Machine Setup

**On the coordinator:**

```bash
# Start the coordinator
crack-coord run --bind 0.0.0.0:8443

# Generate an enrollment token for a new worker
crackctl worker enroll --name "gpu-server-1"
```

**On each worker:**

```bash
# Enroll using the token (server address is embedded in it)
crack-agent enroll --token '<token>'

# On subsequent runs, the agent reconnects automatically
crack-agent run --server <coord-ip>:8443
```

Workers reconnect automatically with exponential backoff (1s to 60s) if the connection drops.

### Dictionary Attacks

Upload a wordlist and create a dictionary task:

```bash
# Upload a wordlist
crackctl file upload rockyou.txt --type wordlist

# Dictionary attack (hashcat -a 0)
crackctl task create --name "Dict attack" --hash-mode 1000 \
  --hash-file <hash-id> --wordlist <wordlist-id>
```

### Dictionary with Rules

The `rules/` directory includes [OneRuleToRuleThemStill](https://github.com/stealthsploit/OneRuleToRuleThemStill) -- an optimized rule set of 48,439 rules by [Will Hunt (@stealthsploit)](https://github.com/stealthsploit), MIT licensed. Upload it and combine with a wordlist:

```bash
# Upload rules file
crackctl file upload rules/OneRuleToRuleThemStill.rule --type rules

# Dictionary + rules attack
crackctl task create --name "Dict+OTRTS" --hash-mode 1000 \
  --hash-file <hash-id> --wordlist <wordlist-id> --rules-file <rules-id>
```

Wordlist and rules files are transferred to workers over the encrypted Noise channel and cached locally. Files are sent in ~40KB chunks and only transferred once per worker.

## TUI Dashboard

### Coordinator

The coordinator TUI has five tabs with vim-style navigation:

| Tab | Content |
|-----|---------|
| **Tasks** | Task list with progress gauges, speed, ETA, chunk breakdown |
| **Workers** | Worker status, GPU devices, hashcat version, last seen |
| **Results** | Cracked hashes with plaintext, worker attribution, timestamps |
| **Audit Log** | System events: connections, completions, errors |
| **Campaigns** | Campaign progress with per-phase status |

**Keybindings:**

| Key | Action |
|-----|--------|
| `1`-`5` | Jump to tab |
| `j`/`k` | Navigate up/down |
| `g`/`G` | Jump to top/bottom |
| `Ctrl+d`/`Ctrl+u` | Page down/up |
| `Tab` | Cycle panel focus |
| `/` | Search/filter current list |
| `:` | Command mode (`:cancel`, `:start`, `:delete`, `:quit`) |
| `?` | Toggle help overlay |
| `q` | Quit |

Toast notifications appear for worker connects/disconnects, completed tasks, and cracked hashes. Use `--headless` for log-only output (no TUI).

### Agent

The agent displays a single-screen dashboard with connection status, current chunk progress with speed/ETA, recent cracks (last 10), and session stats. Use `--headless` for log-only output.

## Campaigns

Campaigns chain multiple attack phases together. Uncracked hashes automatically carry forward between phases.

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

### Built-in Templates

| Template | Hash Mode | Phases | Description |
|----------|-----------|--------|-------------|
| `ntlm-standard` | 1000 (NTLM) | 6 | PIN sweep, common masks, pattern analysis, brute-force up to 8 chars |
| `wpa-quick` | 22000 (WPA) | 3 | 8-digit PINs, common 8-char masks, pattern analysis |
| `generic-quick` | Any | 5 | PIN sweep, common masks, pattern analysis, brute-force up to 7 chars |

### Phase Types

- **StaticMask** -- single mask attack
- **MultiMask** -- sequential list of masks, auto-advances through each
- **ExpandingBrute** -- brute-force with incrementing length (e.g., `?a` length 1 through 8)
- **AutoGenerated** -- the pattern analyzer examines already-cracked passwords and generates targeted masks for the next round

### Pattern Analyzer

The `AutoGenerated` phase type is the most distinctive feature. It examines passwords cracked in earlier phases to infer structural patterns:

1. Converts each cracked password to a skeleton (e.g., `Password1!` becomes `Ullllllld s`)
2. Ranks skeletons by frequency across the cracked set
3. Generates masks from the top patterns, including custom charset narrowing and suffix-anchored variants
4. Filters out masks already tried in previous phases

This creates a feedback loop: each round of cracking informs the next, targeting the most likely remaining password structures.

## Commands

### crackctl

```
crackctl [--api-url <url>]       Override API URL (default: http://127.0.0.1:9443)
                                 env: CRACKCTL_API_URL

Tasks:
  task create                    Create a cracking task
    --name <name>                  Task name (required)
    --hash-mode <mode>             Hashcat hash mode (required)
    --hash-file <id>               Hash file ID (required)
    --mask <mask>                  Attack mask for brute-force (mutually exclusive with --wordlist)
    --wordlist <id>                Wordlist file ID for dictionary attacks
    --rules-file <id>              Rules file ID (requires --wordlist)
    --charset1..4 <chars>          Custom charsets for ?1..?4
    --priority <1-10>              Task priority (default: 5)
    --extra-args <args>            Additional hashcat arguments
  task list                      List all tasks
  task show <id>                 Show task details with chunks
  task results <id>              Show cracked hashes for a task
  task cancel <id>               Cancel a running task
  task delete <id>               Delete a task

Files:
  file upload <path>             Upload a hash file
    --type <type>                  File type (default: hash)
  file list                      List uploaded files

Workers:
  worker list                    List all workers
  worker authorize               Pre-authorize a worker by public key
    --pubkey <key>                 Worker's base64 public key (required)
    --name <name>                  Worker name (required)
  worker enroll                  Generate an enrollment token
    --name <name>                  Worker name (required)
    --expires-minutes <min>        Token TTL (default: 60)

Campaigns:
  campaign create                Create a multi-phase campaign
    --name <name>                  Campaign name (required)
    --hash-mode <mode>             Hashcat hash mode (required)
    --hash-file-path <path>        Hash file path (auto-uploads)
    --template <name>              Use a built-in template
    --auto-start                   Start immediately after creation
    --priority <1-10>              Task priority (default: 5)
  campaign list                  List all campaigns
  campaign show <id>             Show campaign with phases
  campaign start <id>            Start a draft campaign
  campaign results <id>          Show all cracked hashes
  campaign cancel <id>           Cancel a running campaign
  campaign delete <id>           Delete a campaign
  campaign templates             List built-in templates

Potfile:
  potfile stats                  Show potfile statistics
  potfile export                 Export cracked plaintexts
    --output <path>                Write to file instead of stdout

System:
  status                         System overview
```

### crack-coord

```
crack-coord init                 Initialize coordinator (generate keys)
  --data-dir <path>                Data directory (default: platform data dir)

crack-coord run                  Start the coordinator
  --bind <addr>                    Worker transport address (default: 0.0.0.0:8443)
  --api-bind <addr>                REST API address (default: 127.0.0.1:9443)
  --data-dir <path>                Data directory
  --with-agent                     Run a local worker agent in the same process
  --headless                       No TUI, log output only
  --hashcat-path <path>            Path to hashcat binary (default: hashcat)
```

Environment variables: `CRACK_COORD_DATA_DIR`, `CRACK_COORD_BIND`, `CRACK_COORD_API_BIND`

### crack-agent

```
crack-agent init                 Initialize agent (generate keys)
  --coord-key <key>                Coordinator's base64 public key (required)
  --data-dir <path>                Data directory (default: platform data dir)

crack-agent enroll               Enroll via token from coordinator
  --token <token>                  Enrollment token (required)
  --server <addr>                  Override server address from token
  --data-dir <path>                Data directory
  --hashcat-path <path>            Path to hashcat binary

crack-agent run                  Connect and process work
  --server <addr>                  Coordinator address (required)
  --name <name>                    Worker name (default: hostname)
  --data-dir <path>                Data directory
  --headless                       No TUI, log output only
  --hashcat-path <path>            Path to hashcat binary (default: hashcat)
```

Environment variables: `CRACK_AGENT_DATA_DIR`, `CRACK_AGENT_SERVER`

## Security

- **Noise IK protocol** (via `snow`) for all worker-coordinator traffic -- mutual authentication with Curve25519 static keys, ChaCha20-Poly1305 encryption, forward secrecy, no plaintext fallback
- **REST API binds to 127.0.0.1 by default** -- same-machine access only, no authentication. If you override `--api-bind` to a non-loopback address, the API will be exposed without authentication
- **Token-based enrollment** -- time-limited tokens (default 60 min) with embedded coordinator public key and server address
- **Private key protection** -- keys stored with 0600 permissions (Unix), zeroed from memory on drop
- **SQLite with WAL mode** -- embedded, no network-exposed database
- **Heartbeat monitoring** -- 15-second interval, 60-second timeout; disconnected workers have their chunks automatically reassigned

## How It Works

1. **Hash file upload** -- operator uploads hashes via `crackctl`, stored on coordinator disk and transferred to agents over the encrypted channel
2. **Task/campaign creation** -- defines hash mode, attack mask, priority, and optional custom charsets
3. **Keyspace computation** -- coordinator runs `hashcat --keyspace` to determine total work units
4. **Adaptive chunking** -- chunk sizes tuned per-worker based on benchmark speed (~10 min target), with fair-share capping so no single worker monopolizes the keyspace
5. **Chunk dispatch** -- coordinator assigns chunks to idle workers over the Noise-encrypted channel
6. **Hashcat execution** -- agent runs hashcat with `--status-json`, streams progress and speed back to the coordinator in real-time
7. **Result collection** -- cracked hashes reported immediately, stored in SQLite, displayed in the TUI
8. **Campaign advancement** -- when a phase exhausts its keyspace, uncracked hashes roll into the next phase. `AutoGenerated` phases analyze cracked passwords to generate new targeted masks

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
