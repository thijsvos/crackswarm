# Changelog

All notable changes to Crackswarm are documented here.

## [0.9.0] - 2026-04-25

### Added
- Pull-based file RPC over the Noise channel: agents fetch hash files, wordlists, and rules on demand instead of receiving them over a push stream
- Content-addressed agent cache keyed by sha256, with hardlink fast path for same-host coord/agent setups
- `DictionaryByHash` dispatch — wordlists are referenced by hash and fetched lazily by agents
- Reference-counted file lifecycle on the coordinator with background garbage collection of unreferenced files
- Agent-side `EvictFile` protocol message and per-heartbeat cache manifest
- Cache reconciliation on (re)connect — coord and agent agree on what each side has after disconnect
- LRU eviction with configurable disk budget on the agent
- Operator cache controls in `crackctl`: `file pin`, `file unpin`, `file gc`, plus cache visibility commands
- Same-host hardlink fast path for local file uploads (avoids redundant copies)
- Streaming end-to-end byte transfer with progress bar on uploads
- Upload deduplication by sha256 content hash on the coordinator
- Keyspace cache and non-blocking task preparation (large keyspace tasks no longer stall the API loop)

### Fixed
- Race between GC and heartbeat-driven cache sync that could evict files mid-use
- GC eligibility now re-evaluated on unpin (a file pinned then unpinned would otherwise linger)
- Soft-delete used during GC to avoid foreign-key violations on in-flight references
- Clippy 1.95 lints and rustls-webpki CVE patches

### Changed
- Dependabot auto-merges patch/minor bumps when CI passes
- Bumped fetch-metadata to v3, polished dependabot config
- Workspace cargo update — 53 patch/minor dependency bumps
- Comprehensive rustdoc audit: drift fixes, `# Errors` sections on `Result`-returning public APIs, full public-API coverage

## [0.8.2] - 2026-03-29

### Added
- Dictionary phases in all campaign templates (ntlm-standard, wpa-quick, generic-quick)
- `--wordlist` and `--rules-file` flags for `crackctl campaign create`
- Dictionary phases auto-skipped when no wordlist provided (backward compatible)
- Potfile handling documentation in README
- Branch protection with required CI checks on main
- Issue and PR templates

### Changed
- Renamed repository from `password-crack-orchestrate` to `crackswarm`
- Release artifacts now named `crackswarm-<target>`

## [0.8.1] - 2026-03-29

### Fixed
- CI: cargo fmt, clippy warnings, audit ignore for transitive `rsa` advisory (RUSTSEC-2023-0071)

## [0.8.0] - 2026-03-29

### Added
- Dictionary attack support (hashcat `-a 0`) via `--wordlist` flag
- Dictionary + rules attack support via `--wordlist` + `--rules-file` flags
- Bundled [OneRuleToRuleThemStill](https://github.com/stealthsploit/OneRuleToRuleThemStill) rules (48,439 rules by Will Hunt, MIT license)
- Chunked file transfer over Noise-encrypted channel for wordlist/rules distribution to workers
- `TransferFileChunk` protocol message for streaming large files
- CI workflow with fmt, clippy, test, and security audit checks
- Dependabot configuration for Cargo and GitHub Actions
- LICENSE file (MIT)
- SECURITY.md with vulnerability disclosure policy
- Repository topics and README badges

### Changed
- `--mask` is now optional in `crackctl task create` (mutually exclusive with `--wordlist`)
- Campaign engine handles `PhaseConfig::Dictionary` phases (previously stubbed)
- Updated dependencies: reqwest 0.13, snow 0.10, rand 0.10, ratatui 0.30, crossterm 0.29, toml 1.0
- Updated GitHub Actions: checkout v6, upload-artifact v7, download-artifact v8

## [0.6.0] - 2026-03-11

### Added
- Multi-phase campaign system with built-in templates (ntlm-standard, wpa-quick, generic-quick)
- Pattern analyzer: examines cracked passwords to generate targeted masks
- Campaign TUI tab with phase-level progress tracking
- `crackctl campaign` subcommands (create, list, show, start, cancel, delete, results, templates)

## [0.5.0] - 2026-03-11

### Added
- Token-based worker enrollment (`crackctl worker enroll` + `crack-agent enroll`)
- Agent mini-TUI dashboard with connection status, chunk progress, recent cracks
- `--headless` mode for both coordinator and agent
- Potfile stats and export commands

## [0.4.0] - 2026-03-11

### Added
- Ratatui TUI dashboard with vim keybindings (Tasks, Workers, Results, Audit Log tabs)
- Catppuccin Mocha theme
- Search/filter, command mode, toast notifications
- Adaptive chunk sizing based on worker benchmark speed

## [0.3.0] - 2026-03-11

### Added
- Heartbeat monitoring with 60-second timeout
- Automatic chunk reassignment on worker disconnect
- Worker benchmarking for adaptive chunk sizing

## [0.2.0] - 2026-03-09

### Added
- REST API for task and worker management
- `crackctl` CLI tool
- File upload and hash file distribution to workers
- SQLite persistence with WAL mode

## [0.1.0] - 2026-03-09

### Added
- Initial release
- Coordinator-worker architecture with Noise IK encrypted transport
- Brute-force/mask attacks (hashcat mode 3)
- Keyspace computation and cursor-based chunking
- Basic task creation and chunk dispatch
