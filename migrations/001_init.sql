CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    disk_path TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hash_mode INTEGER NOT NULL,
    hash_file_id TEXT NOT NULL REFERENCES files(id),
    attack_config TEXT NOT NULL,
    total_keyspace INTEGER,
    next_skip INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 5,
    status TEXT NOT NULL DEFAULT 'pending',
    total_hashes INTEGER NOT NULL DEFAULT 0,
    cracked_count INTEGER NOT NULL DEFAULT 0,
    extra_args TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    skip INTEGER NOT NULL,
    "limit" INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    assigned_worker TEXT,
    assigned_at TEXT,
    completed_at TEXT,
    progress REAL NOT NULL DEFAULT 0.0,
    speed INTEGER NOT NULL DEFAULT 0,
    cracked_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cracked_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    plaintext TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    cracked_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cracked_unique ON cracked_hashes(task_id, hash);

CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    devices TEXT NOT NULL DEFAULT '[]',
    hashcat_version TEXT,
    os TEXT,
    status TEXT NOT NULL DEFAULT 'disconnected',
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS worker_benchmarks (
    worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    hash_mode INTEGER NOT NULL,
    speed INTEGER NOT NULL,
    measured_at TEXT NOT NULL,
    PRIMARY KEY (worker_id, hash_mode)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL,
    source_ip TEXT,
    worker_id TEXT,
    created_at TEXT NOT NULL
);
