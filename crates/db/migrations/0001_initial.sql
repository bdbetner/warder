CREATE TABLE IF NOT EXISTS protected_zones (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    root_paths_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    agent_label TEXT NOT NULL,
    agent_profile TEXT,
    command_json TEXT NOT NULL,
    protected_zone_ids_json TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    root_pid INTEGER,
    cgroup_path TEXT,
    cgroup_status TEXT NOT NULL,
    cgroup_message TEXT,
    landlock_status TEXT NOT NULL,
    landlock_message TEXT,
    snapshot_status TEXT NOT NULL,
    snapshot_backend TEXT,
    snapshot_id TEXT,
    snapshot_root TEXT,
    snapshot_message TEXT,
    degraded_reasons_json TEXT NOT NULL,
    dependency_file_changes_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_sessions_agent_started
ON sessions(agent_id, started_at);

CREATE TABLE IF NOT EXISTS policy_rules (
    id TEXT PRIMARY KEY,
    protected_zone_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    effect TEXT NOT NULL,
    path_scope TEXT,
    file_globs_json TEXT NOT NULL,
    expires_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_policy_rules_protected_zone_agent
ON policy_rules(protected_zone_id, agent_id, capability);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    protected_zone_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    decision TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_protected_zone_timestamp
ON audit_events(protected_zone_id, timestamp);

CREATE TABLE IF NOT EXISTS file_journal_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    process_id INTEGER,
    protected_zone_id TEXT,
    path TEXT NOT NULL,
    operation TEXT NOT NULL,
    decision TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL,
    attribution TEXT NOT NULL DEFAULT 'unknown',
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_journal_events_session_timestamp
ON file_journal_events(session_id, timestamp, id);

CREATE TABLE IF NOT EXISTS network_journal_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    process_id INTEGER,
    destination TEXT NOT NULL,
    destination_port INTEGER,
    protocol TEXT NOT NULL,
    decision TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence TEXT NOT NULL,
    attribution TEXT NOT NULL DEFAULT 'unknown',
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_network_journal_events_session_timestamp
ON network_journal_events(session_id, timestamp, id);

CREATE TABLE IF NOT EXISTS session_integrity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_integrity_log_session_id
ON session_integrity_log(session_id, id);
