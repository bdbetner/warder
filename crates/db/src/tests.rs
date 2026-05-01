use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use warder_core::{
    ActorType, AgentIdentity, AgentKind, AuditDecision, AuditEvent, Capability, CgroupStatus,
    PolicyEffect, PolicyRule, ProtectedZone, SessionRecord, SessionStatus, SnapshotBackend,
    SnapshotStatus,
};
use warder_journal::{
    FileDecision, FileJournalEvent, FileOperation, JournalAttribution, JournalConfidence,
    JournalSource, NetworkDecision, NetworkJournalEvent, NetworkProtocol,
};

fn temp_db_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "warder-db-{name}-{}-{}.sqlite3",
        std::process::id(),
        timestamp().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn timestamp() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn store(name: &str) -> WarderDb {
    let store = WarderDb::open(temp_db_path(name)).unwrap();
    store.migrate().unwrap();
    store
}

fn temp_db_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "warder-db-{name}-{}-{}",
        std::process::id(),
        timestamp().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ))
}

fn protected_zone() -> ProtectedZone {
    ProtectedZone {
        id: "protected_zone-1".to_string(),
        name: "Research".to_string(),
        description: "Read-only notes".to_string(),
        root_paths: vec![PathBuf::from("/tmp/research"), PathBuf::from("/tmp/notes")],
        created_at: timestamp(),
        updated_at: timestamp(),
    }
}

fn agent() -> AgentIdentity {
    AgentIdentity {
        id: "agent-1".to_string(),
        name: "Local Script".to_string(),
        kind: AgentKind::LocalScript,
        token_hash: "token-hash".to_string(),
        created_at: timestamp(),
        expires_at: Some(timestamp() + Duration::from_secs(60)),
        disabled: false,
    }
}

#[test]
fn migrations_create_expected_tables() {
    let store = store("migrations");

    for table in [
        "protected_zones",
        "agents",
        "sessions",
        "policy_rules",
        "audit_events",
        "file_journal_events",
        "network_journal_events",
    ] {
        assert!(store.table_exists(table).unwrap(), "missing table {table}");
    }
}

#[test]
fn open_configures_wal_and_busy_timeout() {
    let store = WarderDb::open(temp_db_path("open-pragmas")).unwrap();

    let journal_mode: String = store
        .conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let busy_timeout: i64 = store
        .conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();

    assert_eq!(journal_mode, "wal");
    assert_eq!(busy_timeout, 5000);
}

#[cfg(unix)]
#[test]
fn open_creates_private_state_directory_and_database_file() {
    let root = temp_db_dir("private-state");
    let db_path = root.join("state").join("warder.sqlite3");
    let _ = std::fs::remove_dir_all(&root);

    let store = WarderDb::open(&db_path).unwrap();
    drop(store);

    let state_mode = std::fs::metadata(db_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let db_mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(state_mode, 0o700);
    assert_eq!(db_mode, 0o600);
}

#[test]
fn ensure_column_rejects_unknown_migration_identifiers() {
    let store = store("reject-unknown-migration-column");

    let error = store
        .ensure_column("sessions; DROP TABLE sessions; --", "bad", "TEXT")
        .unwrap_err();

    assert!(matches!(
        error,
        DbError::InvalidValue {
            field: "migration_column",
            ..
        }
    ));
}

#[test]
fn protected_zone_crud_round_trips() {
    let store = store("protected_zones");
    let mut protected_zone = protected_zone();

    store.create_protected_zone(&protected_zone).unwrap();
    assert_eq!(
        store.get_protected_zone(&protected_zone.id).unwrap(),
        Some(protected_zone.clone())
    );
    assert_eq!(
        store.list_protected_zones().unwrap(),
        vec![protected_zone.clone()]
    );

    protected_zone.name = "Updated".to_string();
    protected_zone.root_paths = vec![PathBuf::from("/tmp/updated")];
    store.update_protected_zone(&protected_zone).unwrap();

    assert_eq!(
        store.get_protected_zone(&protected_zone.id).unwrap(),
        Some(protected_zone)
    );
}

#[test]
fn agent_crud_round_trips() {
    let store = store("agents");
    let agent = agent();

    store.create_agent(&agent).unwrap();

    assert_eq!(store.get_agent(&agent.id).unwrap(), Some(agent.clone()));
    assert_eq!(store.list_agents().unwrap(), vec![agent]);
}

#[test]
fn sessions_round_trip_with_cgroup_and_snapshot_state() {
    let store = store("sessions");
    let mut session = SessionRecord {
        id: "session-1".to_string(),
        agent_id: "agent-1".to_string(),
        agent_label: "Local Script".to_string(),
        agent_profile: Some("local-script".to_string()),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        protected_zone_ids: vec!["protected_zone-1".to_string()],
        status: SessionStatus::Running,
        exit_code: None,
        started_at: timestamp(),
        ended_at: None,
        root_pid: Some(4242),
        cgroup_path: Some(PathBuf::from("/sys/fs/cgroup/warder/session-1")),
        cgroup_status: CgroupStatus::Tagged,
        landlock_status: warder_core::LandlockStatus::Applied,
        snapshot_status: SnapshotStatus::Created {
            backend: SnapshotBackend::Btrfs,
            snapshot_id: "snap-1".to_string(),
            snapshot_root: Some(PathBuf::from("/tmp/warder-snapshots")),
        },
        dependency_file_changes: vec![DependencyFileChange {
            path: PathBuf::from("/tmp/research/Cargo.toml"),
            before_hash: Some("before".to_string()),
            after_hash: Some("after".to_string()),
            status: DependencyFileChangeStatus::Modified,
        }],
        degraded_reasons: vec!["eBPF unavailable".to_string()],
    };

    store.create_session(&session).unwrap();
    assert_eq!(
        store.get_session(&session.id).unwrap(),
        Some(session.clone())
    );
    assert_eq!(store.list_sessions().unwrap(), vec![session.clone()]);

    session.status = SessionStatus::Completed;
    session.exit_code = Some(0);
    session.ended_at = Some(timestamp() + Duration::from_secs(10));
    session.cgroup_status = CgroupStatus::Degraded("failed to tag child process".to_string());
    session.landlock_status =
        warder_core::LandlockStatus::Degraded("Landlock ruleset unavailable".to_string());
    session.snapshot_status = SnapshotStatus::Reverted {
        backend: SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(PathBuf::from("/tmp/warder-snapshots")),
    };
    session
        .degraded_reasons
        .push("child process escaped cgroup".to_string());
    store.update_session(&session).unwrap();

    assert_eq!(store.get_session(&session.id).unwrap(), Some(session));
}

#[test]
fn file_journal_events_round_trip_by_session() {
    let store = store("file-journal-events");
    let event = FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: timestamp(),
        process_id: Some(4242),
        protected_zone_id: Some("protected_zone-1".to_string()),
        path: PathBuf::from("/tmp/research/notes.md"),
        operation: FileOperation::Write,
        decision: FileDecision::Denied,
        source: JournalSource::Landlock,
        confidence: JournalConfidence::Enforced,
        attribution: JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    };

    store.insert_file_journal_event(&event).unwrap();

    assert_eq!(
        store.list_file_journal_events(Some("session-1")).unwrap(),
        vec![event]
    );
    assert!(store
        .list_file_journal_events(Some("missing-session"))
        .unwrap()
        .is_empty());
}

#[test]
fn network_journal_events_round_trip_by_session() {
    let store = store("network-journal-events");
    let event = NetworkJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: timestamp(),
        process_id: Some(4242),
        destination: "203.0.113.10".to_string(),
        destination_port: Some(443),
        protocol: NetworkProtocol::Tcp,
        decision: NetworkDecision::Observed,
        source: JournalSource::Procfs,
        confidence: JournalConfidence::Observed,
        attribution: JournalAttribution::DirectProcess,
        message: "connected socket observed by procfs inode=12345".to_string(),
    };

    store.insert_network_journal_event(&event).unwrap();

    assert_eq!(
        store
            .list_network_journal_events(Some("session-1"))
            .unwrap(),
        vec![event]
    );
    assert!(store
        .list_network_journal_events(Some("missing-session"))
        .unwrap()
        .is_empty());
}

#[test]
fn policy_rules_round_trip_by_protected_zone() {
    let store = store("policy-rules");
    let rule = PolicyRule {
        id: "rule-1".to_string(),
        protected_zone_id: "protected_zone-1".to_string(),
        agent_id: "agent-1".to_string(),
        capability: Capability::ReadFile,
        effect: PolicyEffect::Allow,
        path_scope: Some(PathBuf::from("/tmp/research")),
        file_globs: vec!["*.md".to_string(), "*.txt".to_string()],
        expires_at: Some(timestamp() + Duration::from_secs(60)),
    };

    store.create_policy_rule(&rule).unwrap();

    assert_eq!(
        store.list_policy_rules(&rule.protected_zone_id).unwrap(),
        vec![rule]
    );
}

#[test]
fn audit_events_insert_and_list_in_time_order() {
    let store = store("audit-events");
    let first = AuditEvent {
        id: "audit-1".to_string(),
        timestamp: timestamp(),
        actor_type: ActorType::Agent,
        actor_id: "agent-1".to_string(),
        protected_zone_id: "protected_zone-1".to_string(),
        action: "read_file".to_string(),
        target: "/tmp/research/notes.md".to_string(),
        decision: AuditDecision::Allowed,
        metadata_json: "{}".to_string(),
    };
    let second = AuditEvent {
        id: "audit-2".to_string(),
        timestamp: timestamp() + Duration::from_secs(1),
        action: "read_file".to_string(),
        ..first.clone()
    };

    store.insert_audit_event(&second).unwrap();
    store.insert_audit_event(&first).unwrap();

    assert_eq!(
        store.list_audit_events().unwrap(),
        vec![first.clone(), second.clone()]
    );
    assert_eq!(
        store
            .list_audit_events_for_protected_zone("protected_zone-1")
            .unwrap(),
        vec![first, second]
    );
}
