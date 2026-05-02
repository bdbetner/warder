use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use warder_core::{
    ActorType, AgentIdentity, AgentKind, AuditDecision, AuditEvent, Capability, CgroupStatus,
    DependencyFileChange, DependencyFileChangeStatus, LandlockStatus, PolicyEffect, PolicyRule,
    ProtectedZone, SessionRecord, SessionStatus, SnapshotBackend, SnapshotStatus,
};
use warder_journal::{
    FileDecision, FileJournalEvent, FileOperation, JournalAttribution, JournalConfidence,
    JournalSource, NetworkDecision, NetworkJournalEvent, NetworkProtocol,
};

pub type DbResult<T> = Result<T, DbError>;

#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidTimestamp(i64),
    InvalidValue { field: &'static str, value: String },
    MissingSession(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptIntegrityReport {
    pub verified_sessions: usize,
    pub log_entries: usize,
    pub issues: Vec<ReceiptIntegrityIssue>,
}

impl ReceiptIntegrityReport {
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptIntegrityIssue {
    pub session_id: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionIntegrityEntry {
    id: i64,
    session_id: String,
    event_kind: String,
    payload_hash: String,
    previous_hash: String,
    entry_hash: String,
    created_at: i64,
}

impl From<rusqlite::Error> for DbError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<std::io::Error> for DbError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for DbError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub struct WarderDb {
    conn: Connection,
}

impl WarderDb {
    pub fn open(path: impl AsRef<Path>) -> DbResult<Self> {
        let path = path.as_ref();
        prepare_db_path(path)?;
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        set_db_file_permissions(path)?;
        Ok(Self { conn })
    }

    pub fn migrate(&self) -> DbResult<()> {
        self.conn.execute_batch(MIGRATIONS)?;
        self.ensure_column("sessions", "agent_profile", "TEXT")?;
        self.ensure_column(
            "sessions",
            "dependency_file_changes_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        self.ensure_column("sessions", "exit_code", "INTEGER")?;
        self.ensure_column("sessions", "snapshot_root", "TEXT")?;
        self.ensure_column(
            "file_journal_events",
            "attribution",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )?;
        Ok(())
    }

    fn ensure_column(
        &self,
        table_name: &str,
        column_name: &str,
        column_type: &str,
    ) -> DbResult<()> {
        validate_migration_column(table_name, column_name, column_type)?;
        let mut statement = self.conn.prepare(&format!(
            "PRAGMA table_info({})",
            quote_identifier(table_name)
        ))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let existing: String = row.get(1)?;
            if existing == column_name {
                return Ok(());
            }
        }
        self.conn.execute(
            &format!(
                "ALTER TABLE {} ADD COLUMN {} {column_type}",
                quote_identifier(table_name),
                quote_identifier(column_name)
            ),
            [],
        )?;
        Ok(())
    }

    fn append_session_integrity_event(
        &self,
        event_kind: &'static str,
        session: &SessionRecord,
    ) -> DbResult<()> {
        let previous_hash = self
            .latest_integrity_entry_hash()?
            .unwrap_or_else(genesis_integrity_hash);
        let payload_hash = session_payload_hash(session)?;
        let created_at = encode_time(SystemTime::now());
        let entry_hash = integrity_entry_hash(
            &previous_hash,
            &session.id,
            event_kind,
            &payload_hash,
            created_at,
        );
        self.conn.execute(
            "INSERT INTO session_integrity_log (
                session_id, event_kind, payload_hash, previous_hash, entry_hash, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session.id,
                event_kind,
                payload_hash,
                previous_hash,
                entry_hash,
                created_at
            ],
        )?;
        Ok(())
    }

    fn latest_integrity_entry_hash(&self) -> DbResult<Option<String>> {
        let mut statement = self.conn.prepare(
            "SELECT entry_hash
             FROM session_integrity_log
             ORDER BY id DESC
             LIMIT 1",
        )?;
        let mut rows = statement.query([])?;
        rows.next()?
            .map(|row| row.get(0))
            .transpose()
            .map_err(Into::into)
    }

    fn session_integrity_entries(&self) -> DbResult<Vec<SessionIntegrityEntry>> {
        let mut statement = self.conn.prepare(
            "SELECT id, session_id, event_kind, payload_hash, previous_hash, entry_hash, created_at
             FROM session_integrity_log
             ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next()? {
            entries.push(SessionIntegrityEntry {
                id: row.get(0)?,
                session_id: row.get(1)?,
                event_kind: row.get(2)?,
                payload_hash: row.get(3)?,
                previous_hash: row.get(4)?,
                entry_hash: row.get(5)?,
                created_at: row.get(6)?,
            });
        }
        Ok(entries)
    }

    pub fn table_exists(&self, table_name: &str) -> DbResult<bool> {
        let exists = self.conn.query_row(
            "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = ?1
                )",
            [table_name],
            |row| row.get::<_, i64>(0),
        )? == 1;
        Ok(exists)
    }

    pub fn create_protected_zone(&self, protected_zone: &ProtectedZone) -> DbResult<()> {
        let root_paths = encode_paths(&protected_zone.root_paths)?;
        self.conn.execute(
            "INSERT INTO protected_zones (
                id, name, description, root_paths_json, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                protected_zone.id,
                protected_zone.name,
                protected_zone.description,
                root_paths,
                encode_time(protected_zone.created_at),
                encode_time(protected_zone.updated_at)
            ],
        )?;
        Ok(())
    }

    pub fn list_protected_zones(&self) -> DbResult<Vec<ProtectedZone>> {
        let mut statement = self.conn.prepare(
            "SELECT id, name, description, root_paths_json, created_at, updated_at
             FROM protected_zones
             ORDER BY created_at, id",
        )?;
        let mut rows = statement.query([])?;
        let mut protected_zones = Vec::new();
        while let Some(row) = rows.next()? {
            protected_zones.push(read_protected_zone(row)?);
        }
        Ok(protected_zones)
    }

    pub fn get_protected_zone(&self, id: &str) -> DbResult<Option<ProtectedZone>> {
        let mut statement = self.conn.prepare(
            "SELECT id, name, description, root_paths_json, created_at, updated_at
             FROM protected_zones
             WHERE id = ?1",
        )?;
        let mut rows = statement.query([id])?;
        rows.next()?.map(read_protected_zone).transpose()
    }

    pub fn update_protected_zone(&self, protected_zone: &ProtectedZone) -> DbResult<()> {
        let root_paths = encode_paths(&protected_zone.root_paths)?;
        self.conn.execute(
            "UPDATE protected_zones
             SET name = ?2,
                 description = ?3,
                 root_paths_json = ?4,
                 created_at = ?5,
                 updated_at = ?6
             WHERE id = ?1",
            params![
                protected_zone.id,
                protected_zone.name,
                protected_zone.description,
                root_paths,
                encode_time(protected_zone.created_at),
                encode_time(protected_zone.updated_at)
            ],
        )?;
        Ok(())
    }

    pub fn create_agent(&self, agent: &AgentIdentity) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO agents (
                id, name, kind, token_hash, created_at, expires_at, disabled
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                agent.id,
                agent.name,
                agent_kind_to_str(&agent.kind),
                agent.token_hash,
                encode_time(agent.created_at),
                encode_optional_time(agent.expires_at),
                agent.disabled
            ],
        )?;
        Ok(())
    }

    pub fn list_agents(&self) -> DbResult<Vec<AgentIdentity>> {
        let mut statement = self.conn.prepare(
            "SELECT id, name, kind, token_hash, created_at, expires_at, disabled
             FROM agents
             ORDER BY name, id",
        )?;
        let mut rows = statement.query([])?;
        let mut agents = Vec::new();
        while let Some(row) = rows.next()? {
            agents.push(read_agent(row)?);
        }
        Ok(agents)
    }

    pub fn get_agent(&self, id: &str) -> DbResult<Option<AgentIdentity>> {
        let mut statement = self.conn.prepare(
            "SELECT id, name, kind, token_hash, created_at, expires_at, disabled
             FROM agents
             WHERE id = ?1",
        )?;
        let mut rows = statement.query([id])?;
        rows.next()?.map(read_agent).transpose()
    }

    pub fn create_session(&self, session: &SessionRecord) -> DbResult<()> {
        let (cgroup_status, cgroup_message) = encode_cgroup_status(&session.cgroup_status);
        let (landlock_status, landlock_message) = encode_landlock_status(&session.landlock_status);
        let (snapshot_status, snapshot_backend, snapshot_id, snapshot_root, snapshot_message) =
            encode_snapshot_status(&session.snapshot_status);
        self.conn.execute(
            "INSERT INTO sessions (
                id, agent_id, agent_label, agent_profile, command_json, protected_zone_ids_json, status,
                exit_code, started_at, ended_at, root_pid, cgroup_path, cgroup_status, cgroup_message,
                landlock_status, landlock_message, snapshot_status, snapshot_backend, snapshot_id, snapshot_root, snapshot_message,
                degraded_reasons_json, dependency_file_changes_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
            params![
                session.id,
                session.agent_id,
                session.agent_label,
                session.agent_profile,
                encode_strings(&session.command)?,
                encode_strings(&session.protected_zone_ids)?,
                session_status_to_str(session.status),
                session.exit_code.map(i64::from),
                encode_time(session.started_at),
                encode_optional_time(session.ended_at),
                session.root_pid.map(|pid| pid as i64),
                session.cgroup_path.as_ref().map(|path| path_to_string(path)),
                cgroup_status,
                cgroup_message,
                landlock_status,
                landlock_message,
                snapshot_status,
                snapshot_backend,
                snapshot_id,
                snapshot_root,
                snapshot_message,
                encode_strings(&session.degraded_reasons)?,
                encode_dependency_file_changes(&session.dependency_file_changes)?,
            ],
        )?;
        self.append_session_integrity_event("create", session)?;
        Ok(())
    }

    pub fn update_session(&self, session: &SessionRecord) -> DbResult<()> {
        let (cgroup_status, cgroup_message) = encode_cgroup_status(&session.cgroup_status);
        let (landlock_status, landlock_message) = encode_landlock_status(&session.landlock_status);
        let (snapshot_status, snapshot_backend, snapshot_id, snapshot_root, snapshot_message) =
            encode_snapshot_status(&session.snapshot_status);
        let changed = self.conn.execute(
            "UPDATE sessions
             SET agent_id = ?2,
                 agent_label = ?3,
                 agent_profile = ?4,
                 command_json = ?5,
                 protected_zone_ids_json = ?6,
                 status = ?7,
                 exit_code = ?8,
                 started_at = ?9,
                 ended_at = ?10,
                 root_pid = ?11,
                 cgroup_path = ?12,
                 cgroup_status = ?13,
                 cgroup_message = ?14,
                 landlock_status = ?15,
                 landlock_message = ?16,
                 snapshot_status = ?17,
                 snapshot_backend = ?18,
                 snapshot_id = ?19,
                 snapshot_root = ?20,
                 snapshot_message = ?21,
                 degraded_reasons_json = ?22,
                 dependency_file_changes_json = ?23
             WHERE id = ?1",
            params![
                session.id,
                session.agent_id,
                session.agent_label,
                session.agent_profile,
                encode_strings(&session.command)?,
                encode_strings(&session.protected_zone_ids)?,
                session_status_to_str(session.status),
                session.exit_code.map(i64::from),
                encode_time(session.started_at),
                encode_optional_time(session.ended_at),
                session.root_pid.map(|pid| pid as i64),
                session
                    .cgroup_path
                    .as_ref()
                    .map(|path| path_to_string(path)),
                cgroup_status,
                cgroup_message,
                landlock_status,
                landlock_message,
                snapshot_status,
                snapshot_backend,
                snapshot_id,
                snapshot_root,
                snapshot_message,
                encode_strings(&session.degraded_reasons)?,
                encode_dependency_file_changes(&session.dependency_file_changes)?,
            ],
        )?;
        if changed == 0 {
            return Err(DbError::MissingSession(session.id.clone()));
        }
        self.append_session_integrity_event("update", session)?;
        Ok(())
    }

    pub fn get_session(&self, id: &str) -> DbResult<Option<SessionRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, agent_id, agent_label, agent_profile, command_json, protected_zone_ids_json, status,
                    exit_code, started_at, ended_at, root_pid, cgroup_path, cgroup_status, cgroup_message,
                    landlock_status, landlock_message, snapshot_status, snapshot_backend, snapshot_id, snapshot_root, snapshot_message,
                    degraded_reasons_json, dependency_file_changes_json
             FROM sessions
             WHERE id = ?1",
        )?;
        let mut rows = statement.query([id])?;
        rows.next()?.map(read_session).transpose()
    }

    pub fn list_sessions(&self) -> DbResult<Vec<SessionRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT id, agent_id, agent_label, agent_profile, command_json, protected_zone_ids_json, status,
                    exit_code, started_at, ended_at, root_pid, cgroup_path, cgroup_status, cgroup_message,
                    landlock_status, landlock_message, snapshot_status, snapshot_backend, snapshot_id, snapshot_root, snapshot_message,
                    degraded_reasons_json, dependency_file_changes_json
             FROM sessions
             ORDER BY started_at, id",
        )?;
        let mut rows = statement.query([])?;
        let mut sessions = Vec::new();
        while let Some(row) = rows.next()? {
            sessions.push(read_session(row)?);
        }
        Ok(sessions)
    }

    pub fn verify_receipt_integrity(&self) -> DbResult<ReceiptIntegrityReport> {
        let sessions = self.list_sessions()?;
        let mut rows = self.session_integrity_entries()?;
        rows.sort_by_key(|row| row.id);

        let mut issues = Vec::new();
        let mut previous_hash = genesis_integrity_hash();
        let mut latest_payload_by_session = std::collections::BTreeMap::<String, String>::new();
        let session_ids = sessions
            .iter()
            .map(|session| session.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for row in &rows {
            if !session_ids.contains(&row.session_id) {
                issues.push(ReceiptIntegrityIssue {
                    session_id: Some(row.session_id.clone()),
                    message: "integrity log references a missing session record".to_string(),
                });
            }
            if row.previous_hash != previous_hash {
                issues.push(ReceiptIntegrityIssue {
                    session_id: Some(row.session_id.clone()),
                    message: format!(
                        "integrity entry {} has previous hash {}, expected {}",
                        row.id, row.previous_hash, previous_hash
                    ),
                });
            }
            let expected_entry_hash = integrity_entry_hash(
                &row.previous_hash,
                &row.session_id,
                &row.event_kind,
                &row.payload_hash,
                row.created_at,
            );
            if row.entry_hash != expected_entry_hash {
                issues.push(ReceiptIntegrityIssue {
                    session_id: Some(row.session_id.clone()),
                    message: format!("integrity entry {} hash does not match its payload", row.id),
                });
            }
            previous_hash = row.entry_hash.clone();
            latest_payload_by_session.insert(row.session_id.clone(), row.payload_hash.clone());
        }

        for session in &sessions {
            let payload_hash = session_payload_hash(session)?;
            match latest_payload_by_session.get(&session.id) {
                Some(logged_hash) if *logged_hash == payload_hash => {}
                Some(_) => issues.push(ReceiptIntegrityIssue {
                    session_id: Some(session.id.clone()),
                    message: "current session record does not match latest integrity log entry"
                        .to_string(),
                }),
                None => issues.push(ReceiptIntegrityIssue {
                    session_id: Some(session.id.clone()),
                    message: "session has no integrity log entry".to_string(),
                }),
            }
        }

        Ok(ReceiptIntegrityReport {
            verified_sessions: sessions.len(),
            log_entries: rows.len(),
            issues,
        })
    }

    pub fn create_policy_rule(&self, rule: &PolicyRule) -> DbResult<()> {
        let file_globs = serde_json::to_string(&rule.file_globs)?;
        self.conn.execute(
            "INSERT INTO policy_rules (
                id, protected_zone_id, agent_id, capability, effect, path_scope,
                file_globs_json, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rule.id,
                rule.protected_zone_id,
                rule.agent_id,
                capability_to_str(rule.capability),
                policy_effect_to_str(rule.effect),
                rule.path_scope.as_ref().map(|path| path_to_string(path)),
                file_globs,
                encode_optional_time(rule.expires_at)
            ],
        )?;
        Ok(())
    }

    pub fn list_policy_rules(&self, protected_zone_id: &str) -> DbResult<Vec<PolicyRule>> {
        let mut statement = self.conn.prepare(
            "SELECT id, protected_zone_id, agent_id, capability, effect, path_scope,
                    file_globs_json, expires_at
             FROM policy_rules
             WHERE protected_zone_id = ?1
             ORDER BY id",
        )?;
        let mut rows = statement.query([protected_zone_id])?;
        let mut rules = Vec::new();
        while let Some(row) = rows.next()? {
            rules.push(read_policy_rule(row)?);
        }
        Ok(rules)
    }

    pub fn insert_audit_event(&self, event: &AuditEvent) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO audit_events (
                id, timestamp, actor_type, actor_id, protected_zone_id, action, target,
                decision, metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.id,
                encode_time(event.timestamp),
                actor_type_to_str(event.actor_type),
                event.actor_id,
                event.protected_zone_id,
                event.action,
                event.target,
                audit_decision_to_str(event.decision),
                event.metadata_json
            ],
        )?;
        Ok(())
    }

    pub fn list_audit_events(&self) -> DbResult<Vec<AuditEvent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, timestamp, actor_type, actor_id, protected_zone_id, action, target,
                    decision, metadata_json
             FROM audit_events
             ORDER BY timestamp, id",
        )?;
        let mut rows = statement.query([])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(read_audit_event(row)?);
        }
        Ok(events)
    }

    pub fn list_audit_events_for_protected_zone(
        &self,
        protected_zone_id: &str,
    ) -> DbResult<Vec<AuditEvent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, timestamp, actor_type, actor_id, protected_zone_id, action, target,
                    decision, metadata_json
             FROM audit_events
             WHERE protected_zone_id = ?1
             ORDER BY timestamp, id",
        )?;
        let mut rows = statement.query([protected_zone_id])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(read_audit_event(row)?);
        }
        Ok(events)
    }

    pub fn insert_file_journal_event(&self, event: &FileJournalEvent) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO file_journal_events (
                session_id, timestamp, process_id, protected_zone_id, path, operation,
                decision, source, confidence, attribution, message
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.session_id,
                encode_time(event.timestamp),
                event.process_id.map(|pid| pid as i64),
                event.protected_zone_id,
                path_to_string(&event.path),
                file_operation_to_str(event.operation),
                file_decision_to_str(event.decision),
                journal_source_to_str(event.source),
                journal_confidence_to_str(event.confidence),
                journal_attribution_to_str(event.attribution),
                event.message
            ],
        )?;
        Ok(())
    }

    pub fn insert_file_journal_events(&self, events: &[FileJournalEvent]) -> DbResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let transaction = self.conn.unchecked_transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO file_journal_events (
                    session_id, timestamp, process_id, protected_zone_id, path, operation,
                    decision, source, confidence, attribution, message
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for event in events {
                statement.execute(params![
                    event.session_id,
                    encode_time(event.timestamp),
                    event.process_id.map(|pid| pid as i64),
                    event.protected_zone_id,
                    path_to_string(&event.path),
                    file_operation_to_str(event.operation),
                    file_decision_to_str(event.decision),
                    journal_source_to_str(event.source),
                    journal_confidence_to_str(event.confidence),
                    journal_attribution_to_str(event.attribution),
                    event.message
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn list_file_journal_events(
        &self,
        session_id: Option<&str>,
    ) -> DbResult<Vec<FileJournalEvent>> {
        let (sql, filter): (&str, Option<&str>) = match session_id {
            Some(session_id) => (
                "SELECT session_id, timestamp, process_id, protected_zone_id, path, operation,
                        decision, source, confidence, attribution, message
                 FROM file_journal_events
                 WHERE session_id = ?1
                 ORDER BY timestamp, id",
                Some(session_id),
            ),
            None => (
                "SELECT session_id, timestamp, process_id, protected_zone_id, path, operation,
                        decision, source, confidence, attribution, message
                 FROM file_journal_events
                 ORDER BY timestamp, id",
                None,
            ),
        };
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = match filter {
            Some(session_id) => statement.query([session_id])?,
            None => statement.query([])?,
        };
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(read_file_journal_event(row)?);
        }
        Ok(events)
    }

    pub fn insert_network_journal_event(&self, event: &NetworkJournalEvent) -> DbResult<()> {
        self.conn.execute(
            "INSERT INTO network_journal_events (
                session_id, timestamp, process_id, destination, destination_port, protocol,
                decision, source, confidence, attribution, message
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.session_id,
                encode_time(event.timestamp),
                event.process_id.map(|pid| pid as i64),
                event.destination,
                event.destination_port.map(|port| port as i64),
                network_protocol_to_str(&event.protocol),
                network_decision_to_str(event.decision),
                journal_source_to_str(event.source),
                journal_confidence_to_str(event.confidence),
                journal_attribution_to_str(event.attribution),
                event.message
            ],
        )?;
        Ok(())
    }

    pub fn insert_network_journal_events(&self, events: &[NetworkJournalEvent]) -> DbResult<()> {
        if events.is_empty() {
            return Ok(());
        }
        let transaction = self.conn.unchecked_transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO network_journal_events (
                    session_id, timestamp, process_id, destination, destination_port, protocol,
                    decision, source, confidence, attribution, message
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for event in events {
                statement.execute(params![
                    event.session_id,
                    encode_time(event.timestamp),
                    event.process_id.map(|pid| pid as i64),
                    event.destination,
                    event.destination_port.map(|port| port as i64),
                    network_protocol_to_str(&event.protocol),
                    network_decision_to_str(event.decision),
                    journal_source_to_str(event.source),
                    journal_confidence_to_str(event.confidence),
                    journal_attribution_to_str(event.attribution),
                    event.message
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn list_network_journal_events(
        &self,
        session_id: Option<&str>,
    ) -> DbResult<Vec<NetworkJournalEvent>> {
        let (sql, filter): (&str, Option<&str>) = match session_id {
            Some(session_id) => (
                "SELECT session_id, timestamp, process_id, destination, destination_port,
                        protocol, decision, source, confidence, attribution, message
                 FROM network_journal_events
                 WHERE session_id = ?1
                 ORDER BY timestamp, id",
                Some(session_id),
            ),
            None => (
                "SELECT session_id, timestamp, process_id, destination, destination_port,
                        protocol, decision, source, confidence, attribution, message
                 FROM network_journal_events
                 ORDER BY timestamp, id",
                None,
            ),
        };
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = match filter {
            Some(session_id) => statement.query([session_id])?,
            None => statement.query([])?,
        };
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(read_network_journal_event(row)?);
        }
        Ok(events)
    }
}

fn prepare_db_path(path: &Path) -> DbResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            set_private_dir_permissions(parent)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> DbResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> DbResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_db_file_permissions(path: &Path) -> DbResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_db_file_permissions(_path: &Path) -> DbResult<()> {
    Ok(())
}

fn validate_migration_column(
    table_name: &str,
    column_name: &str,
    column_type: &str,
) -> DbResult<()> {
    let allowed = matches!(
        (table_name, column_name, column_type),
        ("sessions", "agent_profile", "TEXT")
            | (
                "sessions",
                "dependency_file_changes_json",
                "TEXT NOT NULL DEFAULT '[]'"
            )
            | ("sessions", "exit_code", "INTEGER")
            | ("sessions", "snapshot_root", "TEXT")
            | (
                "file_journal_events",
                "attribution",
                "TEXT NOT NULL DEFAULT 'unknown'"
            )
    );
    if allowed {
        Ok(())
    } else {
        Err(DbError::InvalidValue {
            field: "migration_column",
            value: format!("{table_name}.{column_name} {column_type}"),
        })
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

pub const MIGRATIONS: &str = include_str!("../migrations/0001_initial.sql");

fn read_protected_zone(row: &rusqlite::Row<'_>) -> DbResult<ProtectedZone> {
    let root_paths_json: String = row.get(3)?;
    Ok(ProtectedZone {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        root_paths: decode_paths(&root_paths_json)?,
        created_at: decode_time(row.get(4)?)?,
        updated_at: decode_time(row.get(5)?)?,
    })
}

fn read_agent(row: &rusqlite::Row<'_>) -> DbResult<AgentIdentity> {
    let kind: String = row.get(2)?;
    Ok(AgentIdentity {
        id: row.get(0)?,
        name: row.get(1)?,
        kind: parse_agent_kind(&kind)?,
        token_hash: row.get(3)?,
        created_at: decode_time(row.get(4)?)?,
        expires_at: decode_optional_time(row.get(5)?)?,
        disabled: row.get(6)?,
    })
}

fn read_session(row: &rusqlite::Row<'_>) -> DbResult<SessionRecord> {
    let status: String = row.get(6)?;
    let exit_code: Option<i64> = row.get(7)?;
    let root_pid: Option<i64> = row.get(10)?;
    let cgroup_path: Option<String> = row.get(11)?;
    let cgroup_status: String = row.get(12)?;
    let cgroup_message: Option<String> = row.get(13)?;
    let landlock_status: String = row.get(14)?;
    let landlock_message: Option<String> = row.get(15)?;
    let snapshot_status: String = row.get(16)?;
    let snapshot_backend: Option<String> = row.get(17)?;
    let snapshot_id: Option<String> = row.get(18)?;
    let snapshot_root: Option<String> = row.get(19)?;
    let snapshot_message: Option<String> = row.get(20)?;
    let dependency_file_changes_json: String = row.get(22)?;
    Ok(SessionRecord {
        id: row.get(0)?,
        agent_id: row.get(1)?,
        agent_label: row.get(2)?,
        agent_profile: row.get(3)?,
        command: decode_strings(&row.get::<_, String>(4)?)?,
        protected_zone_ids: decode_strings(&row.get::<_, String>(5)?)?,
        status: parse_session_status(&status)?,
        exit_code: exit_code.map(|code| code as i32),
        started_at: decode_time(row.get(8)?)?,
        ended_at: decode_optional_time(row.get(9)?)?,
        root_pid: root_pid.map(|pid| pid as u32),
        cgroup_path: cgroup_path.map(PathBuf::from),
        cgroup_status: parse_cgroup_status(&cgroup_status, cgroup_message)?,
        landlock_status: parse_landlock_status(&landlock_status, landlock_message)?,
        snapshot_status: parse_snapshot_status(
            &snapshot_status,
            snapshot_backend,
            snapshot_id,
            snapshot_root,
            snapshot_message,
        )?,
        degraded_reasons: decode_strings(&row.get::<_, String>(21)?)?,
        dependency_file_changes: decode_dependency_file_changes(&dependency_file_changes_json)?,
    })
}

fn encode_strings(values: &[String]) -> DbResult<String> {
    Ok(serde_json::to_string(values)?)
}

fn decode_strings(json: &str) -> DbResult<Vec<String>> {
    Ok(serde_json::from_str(json)?)
}

#[derive(Serialize, Deserialize)]
struct StoredDependencyFileChange {
    path: String,
    before_hash: Option<String>,
    after_hash: Option<String>,
    status: String,
}

fn encode_dependency_file_changes(values: &[DependencyFileChange]) -> DbResult<String> {
    let stored = values
        .iter()
        .map(|change| StoredDependencyFileChange {
            path: path_to_string(&change.path),
            before_hash: change.before_hash.clone(),
            after_hash: change.after_hash.clone(),
            status: dependency_file_change_status_to_str(change.status).to_string(),
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_string(&stored)?)
}

fn decode_dependency_file_changes(json: &str) -> DbResult<Vec<DependencyFileChange>> {
    let stored = serde_json::from_str::<Vec<StoredDependencyFileChange>>(json)?;
    stored
        .into_iter()
        .map(|change| {
            Ok(DependencyFileChange {
                path: PathBuf::from(change.path),
                before_hash: change.before_hash,
                after_hash: change.after_hash,
                status: parse_dependency_file_change_status(&change.status)?,
            })
        })
        .collect()
}

fn read_policy_rule(row: &rusqlite::Row<'_>) -> DbResult<PolicyRule> {
    let capability: String = row.get(3)?;
    let effect: String = row.get(4)?;
    let path_scope: Option<String> = row.get(5)?;
    let file_globs_json: String = row.get(6)?;
    Ok(PolicyRule {
        id: row.get(0)?,
        protected_zone_id: row.get(1)?,
        agent_id: row.get(2)?,
        capability: parse_capability(&capability)?,
        effect: parse_policy_effect(&effect)?,
        path_scope: path_scope.map(PathBuf::from),
        file_globs: serde_json::from_str(&file_globs_json)?,
        expires_at: decode_optional_time(row.get(7)?)?,
    })
}

fn read_file_journal_event(row: &rusqlite::Row<'_>) -> DbResult<FileJournalEvent> {
    let process_id: Option<i64> = row.get(2)?;
    let operation: String = row.get(5)?;
    let decision: String = row.get(6)?;
    let source: String = row.get(7)?;
    let confidence: String = row.get(8)?;
    let attribution: String = row.get(9)?;
    Ok(FileJournalEvent {
        session_id: row.get(0)?,
        timestamp: decode_time(row.get(1)?)?,
        process_id: process_id.map(|pid| pid as u32),
        protected_zone_id: row.get(3)?,
        path: PathBuf::from(row.get::<_, String>(4)?),
        operation: parse_file_operation(&operation)?,
        decision: parse_file_decision(&decision)?,
        source: parse_journal_source(&source)?,
        confidence: parse_journal_confidence(&confidence)?,
        attribution: parse_journal_attribution(&attribution)?,
        message: row.get(10)?,
    })
}

fn read_network_journal_event(row: &rusqlite::Row<'_>) -> DbResult<NetworkJournalEvent> {
    let process_id: Option<i64> = row.get(2)?;
    let destination_port: Option<i64> = row.get(4)?;
    let protocol: String = row.get(5)?;
    let decision: String = row.get(6)?;
    let source: String = row.get(7)?;
    let confidence: String = row.get(8)?;
    let attribution: String = row.get(9)?;
    Ok(NetworkJournalEvent {
        session_id: row.get(0)?,
        timestamp: decode_time(row.get(1)?)?,
        process_id: process_id.map(|pid| pid as u32),
        destination: row.get(3)?,
        destination_port: destination_port.map(|port| port as u16),
        protocol: parse_network_protocol(&protocol),
        decision: parse_network_decision(&decision)?,
        source: parse_journal_source(&source)?,
        confidence: parse_journal_confidence(&confidence)?,
        attribution: parse_journal_attribution(&attribution)?,
        message: row.get(10)?,
    })
}

fn read_audit_event(row: &rusqlite::Row<'_>) -> DbResult<AuditEvent> {
    let actor_type: String = row.get(2)?;
    let decision: String = row.get(7)?;
    Ok(AuditEvent {
        id: row.get(0)?,
        timestamp: decode_time(row.get(1)?)?,
        actor_type: parse_actor_type(&actor_type)?,
        actor_id: row.get(3)?,
        protected_zone_id: row.get(4)?,
        action: row.get(5)?,
        target: row.get(6)?,
        decision: parse_audit_decision(&decision)?,
        metadata_json: row.get(8)?,
    })
}

fn encode_paths(paths: &[PathBuf]) -> DbResult<String> {
    let strings = paths
        .iter()
        .map(|path| path_to_string(path))
        .collect::<Vec<_>>();
    Ok(serde_json::to_string(&strings)?)
}

fn decode_paths(json: &str) -> DbResult<Vec<PathBuf>> {
    let strings: Vec<String> = serde_json::from_str(json)?;
    Ok(strings.into_iter().map(PathBuf::from).collect())
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn encode_time(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn encode_optional_time(time: Option<SystemTime>) -> Option<i64> {
    time.map(encode_time)
}

fn session_payload_hash(session: &SessionRecord) -> DbResult<String> {
    let (cgroup_status, cgroup_message) = encode_cgroup_status(&session.cgroup_status);
    let (landlock_status, landlock_message) = encode_landlock_status(&session.landlock_status);
    let (snapshot_status, snapshot_backend, snapshot_id, snapshot_root, snapshot_message) =
        encode_snapshot_status(&session.snapshot_status);
    let dependency_file_changes = session
        .dependency_file_changes
        .iter()
        .map(|change| {
            serde_json::json!({
                "path": path_to_string(&change.path),
                "before_hash": change.before_hash,
                "after_hash": change.after_hash,
                "status": dependency_file_change_status_to_str(change.status),
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "version": 1,
        "id": session.id,
        "agent_id": session.agent_id,
        "agent_label": session.agent_label,
        "agent_profile": session.agent_profile,
        "command": session.command,
        "protected_zone_ids": session.protected_zone_ids,
        "status": session_status_to_str(session.status),
        "exit_code": session.exit_code,
        "started_at": encode_time(session.started_at),
        "ended_at": encode_optional_time(session.ended_at),
        "root_pid": session.root_pid,
        "cgroup_path": session.cgroup_path.as_ref().map(|path| path_to_string(path)),
        "cgroup_status": cgroup_status,
        "cgroup_message": cgroup_message,
        "landlock_status": landlock_status,
        "landlock_message": landlock_message,
        "snapshot_status": snapshot_status,
        "snapshot_backend": snapshot_backend,
        "snapshot_id": snapshot_id,
        "snapshot_root": snapshot_root,
        "snapshot_message": snapshot_message,
        "degraded_reasons": session.degraded_reasons,
        "dependency_file_changes": dependency_file_changes,
    });
    Ok(hash_hex(&serde_json::to_vec(&payload)?))
}

fn genesis_integrity_hash() -> String {
    hash_hex(b"warder-session-integrity-v1")
}

fn integrity_entry_hash(
    previous_hash: &str,
    session_id: &str,
    event_kind: &str,
    payload_hash: &str,
    created_at: i64,
) -> String {
    hash_hex(
        format!("{previous_hash}\n{session_id}\n{event_kind}\n{payload_hash}\n{created_at}")
            .as_bytes(),
    )
}

fn hash_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(hex_nibble(byte >> 4));
        hex.push(hex_nibble(byte));
    }
    hex
}

fn hex_nibble(value: u8) -> char {
    match value & 0x0f {
        0..=9 => (b'0' + (value & 0x0f)) as char,
        value => (b'a' + (value - 10)) as char,
    }
}

fn decode_time(seconds: i64) -> DbResult<SystemTime> {
    if seconds < 0 {
        return Err(DbError::InvalidTimestamp(seconds));
    }
    Ok(UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

fn decode_optional_time(seconds: Option<i64>) -> DbResult<Option<SystemTime>> {
    seconds.map(decode_time).transpose()
}

fn agent_kind_to_str(value: &AgentKind) -> &'static str {
    match value {
        AgentKind::OpenClaw => "openclaw",
        AgentKind::GenericCli => "generic_cli",
        AgentKind::LocalScript => "local_script",
        AgentKind::Unknown => "unknown",
    }
}

fn parse_agent_kind(value: &str) -> DbResult<AgentKind> {
    match value {
        "openclaw" => Ok(AgentKind::OpenClaw),
        "generic_cli" => Ok(AgentKind::GenericCli),
        "local_script" => Ok(AgentKind::LocalScript),
        "unknown" => Ok(AgentKind::Unknown),
        _ => invalid("agent.kind", value),
    }
}

fn session_status_to_str(value: SessionStatus) -> &'static str {
    match value {
        SessionStatus::Recorded => "recorded",
        SessionStatus::Starting => "starting",
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Failed => "failed",
        SessionStatus::Reverted => "reverted",
    }
}

fn parse_session_status(value: &str) -> DbResult<SessionStatus> {
    match value {
        "recorded" => Ok(SessionStatus::Recorded),
        "starting" => Ok(SessionStatus::Starting),
        "running" => Ok(SessionStatus::Running),
        "completed" => Ok(SessionStatus::Completed),
        "failed" => Ok(SessionStatus::Failed),
        "reverted" => Ok(SessionStatus::Reverted),
        _ => invalid("session.status", value),
    }
}

fn encode_cgroup_status(value: &CgroupStatus) -> (&'static str, Option<String>) {
    match value {
        CgroupStatus::NotRequested => ("not-requested", None),
        CgroupStatus::Pending => ("pending", None),
        CgroupStatus::Tagged => ("tagged", None),
        CgroupStatus::Degraded(message) => ("degraded", Some(message.clone())),
        CgroupStatus::Unsupported(message) => ("unsupported", Some(message.clone())),
    }
}

fn parse_cgroup_status(value: &str, message: Option<String>) -> DbResult<CgroupStatus> {
    match value {
        "not-requested" => Ok(CgroupStatus::NotRequested),
        "pending" => Ok(CgroupStatus::Pending),
        "tagged" => Ok(CgroupStatus::Tagged),
        "degraded" => Ok(CgroupStatus::Degraded(message.unwrap_or_default())),
        "unsupported" => Ok(CgroupStatus::Unsupported(message.unwrap_or_default())),
        _ => invalid("session.cgroup_status", value),
    }
}

fn encode_landlock_status(value: &LandlockStatus) -> (&'static str, Option<String>) {
    match value {
        LandlockStatus::NotRequested => ("not_requested", None),
        LandlockStatus::Pending => ("pending", None),
        LandlockStatus::Applied => ("applied", None),
        LandlockStatus::Degraded(message) => ("degraded", Some(message.clone())),
        LandlockStatus::Unsupported(message) => ("unsupported", Some(message.clone())),
    }
}

fn parse_landlock_status(value: &str, message: Option<String>) -> DbResult<LandlockStatus> {
    match value {
        "not_requested" => Ok(LandlockStatus::NotRequested),
        "pending" => Ok(LandlockStatus::Pending),
        "applied" => Ok(LandlockStatus::Applied),
        "degraded" => Ok(LandlockStatus::Degraded(message.unwrap_or_default())),
        "unsupported" => Ok(LandlockStatus::Unsupported(message.unwrap_or_default())),
        _ => invalid("session.landlock_status", value),
    }
}

fn encode_snapshot_status(
    value: &SnapshotStatus,
) -> (
    &'static str,
    Option<&'static str>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    match value {
        SnapshotStatus::NotRequested => ("not_requested", None, None, None, None),
        SnapshotStatus::Pending => ("pending", None, None, None, None),
        SnapshotStatus::Created {
            backend,
            snapshot_id,
            snapshot_root,
        } => (
            "created",
            Some(snapshot_backend_to_str(*backend)),
            Some(snapshot_id.clone()),
            snapshot_root.as_ref().map(|path| path_to_string(path)),
            None,
        ),
        SnapshotStatus::Failed(message) => ("failed", None, None, None, Some(message.clone())),
        SnapshotStatus::Reverted {
            backend,
            snapshot_id,
            snapshot_root,
        } => (
            "reverted",
            Some(snapshot_backend_to_str(*backend)),
            Some(snapshot_id.clone()),
            snapshot_root.as_ref().map(|path| path_to_string(path)),
            None,
        ),
    }
}

fn parse_snapshot_status(
    value: &str,
    backend: Option<String>,
    snapshot_id: Option<String>,
    snapshot_root: Option<String>,
    message: Option<String>,
) -> DbResult<SnapshotStatus> {
    match value {
        "not_requested" => Ok(SnapshotStatus::NotRequested),
        "pending" => Ok(SnapshotStatus::Pending),
        "created" => Ok(SnapshotStatus::Created {
            backend: parse_required_snapshot_backend(backend)?,
            snapshot_id: snapshot_id.unwrap_or_default(),
            snapshot_root: snapshot_root.map(PathBuf::from),
        }),
        "failed" => Ok(SnapshotStatus::Failed(message.unwrap_or_default())),
        "reverted" => Ok(SnapshotStatus::Reverted {
            backend: parse_required_snapshot_backend(backend)?,
            snapshot_id: snapshot_id.unwrap_or_default(),
            snapshot_root: snapshot_root.map(PathBuf::from),
        }),
        _ => invalid("session.snapshot_status", value),
    }
}

fn snapshot_backend_to_str(value: SnapshotBackend) -> &'static str {
    match value {
        SnapshotBackend::Btrfs => "btrfs",
        SnapshotBackend::OverlayFs => "overlayfs",
    }
}

fn parse_required_snapshot_backend(value: Option<String>) -> DbResult<SnapshotBackend> {
    match value.as_deref() {
        Some("btrfs") => Ok(SnapshotBackend::Btrfs),
        Some("overlayfs") => Ok(SnapshotBackend::OverlayFs),
        Some(other) => invalid("session.snapshot_backend", other),
        None => invalid("session.snapshot_backend", ""),
    }
}

fn dependency_file_change_status_to_str(value: DependencyFileChangeStatus) -> &'static str {
    match value {
        DependencyFileChangeStatus::Created => "created",
        DependencyFileChangeStatus::Modified => "modified",
        DependencyFileChangeStatus::Removed => "removed",
    }
}

fn parse_dependency_file_change_status(value: &str) -> DbResult<DependencyFileChangeStatus> {
    match value {
        "created" => Ok(DependencyFileChangeStatus::Created),
        "modified" => Ok(DependencyFileChangeStatus::Modified),
        "removed" => Ok(DependencyFileChangeStatus::Removed),
        _ => invalid("dependency_file_change_status", value),
    }
}

fn capability_to_str(value: Capability) -> &'static str {
    match value {
        Capability::ReadFile => "read_file",
        Capability::WriteFile => "write_file",
        Capability::MoveFile => "move_file",
        Capability::DeleteFile => "delete_file",
        Capability::RunShellCommand => "run_shell_command",
    }
}

fn parse_capability(value: &str) -> DbResult<Capability> {
    match value {
        "read_file" => Ok(Capability::ReadFile),
        "write_file" => Ok(Capability::WriteFile),
        "move_file" => Ok(Capability::MoveFile),
        "delete_file" => Ok(Capability::DeleteFile),
        "run_shell_command" => Ok(Capability::RunShellCommand),
        _ => invalid("capability", value),
    }
}

fn policy_effect_to_str(value: PolicyEffect) -> &'static str {
    match value {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::Ask => "ask",
    }
}

fn parse_policy_effect(value: &str) -> DbResult<PolicyEffect> {
    match value {
        "allow" => Ok(PolicyEffect::Allow),
        "deny" => Ok(PolicyEffect::Deny),
        "ask" => Ok(PolicyEffect::Ask),
        _ => invalid("policy.effect", value),
    }
}

fn actor_type_to_str(value: ActorType) -> &'static str {
    match value {
        ActorType::User => "user",
        ActorType::Agent => "agent",
        ActorType::System => "system",
    }
}

fn parse_actor_type(value: &str) -> DbResult<ActorType> {
    match value {
        "user" => Ok(ActorType::User),
        "agent" => Ok(ActorType::Agent),
        "system" => Ok(ActorType::System),
        _ => invalid("actor_type", value),
    }
}

fn audit_decision_to_str(value: AuditDecision) -> &'static str {
    match value {
        AuditDecision::Allowed => "allowed",
        AuditDecision::Denied => "denied",
        AuditDecision::Requested => "requested",
        AuditDecision::Approved => "approved",
        AuditDecision::Failed => "failed",
    }
}

fn parse_audit_decision(value: &str) -> DbResult<AuditDecision> {
    match value {
        "allowed" => Ok(AuditDecision::Allowed),
        "denied" => Ok(AuditDecision::Denied),
        "requested" => Ok(AuditDecision::Requested),
        "approved" => Ok(AuditDecision::Approved),
        "failed" => Ok(AuditDecision::Failed),
        _ => invalid("audit.decision", value),
    }
}

fn file_operation_to_str(value: FileOperation) -> &'static str {
    match value {
        FileOperation::Read => "read",
        FileOperation::Write => "write",
        FileOperation::Create => "create",
        FileOperation::Delete => "delete",
        FileOperation::Rename => "rename",
    }
}

fn parse_file_operation(value: &str) -> DbResult<FileOperation> {
    match value {
        "read" => Ok(FileOperation::Read),
        "write" => Ok(FileOperation::Write),
        "create" => Ok(FileOperation::Create),
        "delete" => Ok(FileOperation::Delete),
        "rename" => Ok(FileOperation::Rename),
        _ => invalid("file_journal.operation", value),
    }
}

fn file_decision_to_str(value: FileDecision) -> &'static str {
    match value {
        FileDecision::Allowed => "allowed",
        FileDecision::Denied => "denied",
        FileDecision::Observed => "observed",
        FileDecision::Unknown => "unknown",
    }
}

fn parse_file_decision(value: &str) -> DbResult<FileDecision> {
    match value {
        "allowed" => Ok(FileDecision::Allowed),
        "denied" => Ok(FileDecision::Denied),
        "observed" => Ok(FileDecision::Observed),
        "unknown" => Ok(FileDecision::Unknown),
        _ => invalid("file_journal.decision", value),
    }
}

fn network_decision_to_str(value: NetworkDecision) -> &'static str {
    match value {
        NetworkDecision::Allowed => "allowed",
        NetworkDecision::Denied => "denied",
        NetworkDecision::Observed => "observed",
        NetworkDecision::Unknown => "unknown",
    }
}

fn parse_network_decision(value: &str) -> DbResult<NetworkDecision> {
    match value {
        "allowed" => Ok(NetworkDecision::Allowed),
        "denied" => Ok(NetworkDecision::Denied),
        "observed" => Ok(NetworkDecision::Observed),
        "unknown" => Ok(NetworkDecision::Unknown),
        _ => invalid("network_journal.decision", value),
    }
}

fn network_protocol_to_str(value: &NetworkProtocol) -> String {
    match value {
        NetworkProtocol::Tcp => "tcp".to_string(),
        NetworkProtocol::Udp => "udp".to_string(),
        NetworkProtocol::Icmp => "icmp".to_string(),
        NetworkProtocol::Other(value) => value.clone(),
    }
}

fn parse_network_protocol(value: &str) -> NetworkProtocol {
    match value {
        "tcp" => NetworkProtocol::Tcp,
        "udp" => NetworkProtocol::Udp,
        "icmp" => NetworkProtocol::Icmp,
        other => NetworkProtocol::Other(other.to_string()),
    }
}

fn journal_source_to_str(value: JournalSource) -> &'static str {
    match value {
        JournalSource::Landlock => "landlock",
        JournalSource::Inotify => "inotify",
        JournalSource::Ebpf => "ebpf",
        JournalSource::Procfs => "procfs",
        JournalSource::Cgroup => "cgroup",
        JournalSource::Snapshot => "snapshot",
        JournalSource::Manual => "manual",
    }
}

fn parse_journal_source(value: &str) -> DbResult<JournalSource> {
    match value {
        "landlock" => Ok(JournalSource::Landlock),
        "inotify" => Ok(JournalSource::Inotify),
        "ebpf" => Ok(JournalSource::Ebpf),
        "procfs" => Ok(JournalSource::Procfs),
        "cgroup" => Ok(JournalSource::Cgroup),
        "snapshot" => Ok(JournalSource::Snapshot),
        "manual" => Ok(JournalSource::Manual),
        _ => invalid("file_journal.source", value),
    }
}

fn journal_confidence_to_str(value: JournalConfidence) -> &'static str {
    match value {
        JournalConfidence::Enforced => "enforced",
        JournalConfidence::Observed => "observed",
        JournalConfidence::Degraded => "degraded",
    }
}

fn parse_journal_confidence(value: &str) -> DbResult<JournalConfidence> {
    match value {
        "enforced" => Ok(JournalConfidence::Enforced),
        "observed" => Ok(JournalConfidence::Observed),
        "degraded" => Ok(JournalConfidence::Degraded),
        _ => invalid("file_journal.confidence", value),
    }
}

fn journal_attribution_to_str(value: JournalAttribution) -> &'static str {
    match value {
        JournalAttribution::DirectProcess => "direct-process",
        JournalAttribution::SessionWindow => "session-window",
        JournalAttribution::PolicyEnforcement => "policy-enforcement",
        JournalAttribution::Unknown => "unknown",
    }
}

fn parse_journal_attribution(value: &str) -> DbResult<JournalAttribution> {
    match value {
        "direct-process" => Ok(JournalAttribution::DirectProcess),
        "session-window" => Ok(JournalAttribution::SessionWindow),
        "policy-enforcement" => Ok(JournalAttribution::PolicyEnforcement),
        "unknown" => Ok(JournalAttribution::Unknown),
        _ => invalid("file_journal.attribution", value),
    }
}

fn invalid<T>(field: &'static str, value: &str) -> DbResult<T> {
    Err(DbError::InvalidValue {
        field,
        value: value.to_string(),
    })
}

#[cfg(test)]
mod tests;
