use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedZone {
    pub id: String,
    pub name: String,
    pub description: String,
    pub root_paths: Vec<PathBuf>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentIdentity {
    pub id: String,
    pub name: String,
    pub kind: AgentKind,
    pub token_hash: String,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub disabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentKind {
    OpenClaw,
    GenericCli,
    LocalScript,
    Unknown,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    ReadFile,
    WriteFile,
    MoveFile,
    DeleteFile,
    RunShellCommand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub protected_zone_id: String,
    pub agent_id: String,
    pub capability: Capability,
    pub effect: PolicyEffect,
    pub path_scope: Option<PathBuf>,
    pub file_globs: Vec<String>,
    pub expires_at: Option<SystemTime>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Deny,
    Ask,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: SystemTime,
    pub actor_type: ActorType,
    pub actor_id: String,
    pub protected_zone_id: String,
    pub action: String,
    pub target: String,
    pub decision: AuditDecision,
    pub metadata_json: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ActorType {
    User,
    Agent,
    System,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuditDecision {
    Allowed,
    Denied,
    Requested,
    Approved,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: String,
    pub agent_id: String,
    pub agent_label: String,
    pub agent_profile: Option<String>,
    pub command: Vec<String>,
    pub protected_zone_ids: Vec<String>,
    pub status: SessionStatus,
    pub exit_code: Option<i32>,
    pub started_at: SystemTime,
    pub ended_at: Option<SystemTime>,
    pub root_pid: Option<u32>,
    pub cgroup_path: Option<PathBuf>,
    pub cgroup_status: CgroupStatus,
    pub landlock_status: LandlockStatus,
    pub snapshot_status: SnapshotStatus,
    pub dependency_file_changes: Vec<DependencyFileChange>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyFileChange {
    pub path: PathBuf,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub status: DependencyFileChangeStatus,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DependencyFileChangeStatus {
    Created,
    Modified,
    Removed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Recorded,
    Starting,
    Running,
    Completed,
    Failed,
    Reverted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CgroupStatus {
    NotRequested,
    Pending,
    Tagged,
    Degraded(String),
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LandlockStatus {
    NotRequested,
    Pending,
    Applied,
    Degraded(String),
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotStatus {
    NotRequested,
    Pending,
    Created {
        backend: SnapshotBackend,
        snapshot_id: String,
        snapshot_root: Option<PathBuf>,
    },
    Failed(String),
    Reverted {
        backend: SnapshotBackend,
        snapshot_id: String,
        snapshot_root: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SnapshotBackend {
    Btrfs,
    OverlayFs,
}
