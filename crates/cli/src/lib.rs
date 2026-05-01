use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::ExitStatus;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use warder_config::{
    ConfigIssueSeverity, ConfigParseError, EnforcementRequirement, EnvironmentSupport,
    SnapshotBackend as ConfigSnapshotBackend, SnapshotPolicy, WarderConfig, WritePolicy,
};
use warder_core::{
    CgroupStatus, DependencyFileChange, DependencyFileChangeStatus, LandlockStatus, SessionRecord,
    SessionStatus, SnapshotStatus,
};
use warder_db::WarderDb;
use warder_enforcement::{
    plan_landlock_restrictions, prepare_landlock_ruleset_with_kernel, CgroupTagResult,
    CgroupTagStatus, CgroupTagger, LandlockAccess, LandlockPlanStatus, LandlockPrepareStatus,
    LandlockRequirement, LandlockRule, LandlockSupport, SyscallLandlockKernel,
};
use warder_journal::{
    FileJournalEvent, InotifyFileJournalWatcher, NetworkJournalEvent, ProcfsNetworkSocketReader,
    ProtectedJournalZone,
};
use warder_snapshot::{
    load_snapshot_manifest, plan_snapshot, BtrfsSnapshotDriver, SnapshotBackend,
    SnapshotBackendDriver, SnapshotCommandRunner, SnapshotCreateRequest, SnapshotPlan,
    SnapshotRequirement, SnapshotRestoreRequest, SystemSnapshotCommandRunner,
    UnsupportedSnapshotDriver,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    Help,
    Version,
    Start {
        config: Option<PathBuf>,
    },
    Stop,
    Status,
    Doctor,
    Init {
        output: PathBuf,
        profile: String,
        protected_paths: Vec<PathBuf>,
        agent_command: Option<String>,
        force: bool,
        print: bool,
    },
    Profiles {
        format: ProfileCatalogFormat,
    },
    Run {
        config: Option<PathBuf>,
        db: Option<PathBuf>,
        cgroup_root: Option<PathBuf>,
        snapshot_root: Option<PathBuf>,
        launch: bool,
        agent: String,
        command: Vec<String>,
    },
    Journal {
        db: Option<PathBuf>,
        session_id: Option<String>,
        kind: JournalKind,
    },
    Receipt {
        db: Option<PathBuf>,
        session_id: String,
        format: ReceiptFormat,
    },
    Snapshot {
        session_id: String,
        config: Option<PathBuf>,
        snapshot_root: Option<PathBuf>,
    },
    Revert {
        snapshot_id: String,
        snapshot_root: Option<PathBuf>,
        db: Option<PathBuf>,
        session_id: Option<String>,
        preview: bool,
    },
    Explain {
        config: PathBuf,
    },
    DryRun {
        config: PathBuf,
        agent: String,
        command: Vec<String>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReceiptFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProfileCatalogFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JournalKind {
    File,
    Network,
    All,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReadinessLevel {
    Strong,
    Degraded,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostReadinessReport {
    pub level: ReadinessLevel,
    pub blocked_reasons: Vec<String>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDoctorReport {
    pub readiness: HostReadinessReport,
    pub diagnostics: Vec<HostDiagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDiagnostic {
    pub label: String,
    pub status: HostDiagnosticStatus,
    pub message: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostDiagnosticStatus {
    Ok,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostDiagnosticPaths {
    pub proc_self_fd: PathBuf,
    pub proc_self_net_tcp: PathBuf,
    pub proc_self_stat: PathBuf,
    pub cgroup_procs: PathBuf,
    pub docker_env: PathBuf,
    pub container_env: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSessionOutcome {
    pub session_id: String,
    pub validation_warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub session_id: String,
    pub exit_code: Option<i32>,
    pub validation_warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchedDaemon {
    pub pid: u32,
    pub socket_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalDaemonRunOptions {
    pub runtime_path: PathBuf,
    pub socket_path: PathBuf,
    pub config_path: Option<PathBuf>,
}

pub trait DaemonLauncher {
    fn launch(&self) -> Result<LaunchedDaemon, CliError>;

    fn is_alive(&self, pid: u32) -> bool;
}

pub trait DaemonTerminator {
    fn terminate(&self, pid: u32) -> Result<(), CliError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandDaemonLauncher {
    pub executable: PathBuf,
    pub runtime_path: PathBuf,
    pub socket_path: PathBuf,
    pub config_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandDaemonTerminator;

pub fn parse_args<I, S>(args: I) -> Result<CliCommand, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.is_empty() {
        return err("missing program name");
    }
    args.remove(0);

    let Some(command) = args.first().cloned() else {
        return err("missing command");
    };
    args.remove(0);

    match command.as_str() {
        "help" | "--help" | "-h" => Ok(CliCommand::Help),
        "version" | "--version" | "-V" => Ok(CliCommand::Version),
        "start" => parse_start(args),
        "stop" => Ok(CliCommand::Stop),
        "status" => Ok(CliCommand::Status),
        "doctor" => Ok(CliCommand::Doctor),
        "init" => parse_init(args),
        "profiles" => parse_profiles(args),
        "run" => parse_run(args),
        "journal" => parse_journal(args),
        "receipt" => parse_receipt(args),
        "snapshot" => parse_snapshot(args),
        "revert" => parse_revert(args),
        "explain" => parse_required_value(args, "--config").map(|config| CliCommand::Explain {
            config: PathBuf::from(config),
        }),
        "dry-run" => parse_dry_run(args),
        _ => err(format!("unknown command '{command}'")),
    }
}

pub fn is_internal_daemon_run_command<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .nth(1)
        .map(|arg| arg.as_ref() == "__warder-daemon-run")
        .unwrap_or(false)
}

pub fn parse_internal_daemon_run_options<I, S>(
    args: I,
) -> Result<InternalDaemonRunOptions, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.len() < 2 || args[1] != "__warder-daemon-run" {
        return err("internal daemon run command is required");
    }
    args.drain(0..2);

    let mut runtime_path = None;
    let mut socket_path = None;
    let mut config_path = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--runtime" => {
                runtime_path = Some(PathBuf::from(value_after(&args, index, "--runtime")?));
                index += 2;
            }
            "--socket" => {
                socket_path = Some(PathBuf::from(value_after(&args, index, "--socket")?));
                index += 2;
            }
            "--config" => {
                config_path = Some(PathBuf::from(value_after(&args, index, "--config")?));
                index += 2;
            }
            unknown => return err(format!("unknown internal daemon option '{unknown}'")),
        }
    }

    Ok(InternalDaemonRunOptions {
        runtime_path: runtime_path.ok_or_else(|| CliError {
            message: "internal daemon run requires --runtime".to_string(),
        })?,
        socket_path: socket_path.ok_or_else(|| CliError {
            message: "internal daemon run requires --socket".to_string(),
        })?,
        config_path,
    })
}

pub fn command_summary(command: &CliCommand) -> String {
    match command {
        CliCommand::Help => usage().to_string(),
        CliCommand::Version => version().to_string(),
        CliCommand::Start { .. } => "warder daemon start requested".to_string(),
        CliCommand::Stop => "warder daemon stop requested".to_string(),
        CliCommand::Status => "warder status requested".to_string(),
        CliCommand::Doctor => "host readiness check requested".to_string(),
        CliCommand::Init {
            output,
            profile,
            protected_paths,
            ..
        } => format!(
            "starter config requested at '{}' for profile '{profile}' with {} protected path(s)",
            output.display(),
            protected_paths.len()
        ),
        CliCommand::Profiles { format } => format!(
            "agent profile catalog requested as {}",
            profile_catalog_format_label(*format)
        ),
        CliCommand::Run {
            agent,
            command,
            launch,
            ..
        } => {
            let mode = if *launch {
                "supervised launch"
            } else {
                "record-only session"
            };
            format!(
                "{mode} requested for agent '{agent}' with command: {}",
                shell_command_line(command)
            )
        }
        CliCommand::Journal {
            session_id, kind, ..
        } => match session_id {
            Some(session_id) => format!(
                "{} requested for session '{session_id}'",
                journal_kind_summary_label(*kind)
            ),
            None => format!(
                "{} requested for recent sessions",
                journal_kind_summary_label(*kind)
            ),
        },
        CliCommand::Receipt {
            session_id, format, ..
        } => {
            format!(
                "receipt requested for session '{session_id}' as {}",
                receipt_format_label(*format)
            )
        }
        CliCommand::Snapshot {
            session_id,
            config: Some(config),
            snapshot_root: Some(snapshot_root),
        } => format!(
            "snapshot requested for session '{session_id}' using config '{}' and snapshot root '{}'",
            config.display(),
            snapshot_root.display()
        ),
        CliCommand::Snapshot { session_id, .. } => format!(
            "snapshot requested for session '{session_id}', but --config and --snapshot-root are required for live snapshot creation"
        ),
        CliCommand::Revert {
            snapshot_id,
            snapshot_root: Some(snapshot_root),
            preview: true,
            ..
        } => format!(
            "revert preview requested for snapshot '{snapshot_id}' using snapshot root '{}'",
            snapshot_root.display()
        ),
        CliCommand::Revert {
            snapshot_id,
            snapshot_root: Some(snapshot_root),
            ..
        } => format!(
            "guarded revert requested for snapshot '{snapshot_id}' using snapshot root '{}'",
            snapshot_root.display()
        ),
        CliCommand::Revert {
            snapshot_id,
            snapshot_root: None,
            ..
        } => format!(
            "revert requested for snapshot '{snapshot_id}', but --snapshot-root is required for guarded restore"
        ),
        CliCommand::Explain { config } => {
            format!(
                "policy explanation requested for config '{}'",
                config.display()
            )
        }
        CliCommand::DryRun { agent, command, .. } => format!(
            "dry run requested for agent '{agent}' with command: {}",
            shell_command_line(command)
        ),
    }
}

pub fn version() -> String {
    format!("warder {}", env!("CARGO_PKG_VERSION"))
}

pub fn write_starter_config(
    output: impl Into<PathBuf>,
    profile: &str,
    protected_paths: &[PathBuf],
    agent_command: Option<&str>,
    force: bool,
) -> Result<String, CliError> {
    if protected_paths.is_empty() {
        return err("starter config requires at least one protected path");
    }
    let output = output.into();
    let config = render_starter_config(profile, protected_paths, agent_command)?;
    if force {
        std::fs::write(&output, config).map_err(|error| CliError {
            message: format!(
                "failed to write starter config '{}': {error}",
                output.display()
            ),
        })?;
    } else {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|error| CliError {
                message: format!(
                    "failed to create starter config '{}': {error}",
                    output.display()
                ),
            })?;
        use std::io::Write;
        file.write_all(config.as_bytes())
            .map_err(|error| CliError {
                message: format!(
                    "failed to write starter config '{}': {error}",
                    output.display()
                ),
            })?;
    }
    Ok(format!(
        "wrote starter config: {}\nnext: warder explain --config {}",
        output.display(),
        shell_quote(&output.display().to_string())
    ))
}

pub fn render_starter_config(
    profile: &str,
    protected_paths: &[PathBuf],
    agent_command: Option<&str>,
) -> Result<String, CliError> {
    if protected_paths.is_empty() {
        return err("starter config requires at least one protected path");
    }
    let profile = profile.trim();
    if profile.is_empty() {
        return err("starter config profile cannot be empty");
    }
    if !is_safe_config_identifier(profile) {
        return err(format!(
            "starter config profile '{profile}' may only contain ASCII letters, numbers, '.', '_', or '-'"
        ));
    }
    let agent_command = agent_command
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| default_agent_command_for_profile(profile).to_string());
    let normalized_paths = protected_paths
        .iter()
        .map(|path| normalize_starter_path(path))
        .collect::<Result<Vec<_>, _>>()?;
    let zone_paths = normalized_paths
        .iter()
        .map(|path| toml_string(&path.display().to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let zone_name = if protected_paths.len() == 1 {
        "Protected Path"
    } else {
        "Protected Paths"
    };

    Ok(format!(
        "[enforcement]\n\
landlock = \"best-effort\"\n\
cgroups = \"best-effort\"\n\n\
[network]\n\
journal = true\n\n\
[[zones]]\n\
id = \"protected\"\n\
name = \"{zone_name}\"\n\
description = \"Generated by warder init; edit paths and policy before using for sensitive work.\"\n\
paths = [{zone_paths}]\n\
write_policy = \"deny\"\n\
snapshot = \"disabled\"\n\n\
[[agents]]\n\
id = {agent_id}\n\
label = {agent_label}\n\
command = {agent_command}\n\
profile = {profile}\n",
        agent_id = toml_string(profile),
        agent_label = toml_string(&starter_agent_label(profile)),
        agent_command = toml_string(&agent_command),
        profile = toml_string(profile)
    ))
}

fn default_agent_command_for_profile(profile: &str) -> &'static str {
    match profile {
        "codex-cli" => "codex",
        "claude-code" => "claude",
        "goose-cli" => "goose",
        "openclaw-cli" | "openclaw-gateway" | "openclaw-agent" => "openclaw",
        "local-script" => "sh",
        _ => "sh",
    }
}

fn starter_agent_label(profile: &str) -> String {
    known_agent_profile_catalog()
        .into_iter()
        .find(|entry| entry.id == profile)
        .map(|entry| entry.id.to_string())
        .unwrap_or_else(|| profile.to_string())
}

fn is_safe_config_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn normalize_starter_path(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|current_dir| current_dir.join(path))
        .map_err(|error| CliError {
            message: format!("failed to resolve current directory for starter config: {error}"),
        })
}

fn toml_string(value: &str) -> String {
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

pub fn command_not_implemented_error(command: &CliCommand) -> Option<CliError> {
    match command {
        CliCommand::Snapshot { config: None, .. }
        | CliCommand::Snapshot {
            snapshot_root: None,
            ..
        }
        | CliCommand::Revert {
            snapshot_root: None,
            ..
        } => Some(CliError {
            message: command_summary(command),
        }),
        CliCommand::Snapshot {
            config: Some(_),
            snapshot_root: Some(_),
            ..
        } => None,
        CliCommand::Revert {
            snapshot_root: Some(_),
            ..
        } => None,
        _ => None,
    }
}

pub fn render_revert_preview(
    snapshot_root: impl AsRef<Path>,
    snapshot_id: &str,
) -> Result<String, CliError> {
    let manifest =
        load_snapshot_manifest(snapshot_root, snapshot_id).map_err(|error| CliError {
            message: error.message,
        })?;
    let mut lines = vec![
        format!("snapshot: {}", manifest.snapshot_id),
        format!("backend: {}", manifest.backend),
        "restore: preview only; no changes made".to_string(),
    ];
    if manifest.backend != "btrfs" {
        lines.push("restore readiness: blocked".to_string());
        lines.push(format!(
            "blocked: manifest backend is {}; guarded restore currently supports btrfs only",
            manifest.backend
        ));
    } else if manifest.entries.is_empty() {
        lines.push("restore readiness: blocked".to_string());
        lines.push("blocked: manifest has no entries".to_string());
    } else if manifest
        .entries
        .iter()
        .any(|entry| revert_preview_entry_status(&entry.source_root, &entry.snapshot_path).blocked)
    {
        lines.push("restore readiness: blocked".to_string());
    } else {
        lines.push("restore readiness: ready".to_string());
    }
    lines.push("restore entries:".to_string());
    lines.extend(
        manifest
            .entries
            .iter()
            .map(|entry| render_revert_preview_entry(&entry.source_root, &entry.snapshot_path)),
    );
    Ok(lines.join("\n"))
}

fn render_revert_preview_entry(source_root: &str, snapshot_path: &str) -> String {
    let status = revert_preview_entry_status(source_root, snapshot_path).label;
    format!("- {status}: {source_root} <= {snapshot_path}")
}

struct RevertPreviewEntryStatus {
    label: &'static str,
    blocked: bool,
}

fn revert_preview_entry_status(source_root: &str, snapshot_path: &str) -> RevertPreviewEntryStatus {
    let source_root_path = Path::new(source_root);
    let snapshot_path = Path::new(snapshot_path);
    if !snapshot_path.exists() {
        RevertPreviewEntryStatus {
            label: "blocked: snapshot path missing",
            blocked: true,
        }
    } else if source_root_path.exists() {
        RevertPreviewEntryStatus {
            label: "blocked: target exists",
            blocked: true,
        }
    } else if !source_root_path
        .parent()
        .map(|parent| parent.exists())
        .unwrap_or(false)
    {
        RevertPreviewEntryStatus {
            label: "blocked: target parent missing",
            blocked: true,
        }
    } else {
        RevertPreviewEntryStatus {
            label: "ready: target missing",
            blocked: false,
        }
    }
}

pub fn create_snapshot_from_config(
    config_path: impl Into<PathBuf>,
    snapshot_root: impl Into<PathBuf>,
    session_id: &str,
) -> Result<String, CliError> {
    create_snapshot_from_config_with_runner(
        config_path,
        snapshot_root,
        session_id,
        SystemSnapshotCommandRunner,
    )
}

pub fn create_snapshot_from_config_with_runner<R>(
    config_path: impl Into<PathBuf>,
    snapshot_root: impl Into<PathBuf>,
    session_id: &str,
    runner: R,
) -> Result<String, CliError>
where
    R: SnapshotCommandRunner,
{
    let config_path = config_path.into();
    let snapshot_root = snapshot_root.into();
    let config = load_config(&config_path)?;
    let validation = config.validate(&EnvironmentSupport {
        landlock: true,
        cgroups: true,
        ebpf: true,
        snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
    });
    let errors = validation
        .issues
        .iter()
        .filter(|issue| issue.severity == ConfigIssueSeverity::Error)
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return err(format!("config validation failed: {}", errors.join("; ")));
    }
    let roots = config
        .zones
        .iter()
        .flat_map(|zone| zone.paths.iter().cloned())
        .collect::<Vec<_>>();
    let driver = BtrfsSnapshotDriver::new(&snapshot_root, runner);
    let outcome = driver
        .create_snapshot(&SnapshotCreateRequest {
            session_id: session_id.to_string(),
            roots,
        })
        .map_err(|error| CliError {
            message: error.message,
        })?;
    Ok(format!(
        "snapshot created: {} via {}\nsnapshot root: {}\nrestore: {}",
        outcome.snapshot_id,
        snapshot_plan_backend_label(&outcome.backend),
        snapshot_root.display(),
        guarded_snapshot_restore_command(&outcome.snapshot_id, Some(&snapshot_root))
    ))
}

pub fn restore_snapshot_from_root(
    snapshot_root: impl Into<PathBuf>,
    snapshot_id: &str,
) -> Result<String, CliError> {
    restore_snapshot_from_root_with_runner(snapshot_root, snapshot_id, SystemSnapshotCommandRunner)
}

pub fn restore_snapshot_from_root_for_session(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    snapshot_root: impl Into<PathBuf>,
    snapshot_id: &str,
) -> Result<String, CliError> {
    restore_snapshot_from_root_for_session_with_runner(
        db_path,
        session_id,
        snapshot_root,
        snapshot_id,
        SystemSnapshotCommandRunner,
    )
}

pub fn restore_snapshot_from_root_for_session_with_runner<R>(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    snapshot_root: impl Into<PathBuf>,
    snapshot_id: &str,
    runner: R,
) -> Result<String, CliError>
where
    R: SnapshotCommandRunner,
{
    let db_path = db_path.into();
    let snapshot_root = snapshot_root.into();
    validate_snapshot_restore_recording(&db_path, session_id, snapshot_id, &snapshot_root)?;
    let report = restore_snapshot_from_root_with_runner(&snapshot_root, snapshot_id, runner)?;
    record_snapshot_restore(db_path, session_id, snapshot_id, snapshot_root)?;
    Ok(format!(
        "{report}\nsession recorded as reverted: {session_id}"
    ))
}

pub fn restore_snapshot_from_root_with_runner<R>(
    snapshot_root: impl Into<PathBuf>,
    snapshot_id: &str,
    runner: R,
) -> Result<String, CliError>
where
    R: SnapshotCommandRunner,
{
    let driver = BtrfsSnapshotDriver::new(snapshot_root, runner);
    let outcome = driver
        .restore_snapshot(&SnapshotRestoreRequest {
            snapshot_id: snapshot_id.to_string(),
        })
        .map_err(|error| CliError {
            message: error.message,
        })?;
    Ok(format!(
        "snapshot restored: {} via {}",
        outcome.snapshot_id,
        snapshot_plan_backend_label(&outcome.backend)
    ))
}

fn record_snapshot_restore(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    snapshot_id: &str,
    snapshot_root: PathBuf,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        session.status = SessionStatus::Reverted;
        session.ended_at = Some(SystemTime::now());
        session.snapshot_status = SnapshotStatus::Reverted {
            backend: warder_core::SnapshotBackend::Btrfs,
            snapshot_id: snapshot_id.to_string(),
            snapshot_root: Some(snapshot_root),
        };
    })
}

fn validate_snapshot_restore_recording(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    snapshot_id: &str,
    snapshot_root: &Path,
) -> Result<(), CliError> {
    let db = WarderDb::open(db_path.into()).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    let session = db
        .get_session(session_id)
        .map_err(db_error)?
        .ok_or_else(|| CliError {
            message: format!("session '{session_id}' was not found"),
        })?;
    if session.status == SessionStatus::Reverted {
        return err(format!(
            "session '{session_id}' is already recorded as reverted"
        ));
    }
    if matches!(
        session.status,
        SessionStatus::Starting | SessionStatus::Running
    ) {
        return err(format!(
            "session '{session_id}' is still {}; refusing to record restore",
            session_status_label(session.status)
        ));
    }
    match &session.snapshot_status {
        SnapshotStatus::Created {
            backend,
            snapshot_id: created_snapshot_id,
            snapshot_root: created_snapshot_root,
            ..
        } if created_snapshot_id == snapshot_id => {
            if *backend != warder_core::SnapshotBackend::Btrfs {
                return err(format!(
                    "session '{session_id}' snapshot backend is {}; guarded restore currently supports btrfs only",
                    snapshot_backend_label(*backend)
                ));
            }
            if let Some(created_snapshot_root) = created_snapshot_root {
                if created_snapshot_root != snapshot_root {
                    return err(format!(
                        "snapshot root '{}' does not match session snapshot root '{}'",
                        snapshot_root.display(),
                        created_snapshot_root.display()
                    ));
                }
            } else {
                return err(format!(
                    "session '{session_id}' snapshot '{snapshot_id}' does not record a snapshot root"
                ));
            }
            Ok(())
        }
        SnapshotStatus::Created {
            snapshot_id: created_snapshot_id,
            ..
        } => err(format!(
            "snapshot '{snapshot_id}' does not match session snapshot '{created_snapshot_id}'"
        )),
        SnapshotStatus::Failed(message) => err(format!(
            "session '{session_id}' snapshot creation failed; cannot record restore: {message}"
        )),
        _ => err(format!(
            "session '{session_id}' does not have a created snapshot to record as reverted"
        )),
    }
}

pub fn render_session_receipt(session: &SessionRecord) -> String {
    render_session_receipt_with_activity(session, &[], &[], None)
}

fn render_session_receipt_with_activity(
    session: &SessionRecord,
    file_events: &[FileJournalEvent],
    network_events: &[NetworkJournalEvent],
    db_path: Option<&Path>,
) -> String {
    let mut lines = vec![
        format!("session: {}", session.id),
        format!("agent: {} ({})", session.agent_label, session.agent_id),
        format!(
            "profile: {}",
            session.agent_profile.as_deref().unwrap_or("generic-cli")
        ),
        format!("status: {}", session_status_label(session.status)),
        format!("exit code: {}", optional_exit_code_label(session.exit_code)),
        format!("command: {}", shell_command_line(&session.command)),
        format!("protected zones: {}", session.protected_zone_ids.join(", ")),
        format!("root pid: {}", optional_pid_label(session.root_pid)),
        format!(
            "cgroup: {}",
            cgroup_status_label(&session.cgroup_status, session.cgroup_path.as_ref())
        ),
        format!(
            "landlock: {}",
            landlock_status_label(&session.landlock_status)
        ),
        format!(
            "snapshot: {}",
            snapshot_status_label(&session.snapshot_status)
        ),
    ];
    let readiness = assess_session_readiness(session);
    lines.push(format!(
        "session readiness: {}",
        readiness_level_label(readiness.level)
    ));
    append_reason_list("blocked reasons", &readiness.blocked_reasons, &mut lines);
    append_reason_list("degraded reasons", &readiness.degraded_reasons, &mut lines);
    let dependency_summary = dependency_change_summary(&session.command);
    lines.push(format!(
        "dependency changes: {} ({})",
        dependency_summary.status, dependency_summary.reason
    ));
    for evidence in &dependency_summary.evidence {
        lines.push(format!("- dependency evidence: {evidence}"));
    }
    if session.dependency_file_changes.is_empty() {
        lines.push("dependency file changes: none".to_string());
    } else {
        lines.push(format!(
            "dependency file changes: {}",
            session.dependency_file_changes.len()
        ));
        lines.extend(
            session
                .dependency_file_changes
                .iter()
                .map(render_dependency_file_change_line),
        );
    }
    let file_activity = file_activity_summary(file_events);
    lines.push(format!(
        "file activity: {} event(s)",
        file_activity.total_events
    ));
    if file_activity.total_events > 0 {
        lines.push(format!(
            "file activity zones: {}",
            render_count_map(&file_activity.zones)
        ));
        lines.push(format!(
            "file activity sources: {}",
            render_count_map(&file_activity.sources)
        ));
        lines.push(format!(
            "file activity attribution: {}",
            render_count_map(&file_activity.attribution)
        ));
    }
    let network_activity = network_activity_summary(network_events);
    lines.push(format!(
        "network activity: {} event(s)",
        network_activity.total_events
    ));
    if network_activity.total_events > 0 {
        lines.push(format!(
            "network activity destinations: {}",
            render_count_map(&network_activity.destinations)
        ));
        lines.push(format!(
            "network activity protocols: {}",
            render_count_map(&network_activity.protocols)
        ));
        lines.push(format!(
            "network activity sources: {}",
            render_count_map(&network_activity.sources)
        ));
        lines.push(format!(
            "network activity attribution: {}",
            render_count_map(&network_activity.attribution)
        ));
    }
    lines.push(format!(
        "degraded coverage: {} reason(s)",
        session.degraded_reasons.len()
    ));
    if session.degraded_reasons.is_empty() {
        lines.push("coverage degraded reasons: none".to_string());
    } else {
        lines.push("coverage degraded reasons:".to_string());
        lines.extend(
            session
                .degraded_reasons
                .iter()
                .map(|reason| format!("- {reason}")),
        );
    }
    let review_guidance = receipt_review_guidance(session, &file_activity, &network_activity);
    lines.push("review guidance:".to_string());
    lines.extend(
        review_guidance
            .iter()
            .map(|guidance| format!("- {guidance}")),
    );
    let review_actions =
        receipt_review_actions(session, &file_activity, &network_activity, db_path);
    lines.push("review actions:".to_string());
    lines.extend(render_review_action_lines(&review_actions));
    let recovery_guidance =
        receipt_recovery_guidance(session, &file_activity, &network_activity, db_path);
    lines.push("recovery guidance:".to_string());
    lines.extend(
        recovery_guidance
            .iter()
            .map(|guidance| format!("- {guidance}")),
    );
    let recovery_actions =
        receipt_recovery_actions(session, &file_activity, &network_activity, db_path);
    lines.push("recovery actions:".to_string());
    lines.extend(render_recovery_action_lines(&recovery_actions));
    lines.join("\n")
}

pub fn render_session_receipt_json(session: &SessionRecord) -> Result<String, CliError> {
    serde_json::to_string_pretty(&StructuredSessionReceipt::from(session)).map_err(|error| {
        CliError {
            message: format!("failed to render structured receipt: {error}"),
        }
    })
}

fn render_session_receipt_json_with_activity(
    session: &SessionRecord,
    file_events: &[FileJournalEvent],
    network_events: &[NetworkJournalEvent],
    db_path: Option<&Path>,
) -> Result<String, CliError> {
    let mut receipt = StructuredSessionReceipt::from(session);
    receipt.file_activity = file_activity_summary(file_events);
    receipt.network_activity = network_activity_summary(network_events);
    receipt.review_guidance =
        receipt_review_guidance(session, &receipt.file_activity, &receipt.network_activity);
    receipt.review_actions = receipt_review_actions(
        session,
        &receipt.file_activity,
        &receipt.network_activity,
        db_path,
    );
    receipt.recovery_guidance = receipt_recovery_guidance(
        session,
        &receipt.file_activity,
        &receipt.network_activity,
        db_path,
    );
    receipt.recovery_actions = receipt_recovery_actions(
        session,
        &receipt.file_activity,
        &receipt.network_activity,
        db_path,
    );
    serde_json::to_string_pretty(&receipt).map_err(|error| CliError {
        message: format!("failed to render structured receipt: {error}"),
    })
}

#[derive(Serialize)]
struct StructuredSessionReceipt {
    session_id: String,
    agent: StructuredReceiptAgent,
    status: &'static str,
    exit_code: Option<i32>,
    command: Vec<String>,
    protected_zones: Vec<String>,
    root_pid: Option<u32>,
    enforcement: StructuredReceiptEnforcement,
    dependency_changes: DependencyChangeSummary,
    dependency_file_changes: Vec<StructuredDependencyFileChange>,
    file_activity: StructuredFileActivitySummary,
    network_activity: StructuredNetworkActivitySummary,
    readiness: StructuredReadiness,
    degraded_coverage: StructuredDegradedCoverage,
    degraded_reasons: Vec<String>,
    review_guidance: Vec<String>,
    review_actions: Vec<StructuredReviewAction>,
    recovery_guidance: Vec<String>,
    recovery_actions: Vec<StructuredRecoveryAction>,
}

#[derive(Serialize)]
struct StructuredReceiptAgent {
    id: String,
    label: String,
    profile: String,
}

#[derive(Serialize)]
struct StructuredReceiptEnforcement {
    cgroup: StructuredReceiptStatus,
    landlock: StructuredReceiptStatus,
    snapshot: StructuredReceiptStatus,
}

#[derive(Serialize)]
struct StructuredReceiptStatus {
    status: &'static str,
    message: Option<String>,
    path: Option<String>,
    backend: Option<&'static str>,
    snapshot_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct DependencyChangeSummary {
    status: &'static str,
    reason: String,
    evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StructuredDependencyFileChange {
    path: String,
    before_hash: Option<String>,
    after_hash: Option<String>,
    status: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DependencyFileSnapshot {
    path: PathBuf,
    content_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StructuredFileActivitySummary {
    total_events: usize,
    zones: std::collections::BTreeMap<String, usize>,
    sources: std::collections::BTreeMap<String, usize>,
    attribution: std::collections::BTreeMap<String, usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StructuredNetworkActivitySummary {
    total_events: usize,
    destinations: std::collections::BTreeMap<String, usize>,
    protocols: std::collections::BTreeMap<String, usize>,
    sources: std::collections::BTreeMap<String, usize>,
    attribution: std::collections::BTreeMap<String, usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StructuredReadiness {
    level: &'static str,
    blocked_reasons: Vec<String>,
    degraded_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StructuredDegradedCoverage {
    total_reasons: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StructuredReviewAction {
    kind: &'static str,
    label: &'static str,
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_argv: Option<Vec<String>>,
    mutates: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StructuredRecoveryAction {
    kind: &'static str,
    label: &'static str,
    command: String,
    command_argv: Vec<String>,
    mutates: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl From<&SessionRecord> for StructuredSessionReceipt {
    fn from(session: &SessionRecord) -> Self {
        let readiness = assess_session_readiness(session);
        Self {
            session_id: session.id.clone(),
            agent: StructuredReceiptAgent {
                id: session.agent_id.clone(),
                label: session.agent_label.clone(),
                profile: session
                    .agent_profile
                    .clone()
                    .unwrap_or_else(|| "generic-cli".to_string()),
            },
            status: session_status_label(session.status),
            exit_code: session.exit_code,
            command: session.command.clone(),
            protected_zones: session.protected_zone_ids.clone(),
            root_pid: session.root_pid,
            enforcement: StructuredReceiptEnforcement {
                cgroup: structured_cgroup_status(
                    &session.cgroup_status,
                    session.cgroup_path.as_ref(),
                ),
                landlock: structured_landlock_status(&session.landlock_status),
                snapshot: structured_snapshot_status(&session.snapshot_status),
            },
            dependency_changes: dependency_change_summary(&session.command),
            dependency_file_changes: session
                .dependency_file_changes
                .iter()
                .map(StructuredDependencyFileChange::from)
                .collect(),
            file_activity: StructuredFileActivitySummary::empty(),
            network_activity: StructuredNetworkActivitySummary::empty(),
            readiness: StructuredReadiness::from(readiness),
            degraded_coverage: StructuredDegradedCoverage {
                total_reasons: session.degraded_reasons.len(),
            },
            degraded_reasons: session.degraded_reasons.clone(),
            review_guidance: receipt_review_guidance(
                session,
                &StructuredFileActivitySummary::empty(),
                &StructuredNetworkActivitySummary::empty(),
            ),
            review_actions: receipt_review_actions(
                session,
                &StructuredFileActivitySummary::empty(),
                &StructuredNetworkActivitySummary::empty(),
                None,
            ),
            recovery_guidance: receipt_recovery_guidance(
                session,
                &StructuredFileActivitySummary::empty(),
                &StructuredNetworkActivitySummary::empty(),
                None,
            ),
            recovery_actions: receipt_recovery_actions(
                session,
                &StructuredFileActivitySummary::empty(),
                &StructuredNetworkActivitySummary::empty(),
                None,
            ),
        }
    }
}

impl From<HostReadinessReport> for StructuredReadiness {
    fn from(readiness: HostReadinessReport) -> Self {
        Self {
            level: readiness_level_label(readiness.level),
            blocked_reasons: readiness.blocked_reasons,
            degraded_reasons: readiness.degraded_reasons,
        }
    }
}

impl StructuredFileActivitySummary {
    fn empty() -> Self {
        Self {
            total_events: 0,
            zones: std::collections::BTreeMap::new(),
            sources: std::collections::BTreeMap::new(),
            attribution: std::collections::BTreeMap::new(),
        }
    }
}

impl StructuredNetworkActivitySummary {
    fn empty() -> Self {
        Self {
            total_events: 0,
            destinations: std::collections::BTreeMap::new(),
            protocols: std::collections::BTreeMap::new(),
            sources: std::collections::BTreeMap::new(),
            attribution: std::collections::BTreeMap::new(),
        }
    }
}

impl From<&DependencyFileChange> for StructuredDependencyFileChange {
    fn from(change: &DependencyFileChange) -> Self {
        Self {
            path: change.path.display().to_string(),
            before_hash: change.before_hash.clone(),
            after_hash: change.after_hash.clone(),
            status: dependency_file_change_status_label(change.status),
        }
    }
}

pub fn render_session_receipt_from_db(
    db_path: Option<PathBuf>,
    session_id: &str,
) -> Result<String, CliError> {
    render_session_receipt_from_db_with_format(db_path, session_id, ReceiptFormat::Text)
}

pub fn render_session_receipt_from_db_with_format(
    db_path: Option<PathBuf>,
    session_id: &str,
    format: ReceiptFormat,
) -> Result<String, CliError> {
    let explicit_db_path = db_path.clone();
    let db_path = db_path.unwrap_or_else(default_db_path);
    let db = WarderDb::open(&db_path).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    let session = db
        .get_session(session_id)
        .map_err(db_error)?
        .ok_or_else(|| CliError {
            message: format!("session '{session_id}' was not found"),
        })?;
    let file_events = db
        .list_file_journal_events(Some(session_id))
        .map_err(db_error)?;
    let network_events = db
        .list_network_journal_events(Some(session_id))
        .map_err(db_error)?;
    match format {
        ReceiptFormat::Text => Ok(render_session_receipt_with_activity(
            &session,
            &file_events,
            &network_events,
            explicit_db_path.as_deref(),
        )),
        ReceiptFormat::Json => render_session_receipt_json_with_activity(
            &session,
            &file_events,
            &network_events,
            explicit_db_path.as_deref(),
        ),
    }
}

pub fn render_file_journal_from_db(
    db_path: Option<PathBuf>,
    session_id: Option<&str>,
) -> Result<String, CliError> {
    let db_path = db_path.unwrap_or_else(default_db_path);
    let db = WarderDb::open(db_path).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    ensure_journal_session_exists(&db, session_id)?;
    let events = db.list_file_journal_events(session_id).map_err(db_error)?;
    Ok(warder_journal::render_file_journal_summary(&events))
}

pub fn render_network_journal_from_db(
    db_path: Option<PathBuf>,
    session_id: Option<&str>,
) -> Result<String, CliError> {
    let db_path = db_path.unwrap_or_else(default_db_path);
    let db = WarderDb::open(db_path).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    ensure_journal_session_exists(&db, session_id)?;
    let events = db
        .list_network_journal_events(session_id)
        .map_err(db_error)?;
    Ok(warder_journal::render_network_journal_summary(&events))
}

pub fn render_all_journals_from_db(
    db_path: Option<PathBuf>,
    session_id: Option<&str>,
) -> Result<String, CliError> {
    let db_path = db_path.unwrap_or_else(default_db_path);
    let db = WarderDb::open(db_path).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    ensure_journal_session_exists(&db, session_id)?;
    let file_events = db.list_file_journal_events(session_id).map_err(db_error)?;
    let network_events = db
        .list_network_journal_events(session_id)
        .map_err(db_error)?;
    Ok(format!(
        "{}\n\n{}",
        warder_journal::render_file_journal_summary(&file_events),
        warder_journal::render_network_journal_summary(&network_events)
    ))
}

fn ensure_journal_session_exists(db: &WarderDb, session_id: Option<&str>) -> Result<(), CliError> {
    if let Some(session_id) = session_id {
        if db.get_session(session_id).map_err(db_error)?.is_none() {
            return Err(CliError {
                message: format!("session '{session_id}' was not found"),
            });
        }
    }

    Ok(())
}

pub fn render_policy_explain_from_config(
    config_path: Option<PathBuf>,
    environment: &EnvironmentSupport,
) -> Result<String, CliError> {
    let config_path = config_path.ok_or_else(|| CliError {
        message: "explain requires --config".to_string(),
    })?;
    let config = load_config(&config_path)?;
    Ok(render_policy_explain(&config, environment))
}

pub fn render_dry_run_from_config(
    config_path: Option<PathBuf>,
    agent: &str,
    command: &[String],
    environment: &EnvironmentSupport,
) -> Result<String, CliError> {
    let config_path = config_path.ok_or_else(|| CliError {
        message: "dry-run requires --config".to_string(),
    })?;
    let config = load_config(&config_path)?;
    let agent_config = config
        .agents
        .iter()
        .find(|candidate| candidate.id == agent)
        .ok_or_else(|| CliError {
            message: format!("agent '{agent}' is not declared in config"),
        })?;

    let mut lines = vec![
        "dry run".to_string(),
        format!("agent: {agent}"),
        format!("command: {}", shell_command_line(command)),
        "launch: no command was run".to_string(),
    ];
    lines.push(render_pre_launch_readiness(environment));
    let agent_profile = effective_agent_profile_for_run(
        agent_config.profile.as_deref(),
        &agent_config.command,
        command,
    );
    lines.push(render_agent_profile_summary(
        agent_profile.as_deref(),
        &agent_config.command,
    ));
    append_openclaw_preflight_lines(agent_profile.as_deref(), command, &mut lines);
    lines.push(render_policy_explain(&config, environment));
    Ok(lines.join("\n"))
}

pub fn render_daemon_status_from_runtime(
    runtime_path: Option<PathBuf>,
) -> Result<String, CliError> {
    let runtime_path = runtime_path.unwrap_or_else(default_daemon_runtime_path);
    let store = warder_daemon::DaemonRuntimeFile::new(runtime_path);
    let report = store.read_status().map_err(runtime_file_error)?;
    Ok(warder_daemon::render_daemon_runtime_report(&report))
}

pub fn start_daemon_runtime(runtime_path: Option<PathBuf>) -> Result<String, CliError> {
    start_daemon_runtime_with_config(runtime_path, None)
}

pub fn start_daemon_runtime_with_config(
    runtime_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
) -> Result<String, CliError> {
    let runtime_path = runtime_path.unwrap_or_else(default_daemon_runtime_path);
    let launcher = CommandDaemonLauncher {
        executable: std::env::current_exe().map_err(|error| CliError {
            message: format!("failed to locate current executable for daemon start: {error}"),
        })?,
        runtime_path: runtime_path.clone(),
        socket_path: PathBuf::from("/tmp/warder.sock"),
        config_path: config_path.clone(),
    };
    start_daemon_runtime_with_launcher_and_config(Some(runtime_path), config_path, &launcher)
}

pub fn start_daemon_runtime_with_launcher(
    runtime_path: Option<PathBuf>,
    launcher: &impl DaemonLauncher,
) -> Result<String, CliError> {
    start_daemon_runtime_with_launcher_and_config(runtime_path, None, launcher)
}

pub fn start_daemon_runtime_with_launcher_and_config(
    runtime_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    launcher: &impl DaemonLauncher,
) -> Result<String, CliError> {
    let runtime_path = runtime_path.unwrap_or_else(default_daemon_runtime_path);
    let validation_warnings = validate_daemon_start_config(config_path.as_ref())?;
    let launched = launcher.launch()?;
    if !launcher.is_alive(launched.pid) {
        return err(format!(
            "failed to verify daemon process {} after launch",
            launched.pid
        ));
    }

    let report = verify_launched_daemon_runtime(&runtime_path, &launched, launcher)?;
    Ok(render_daemon_start_report(&report, &validation_warnings))
}

pub fn stop_daemon_runtime(runtime_path: Option<PathBuf>) -> Result<String, CliError> {
    stop_daemon_runtime_with_terminator(runtime_path, &CommandDaemonTerminator)
}

pub fn stop_daemon_runtime_with_terminator(
    runtime_path: Option<PathBuf>,
    terminator: &impl DaemonTerminator,
) -> Result<String, CliError> {
    let runtime_path = runtime_path.unwrap_or_else(default_daemon_runtime_path);
    let store = warder_daemon::DaemonRuntimeFile::new(runtime_path);
    let current = store.read_status().map_err(runtime_file_error)?;
    let mut terminated_pid = None;
    if current.status == warder_daemon::DaemonRuntimeStatus::Running {
        if let Some(pid) = current.pid {
            terminator.terminate(pid)?;
            terminated_pid = Some(pid);
        }
    }
    store.clear().map_err(runtime_file_error)?;
    let message = terminated_pid
        .map(|pid| format!("daemon pid {pid} terminated and runtime state cleared"))
        .unwrap_or_else(|| {
            "daemon runtime state cleared; no background process was stopped".to_string()
        });
    Ok(warder_daemon::render_daemon_runtime_report(
        &warder_daemon::DaemonRuntimeReport {
            status: warder_daemon::DaemonRuntimeStatus::Stopped,
            pid: None,
            socket_path: None,
            message,
        },
    ))
}

pub fn write_internal_daemon_runtime_state(
    options: &InternalDaemonRunOptions,
    pid: u32,
) -> Result<warder_daemon::DaemonRuntimeReport, CliError> {
    let policy = load_daemon_policy_snapshot(options.config_path.as_ref())?;
    let coordinator = warder_daemon::DaemonCoordinator::new(
        warder_daemon::DaemonStartRequest {
            pid,
            socket_path: options.socket_path.clone(),
        },
        policy,
    );
    let report = coordinator.runtime_report();
    warder_daemon::DaemonRuntimeFile::new(&options.runtime_path)
        .write_status(&report)
        .map_err(runtime_file_error)?;
    Ok(report)
}

pub fn start_internal_daemon_coordinator(
    options: &InternalDaemonRunOptions,
    pid: u32,
) -> Result<warder_daemon::DaemonCoordinator, CliError> {
    let policy = load_daemon_policy_snapshot(options.config_path.as_ref())?;
    let coordinator = warder_daemon::DaemonCoordinator::new(
        warder_daemon::DaemonStartRequest {
            pid,
            socket_path: options.socket_path.clone(),
        },
        policy,
    );
    warder_daemon::DaemonRuntimeFile::new(&options.runtime_path)
        .write_status(&coordinator.runtime_report())
        .map_err(runtime_file_error)?;
    Ok(coordinator)
}

pub fn run_internal_daemon_forever(options: InternalDaemonRunOptions) -> ! {
    let mut coordinator = match start_internal_daemon_coordinator(&options, std::process::id()) {
        Ok(coordinator) => coordinator,
        Err(error) => {
            eprintln!("error: {}", error.message);
            std::process::exit(2);
        }
    };
    loop {
        let _tick = coordinator.tick(warder_daemon::probe_current_host());
        std::thread::sleep(Duration::from_secs(60));
    }
}

impl DaemonLauncher for CommandDaemonLauncher {
    fn launch(&self) -> Result<LaunchedDaemon, CliError> {
        let mut command = Command::new(&self.executable);
        command
            .args(internal_daemon_run_args(
                &self.runtime_path,
                &self.socket_path,
                self.config_path.as_deref(),
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_background_daemon_process(&mut command);

        let child = command.spawn().map_err(|error| CliError {
            message: format!(
                "failed to launch daemon '{}': {error}",
                self.executable.display()
            ),
        })?;
        Ok(LaunchedDaemon {
            pid: child.id(),
            socket_path: self.socket_path.clone(),
        })
    }

    fn is_alive(&self, pid: u32) -> bool {
        PathBuf::from(format!("/proc/{pid}")).exists()
    }
}

#[cfg(unix)]
fn configure_background_daemon_process(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_background_daemon_process(_command: &mut Command) {}

pub fn internal_daemon_run_args(
    runtime_path: &Path,
    socket_path: &Path,
    config_path: Option<&Path>,
) -> Vec<String> {
    let mut args = vec![
        "__warder-daemon-run".to_string(),
        "--runtime".to_string(),
        runtime_path.display().to_string(),
        "--socket".to_string(),
        socket_path.display().to_string(),
    ];
    if let Some(config_path) = config_path {
        args.push("--config".to_string());
        args.push(config_path.display().to_string());
    }
    args
}

impl DaemonTerminator for CommandDaemonTerminator {
    fn terminate(&self, pid: u32) -> Result<(), CliError> {
        let status = Command::new("kill")
            .arg(pid.to_string())
            .status()
            .map_err(|error| CliError {
                message: format!("failed to run kill for daemon pid {pid}: {error}"),
            })?;
        if status.success() {
            Ok(())
        } else {
            err(format!(
                "failed to terminate daemon pid {pid}: kill exited with {status}"
            ))
        }
    }
}

pub fn usage() -> &'static str {
    "usage: warder <command>\n\
primary: warder run --config <path> --launch --agent <id> [--cgroup-root <path>] [--snapshot-root <path>] -- <agent command>\n\
record only: warder run --config <path> --agent <id> -- <agent command>\n\
preflight: warder dry-run --config <path> --agent <id> -- <agent command>\n\
readiness: warder doctor\n\
init: warder init --protected-path <path> [--output <path>] [--profile <id>] [--agent-command <command>] [--force] [--print]\n\
profiles: warder profiles [--format text|json]\n\
snapshot: warder snapshot --config <path> --session <id> --snapshot-root <path>\n\
recovery: warder revert --snapshot <id> --snapshot-root <path> [--preview | --db <path> --session <id>]\n\
inspect: warder receipt [--db <path>] --session <id> [--format text|json] | warder journal [--db <path>] [--file|--network|--all] [--session <id>] | warder status\n\
daemon optional: warder start|stop"
}

pub fn create_run_session(
    command: &CliCommand,
    environment: &EnvironmentSupport,
    now: SystemTime,
) -> Result<RunSessionOutcome, CliError> {
    let CliCommand::Run {
        config,
        db,
        cgroup_root: _,
        snapshot_root,
        launch,
        agent,
        command,
    } = command
    else {
        return err("create_run_session requires a run command");
    };
    let config_path = config.as_ref().ok_or_else(|| CliError {
        message: "run requires --config before a session can be recorded".to_string(),
    })?;
    let db_path = db.clone().unwrap_or_else(default_db_path);
    let config = load_config(config_path)?;
    let validation = config.validate(environment);
    let mut errors = validation
        .issues
        .iter()
        .filter(|issue| issue.severity == ConfigIssueSeverity::Error)
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    let snapshot_plan = planned_snapshot_plan(&config, environment);
    append_snapshot_plan_validation(&snapshot_plan, &mut errors, &mut Vec::new());
    if !errors.is_empty() {
        return err(format!("config validation failed: {}", errors.join("; ")));
    }
    let mut validation_warnings = validation
        .issues
        .iter()
        .filter(|issue| issue.severity == ConfigIssueSeverity::Warning)
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    let agent_config = config
        .agents
        .iter()
        .find(|candidate| candidate.id == *agent)
        .ok_or_else(|| CliError {
            message: format!("agent '{agent}' is not declared in config"),
        })?;

    if let Some(parent) = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| CliError {
            message: format!(
                "failed to create state directory '{}': {error}",
                parent.display()
            ),
        })?;
    }
    let db = WarderDb::open(&db_path).map_err(db_error)?;
    db.migrate().map_err(db_error)?;

    let session_id = generate_session_id();
    let snapshot_status =
        planned_snapshot_status(&config, environment, &session_id, snapshot_root.as_deref())?;
    append_snapshot_status_warning(&snapshot_status, &mut validation_warnings);
    let landlock_plan = planned_landlock_restrictions(&config, environment);
    let landlock_status = landlock_status_from_plan(&landlock_plan.status);
    if let LandlockStatus::Degraded(message) | LandlockStatus::Unsupported(message) =
        &landlock_status
    {
        push_unique(&mut validation_warnings, message.clone());
    }
    if config.network.journal {
        if let warder_journal::EbpfNetworkJournalAttachStatus::Unavailable(message) =
            planned_ebpf_network_journal_attach(&config, environment).status
        {
            push_unique(&mut validation_warnings, message);
        }
    }
    append_non_enforcing_network_policy_warning(&config, &mut validation_warnings);
    let session = SessionRecord {
        id: session_id.clone(),
        agent_id: agent_config.id.clone(),
        agent_label: agent_config.label.clone(),
        agent_profile: effective_agent_profile_for_run(
            agent_config.profile.as_deref(),
            &agent_config.command,
            command,
        ),
        command: command.clone(),
        protected_zone_ids: config.zones.iter().map(|zone| zone.id.clone()).collect(),
        status: if *launch {
            SessionStatus::Starting
        } else {
            SessionStatus::Recorded
        },
        exit_code: None,
        started_at: now,
        ended_at: None,
        root_pid: None,
        cgroup_path: None,
        cgroup_status: cgroup_status_from_requirement(config.enforcement.cgroups),
        landlock_status,
        snapshot_status,
        dependency_file_changes: Vec::new(),
        degraded_reasons: {
            if let Some(profile) = effective_agent_profile_for_run(
                agent_config.profile.as_deref(),
                &agent_config.command,
                command,
            ) {
                append_openclaw_preflight_warnings(&profile, command, &mut validation_warnings);
            }
            validation_warnings.clone()
        },
    };
    db.create_session(&session).map_err(db_error)?;

    Ok(RunSessionOutcome {
        session_id,
        validation_warnings,
    })
}

pub fn prepare_supervised_run(
    command: &CliCommand,
    environment: &EnvironmentSupport,
    now: SystemTime,
    cgroup_root: impl Into<PathBuf>,
    root_pid: u32,
) -> Result<RunSessionOutcome, CliError> {
    let outcome = create_run_session(command, environment, now)?;
    let CliCommand::Run { db, .. } = command else {
        return err("prepare_supervised_run requires a run command");
    };
    let db_path = db.clone().unwrap_or_else(default_db_path);
    let tagger = CgroupTagger::new(cgroup_root);
    let tag_result = tagger
        .tag_pid(&outcome.session_id, root_pid)
        .map_err(|error| CliError {
            message: error.message,
        })?;
    apply_cgroup_tag_result(db_path, &outcome.session_id, tag_result)?;
    Ok(outcome)
}

pub fn apply_cgroup_tag_result(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    result: CgroupTagResult,
) -> Result<(), CliError> {
    let db = WarderDb::open(db_path.into()).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    let mut session = db
        .get_session(session_id)
        .map_err(db_error)?
        .ok_or_else(|| CliError {
            message: format!("session '{session_id}' was not found"),
        })?;

    match result.status {
        CgroupTagStatus::Tagged => {
            session.cgroup_path = result.cgroup_path;
            session.cgroup_status = CgroupStatus::Tagged;
        }
        CgroupTagStatus::Unsupported(message) => {
            session.cgroup_path = None;
            session.cgroup_status = CgroupStatus::Unsupported(message.clone());
            if !session
                .degraded_reasons
                .iter()
                .any(|current| current == &message)
            {
                session.degraded_reasons.push(message);
            }
        }
    }

    db.update_session(&session).map_err(db_error)
}

pub fn launch_supervised_run(
    command: &CliCommand,
    environment: &EnvironmentSupport,
    started_at: SystemTime,
) -> Result<LaunchOutcome, CliError> {
    let CliCommand::Run {
        config,
        db,
        cgroup_root,
        launch,
        command: child_command,
        ..
    } = command
    else {
        return err("launch_supervised_run requires a run command");
    };
    if !launch {
        return err("launch_supervised_run requires --launch");
    }
    let (program, args) = child_command.split_first().ok_or_else(|| CliError {
        message: "run requires a command to launch".to_string(),
    })?;
    let config_path = config.as_ref().ok_or_else(|| CliError {
        message: "run requires --config before a command can be launched".to_string(),
    })?;
    let config = load_config(config_path)?;
    let cgroup_plan = planned_launch_cgroup_tagging(&config, cgroup_root.as_ref());
    if let LaunchCgroupTagPlan::Blocked(message) = &cgroup_plan {
        return err(message.clone());
    }
    let landlock_plan = planned_landlock_restrictions(&config, environment);
    let landlock_status = landlock_plan.status.clone();
    if let LandlockPlanStatus::Blocked(message) = landlock_status {
        return err(message);
    }
    let outcome = create_run_session(command, environment, started_at)?;
    let db_path = db.clone().unwrap_or_else(default_db_path);
    let mut validation_warnings = outcome.validation_warnings;
    let dependency_roots = dependency_zone_roots(&config);
    let before_dependency_files = match scan_dependency_files(&dependency_roots) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let message = error.message;
            add_session_degraded_reason(&db_path, &outcome.session_id, message.clone())?;
            if !validation_warnings
                .iter()
                .any(|warning| warning == &message)
            {
                validation_warnings.push(message);
            }
            Vec::new()
        }
    };
    let prepared_landlock = prepare_landlock_for_launch(&landlock_plan).map_err(|error| {
        let message = error.message;
        let _ = fail_session(&db_path, &outcome.session_id, message.clone());
        CliError { message }
    })?;
    if let PreparedLandlock::Degraded(message) = &prepared_landlock {
        set_session_landlock_status(
            &db_path,
            &outcome.session_id,
            LandlockStatus::Degraded(message.clone()),
        )?;
        add_session_degraded_reason(&db_path, &outcome.session_id, message.clone())?;
        if !validation_warnings.iter().any(|warning| warning == message) {
            validation_warnings.push(message.clone());
        }
    }
    if let LaunchCgroupTagPlan::Skip { status, reason } = &cgroup_plan {
        set_session_cgroup_status(&db_path, &outcome.session_id, status.clone())?;
        if let Some(reason) = reason {
            add_session_degraded_reason(&db_path, &outcome.session_id, reason.clone())?;
            if !validation_warnings.iter().any(|warning| warning == reason) {
                validation_warnings.push(reason.clone());
            }
        }
    }
    let mut inotify_watcher = match start_inotify_file_journal(&config) {
        Ok(watcher) => Some(watcher),
        Err(error) => {
            let message = error.message;
            add_session_degraded_reason(&db_path, &outcome.session_id, message.clone())?;
            if !validation_warnings
                .iter()
                .any(|warning| warning == &message)
            {
                validation_warnings.push(message);
            }
            None
        }
    };
    let mut ebpf_collector = if config.network.journal {
        match start_ebpf_file_journal(&config, environment) {
            Ok(collector) => Some(collector),
            Err(error) => {
                let message = error.message;
                add_session_degraded_reason(&db_path, &outcome.session_id, message.clone())?;
                if !validation_warnings
                    .iter()
                    .any(|warning| warning == &message)
                {
                    validation_warnings.push(message);
                }
                None
            }
        }
    } else {
        None
    };
    let mut ebpf_network_collector = if config.network.journal {
        match start_ebpf_network_journal(&config, environment) {
            Ok(collector) => Some(collector),
            Err(error) => {
                let message = error.message;
                add_session_degraded_reason(&db_path, &outcome.session_id, message.clone())?;
                if !validation_warnings
                    .iter()
                    .any(|warning| warning == &message)
                {
                    validation_warnings.push(message);
                }
                None
            }
        }
    } else {
        None
    };

    let mut child_command = Command::new(program);
    child_command.args(args);
    configure_landlock_child_setup(&mut child_command, prepared_landlock);
    let mut child = match child_command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let message = format!("failed to launch supervised command '{program}': {error}");
            fail_session(&db_path, &outcome.session_id, message.clone())?;
            return err(message);
        }
    };
    if landlock_plan.status == LandlockPlanStatus::Apply {
        set_session_landlock_status(&db_path, &outcome.session_id, LandlockStatus::Applied)?;
    }
    let child_pid = child.id();
    set_session_root_pid(&db_path, &outcome.session_id, child_pid)?;
    let mut procfs_network_reader = if config.network.journal {
        Some(ProcfsNetworkSocketReader::new(child_pid))
    } else {
        None
    };
    if let LaunchCgroupTagPlan::Tag { root } = &cgroup_plan {
        let tagger = CgroupTagger::new(root);
        let tag_result = match tagger.tag_pid(&outcome.session_id, child_pid) {
            Ok(result) => result,
            Err(error) => {
                let message = error.message;
                let _ = child.kill();
                let _ = child.wait();
                fail_session(&db_path, &outcome.session_id, message.clone())?;
                return err(message);
            }
        };
        apply_cgroup_tag_result(&db_path, &outcome.session_id, tag_result)?;
    }
    let exit_code = wait_for_child_with_file_journals(
        &db_path,
        &outcome.session_id,
        &mut child,
        inotify_watcher.as_mut(),
        ebpf_collector.as_mut(),
        ebpf_network_collector.as_mut(),
        procfs_network_reader.as_mut(),
    )?;
    match scan_dependency_files(&dependency_roots) {
        Ok(after_dependency_files) => {
            let changes =
                diff_dependency_file_snapshots(&before_dependency_files, &after_dependency_files);
            set_session_dependency_file_changes(&db_path, &outcome.session_id, changes)?;
        }
        Err(error) => {
            let message = error.message;
            add_session_degraded_reason(&db_path, &outcome.session_id, message.clone())?;
            if !validation_warnings
                .iter()
                .any(|warning| warning == &message)
            {
                validation_warnings.push(message);
            }
        }
    }
    persist_inotify_file_journal_events(&db_path, &outcome.session_id, inotify_watcher.as_mut())?;
    persist_ebpf_file_journal_events(&db_path, &outcome.session_id, ebpf_collector.as_mut())?;
    persist_ebpf_network_journal_events(
        &db_path,
        &outcome.session_id,
        ebpf_network_collector.as_mut(),
    )?;
    persist_procfs_network_journal_events(
        &db_path,
        &outcome.session_id,
        procfs_network_reader.as_mut(),
    )?;

    Ok(LaunchOutcome {
        session_id: outcome.session_id,
        exit_code,
        validation_warnings,
    })
}

fn parse_run(args: Vec<String>) -> Result<CliCommand, CliError> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| CliError {
            message: "run requires '--' before the supervised command".to_string(),
        })?;
    let options = &args[..separator];
    let command = args[(separator + 1)..].to_vec();
    if command.is_empty() {
        return err("run requires a command after '--'");
    }

    let mut config = None;
    let mut db = None;
    let mut cgroup_root = None;
    let mut snapshot_root = None;
    let mut launch = false;
    let mut agent = None;
    let mut index = 0;
    while index < options.len() {
        match options[index].as_str() {
            "--config" => {
                config = Some(PathBuf::from(value_after(options, index, "--config")?));
                index += 2;
            }
            "--db" => {
                db = Some(PathBuf::from(value_after(options, index, "--db")?));
                index += 2;
            }
            "--cgroup-root" => {
                cgroup_root = Some(PathBuf::from(value_after(options, index, "--cgroup-root")?));
                index += 2;
            }
            "--snapshot-root" => {
                snapshot_root = Some(PathBuf::from(value_after(
                    options,
                    index,
                    "--snapshot-root",
                )?));
                index += 2;
            }
            "--launch" => {
                launch = true;
                index += 1;
            }
            "--agent" => {
                agent = Some(value_after(options, index, "--agent")?);
                index += 2;
            }
            unknown => return err(format!("unknown run option '{unknown}'")),
        }
    }

    let Some(agent) = agent else {
        return err("run requires --agent so the session is clearly tagged");
    };

    Ok(CliCommand::Run {
        config,
        db,
        cgroup_root,
        snapshot_root,
        launch,
        agent,
        command,
    })
}

fn parse_journal(args: Vec<String>) -> Result<CliCommand, CliError> {
    let mut db = None;
    let mut session_id = None;
    let mut kind = JournalKind::File;
    let mut selected_kind = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                db = Some(PathBuf::from(value_after(&args, index, "--db")?));
                index += 2;
            }
            "--session" => {
                session_id = Some(value_after(&args, index, "--session")?);
                index += 2;
            }
            "--file" => {
                if selected_kind.is_some() && selected_kind != Some(JournalKind::File) {
                    return err(
                        "journal selectors --file, --network, and --all cannot be combined",
                    );
                }
                selected_kind = Some(JournalKind::File);
                kind = JournalKind::File;
                index += 1;
            }
            "--network" => {
                if selected_kind.is_some() && selected_kind != Some(JournalKind::Network) {
                    return err(
                        "journal selectors --file, --network, and --all cannot be combined",
                    );
                }
                selected_kind = Some(JournalKind::Network);
                kind = JournalKind::Network;
                index += 1;
            }
            "--all" => {
                if selected_kind.is_some() && selected_kind != Some(JournalKind::All) {
                    return err(
                        "journal selectors --file, --network, and --all cannot be combined",
                    );
                }
                selected_kind = Some(JournalKind::All);
                kind = JournalKind::All;
                index += 1;
            }
            unknown => return err(format!("unknown journal option '{unknown}'")),
        }
    }

    Ok(CliCommand::Journal {
        db,
        session_id,
        kind,
    })
}

fn parse_snapshot(args: Vec<String>) -> Result<CliCommand, CliError> {
    let mut session_id = None;
    let mut config = None;
    let mut snapshot_root = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--session" => {
                session_id = Some(value_after(&args, index, "--session")?);
                index += 2;
            }
            "--config" => {
                config = Some(PathBuf::from(value_after(&args, index, "--config")?));
                index += 2;
            }
            "--snapshot-root" => {
                snapshot_root = Some(PathBuf::from(value_after(&args, index, "--snapshot-root")?));
                index += 2;
            }
            unknown => return err(format!("unknown snapshot option '{unknown}'")),
        }
    }
    let Some(session_id) = session_id else {
        return err("snapshot requires --session");
    };
    Ok(CliCommand::Snapshot {
        session_id,
        config,
        snapshot_root,
    })
}

fn parse_receipt(args: Vec<String>) -> Result<CliCommand, CliError> {
    let mut db = None;
    let mut session_id = None;
    let mut format = ReceiptFormat::Text;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                db = Some(PathBuf::from(value_after(&args, index, "--db")?));
                index += 2;
            }
            "--session" => {
                session_id = Some(value_after(&args, index, "--session")?);
                index += 2;
            }
            "--format" => {
                format = parse_receipt_format(&value_after(&args, index, "--format")?)?;
                index += 2;
            }
            unknown => return err(format!("unknown receipt option '{unknown}'")),
        }
    }

    let Some(session_id) = session_id else {
        return err("receipt requires --session");
    };

    Ok(CliCommand::Receipt {
        db,
        session_id,
        format,
    })
}

fn parse_profiles(args: Vec<String>) -> Result<CliCommand, CliError> {
    let mut format = ProfileCatalogFormat::Text;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = parse_profile_catalog_format(&value_after(&args, index, "--format")?)?;
                index += 2;
            }
            unknown => return err(format!("unknown profiles option '{unknown}'")),
        }
    }

    Ok(CliCommand::Profiles { format })
}

fn parse_init(args: Vec<String>) -> Result<CliCommand, CliError> {
    let mut output = PathBuf::from("warder.toml");
    let mut profile = "codex-cli".to_string();
    let mut protected_paths = Vec::new();
    let mut agent_command = None;
    let mut force = false;
    let mut print = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                output = PathBuf::from(value_after(&args, index, "--output")?);
                index += 2;
            }
            "--profile" => {
                profile = value_after(&args, index, "--profile")?;
                index += 2;
            }
            "--protected-path" => {
                protected_paths.push(PathBuf::from(value_after(
                    &args,
                    index,
                    "--protected-path",
                )?));
                index += 2;
            }
            "--agent-command" => {
                agent_command = Some(value_after(&args, index, "--agent-command")?);
                index += 2;
            }
            "--force" => {
                force = true;
                index += 1;
            }
            "--print" => {
                print = true;
                index += 1;
            }
            unknown => return err(format!("unknown init option '{unknown}'")),
        }
    }

    if protected_paths.is_empty() {
        return err("init requires at least one --protected-path");
    }
    if print && force {
        return err("init --print cannot be combined with --force");
    }

    Ok(CliCommand::Init {
        output,
        profile,
        protected_paths,
        agent_command,
        force,
        print,
    })
}

fn parse_revert(args: Vec<String>) -> Result<CliCommand, CliError> {
    let mut snapshot_id = None;
    let mut snapshot_root = None;
    let mut db = None;
    let mut session_id = None;
    let mut preview = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--snapshot" => {
                snapshot_id = Some(value_after(&args, index, "--snapshot")?);
                index += 2;
            }
            "--snapshot-root" => {
                snapshot_root = Some(PathBuf::from(value_after(&args, index, "--snapshot-root")?));
                index += 2;
            }
            "--db" => {
                db = Some(PathBuf::from(value_after(&args, index, "--db")?));
                index += 2;
            }
            "--session" => {
                session_id = Some(value_after(&args, index, "--session")?);
                index += 2;
            }
            "--preview" => {
                preview = true;
                index += 1;
            }
            unknown => return err(format!("unknown revert option '{unknown}'")),
        }
    }
    let Some(snapshot_id) = snapshot_id else {
        return err("revert requires --snapshot");
    };
    match (&db, &session_id) {
        (Some(_), None) => return err("revert requires --session when --db is provided"),
        (None, Some(_)) => return err("revert requires --db when --session is provided"),
        _ => {}
    }
    if preview && db.is_some() {
        return err("revert --preview cannot be combined with --db/--session because no restore is recorded");
    }
    Ok(CliCommand::Revert {
        snapshot_id,
        snapshot_root,
        db,
        session_id,
        preview,
    })
}

fn parse_receipt_format(value: &str) -> Result<ReceiptFormat, CliError> {
    match value {
        "text" => Ok(ReceiptFormat::Text),
        "json" => Ok(ReceiptFormat::Json),
        unknown => err(format!("unknown receipt format '{unknown}'")),
    }
}

fn parse_profile_catalog_format(value: &str) -> Result<ProfileCatalogFormat, CliError> {
    match value {
        "text" => Ok(ProfileCatalogFormat::Text),
        "json" => Ok(ProfileCatalogFormat::Json),
        unknown => err(format!("unknown profiles format '{unknown}'")),
    }
}

fn parse_dry_run(args: Vec<String>) -> Result<CliCommand, CliError> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| CliError {
            message: "dry-run requires '--' before the supervised command".to_string(),
        })?;
    let options = &args[..separator];
    let command = args[(separator + 1)..].to_vec();
    if command.is_empty() {
        return err("dry-run requires a command after '--'");
    }

    let mut config = None;
    let mut agent = None;
    let mut index = 0;
    while index < options.len() {
        match options[index].as_str() {
            "--config" => {
                config = Some(PathBuf::from(value_after(options, index, "--config")?));
                index += 2;
            }
            "--agent" => {
                agent = Some(value_after(options, index, "--agent")?);
                index += 2;
            }
            unknown => return err(format!("unknown dry-run option '{unknown}'")),
        }
    }

    let Some(config) = config else {
        return err("dry-run requires --config");
    };
    let Some(agent) = agent else {
        return err("dry-run requires --agent so the session is clearly tagged");
    };

    Ok(CliCommand::DryRun {
        config,
        agent,
        command,
    })
}

fn parse_start(args: Vec<String>) -> Result<CliCommand, CliError> {
    if args.is_empty() {
        return Ok(CliCommand::Start { config: None });
    }
    parse_required_value(args, "--config").map(|config| CliCommand::Start {
        config: Some(PathBuf::from(config)),
    })
}

fn parse_required_value(args: Vec<String>, flag: &str) -> Result<String, CliError> {
    if args.len() != 2 || args[0] != flag {
        return err(format!("expected {flag} <value>"));
    }
    Ok(args[1].clone())
}

fn value_after(options: &[String], index: usize, flag: &str) -> Result<String, CliError> {
    options.get(index + 1).cloned().ok_or_else(|| CliError {
        message: format!("{flag} requires a value"),
    })
}

fn err<T>(message: impl Into<String>) -> Result<T, CliError> {
    Err(CliError {
        message: message.into(),
    })
}

fn push_unique(messages: &mut Vec<String>, message: String) {
    if !messages.iter().any(|current| current == &message) {
        messages.push(message);
    }
}

fn append_snapshot_plan_validation(
    plan: &SnapshotPlan,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    match plan {
        SnapshotPlan::Block(message) => push_unique(errors, message.clone()),
        SnapshotPlan::Skip(message) => push_unique(warnings, message.clone()),
        SnapshotPlan::Create { .. } | SnapshotPlan::NotRequested => {}
    }
}

fn append_snapshot_status_warning(status: &SnapshotStatus, warnings: &mut Vec<String>) {
    if let SnapshotStatus::Failed(message) = status {
        push_unique(warnings, message.clone());
    }
}

fn db_error(error: warder_db::DbError) -> CliError {
    CliError {
        message: format!("database error: {error:?}"),
    }
}

fn runtime_file_error(error: warder_daemon::DaemonRuntimeFileError) -> CliError {
    CliError {
        message: format!("daemon runtime error: {}", error.message),
    }
}

fn load_daemon_policy_snapshot(
    config_path: Option<&PathBuf>,
) -> Result<Option<warder_daemon::DaemonPolicySnapshot>, CliError> {
    let Some(config_path) = config_path else {
        return Ok(None);
    };
    let config = load_config(config_path)?;
    Ok(Some(warder_daemon::DaemonPolicySnapshot {
        zone_count: config.zones.len(),
        agent_count: config.agents.len(),
        network_journal: config.network.journal,
    }))
}

fn validate_daemon_start_config(config_path: Option<&PathBuf>) -> Result<Vec<String>, CliError> {
    validate_daemon_start_config_with_environment(
        config_path,
        &environment_support_from_probe(warder_daemon::probe_current_host()),
    )
}

fn validate_daemon_start_config_with_environment(
    config_path: Option<&PathBuf>,
    environment: &EnvironmentSupport,
) -> Result<Vec<String>, CliError> {
    let Some(config_path) = config_path else {
        return Ok(Vec::new());
    };
    let config = load_config(config_path)?;
    let validation = config.validate(environment);
    let mut errors = validation
        .issues
        .iter()
        .filter(|issue| issue.severity == ConfigIssueSeverity::Error)
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    let snapshot_plan = planned_snapshot_plan(&config, environment);
    append_snapshot_plan_validation(&snapshot_plan, &mut errors, &mut Vec::new());
    if !errors.is_empty() {
        return err(format!("config validation failed: {}", errors.join("; ")));
    }
    let mut warnings = validation
        .issues
        .iter()
        .filter(|issue| issue.severity == ConfigIssueSeverity::Warning)
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    if config.network.journal {
        if let warder_journal::EbpfNetworkJournalAttachStatus::Unavailable(message) =
            planned_ebpf_network_journal_attach(&config, environment).status
        {
            push_unique(&mut warnings, message);
        }
    }
    append_snapshot_plan_validation(&snapshot_plan, &mut Vec::new(), &mut warnings);
    Ok(warnings)
}

pub fn environment_support_from_probe(probe: warder_daemon::CapabilityProbe) -> EnvironmentSupport {
    let report = warder_daemon::DaemonCapabilityReport::from_probe(probe.clone());
    EnvironmentSupport {
        landlock: probe.landlock == warder_daemon::CapabilityState::Available,
        cgroups: probe.cgroups == warder_daemon::CapabilityState::Available,
        ebpf: probe.ebpf == warder_daemon::CapabilityState::Available,
        snapshot_backends: report
            .snapshot_backends
            .into_iter()
            .map(|backend| match backend {
                warder_core::SnapshotBackend::Btrfs => warder_config::SnapshotBackend::Btrfs,
                warder_core::SnapshotBackend::OverlayFs => {
                    warder_config::SnapshotBackend::OverlayFs
                }
            })
            .collect(),
    }
}

pub fn assess_host_readiness(probe: warder_daemon::CapabilityProbe) -> HostReadinessReport {
    let mut blocked_reasons = Vec::new();
    let mut degraded_reasons = Vec::new();

    if let warder_daemon::CapabilityState::Unavailable(reason) = probe.landlock {
        blocked_reasons.push(format!("Landlock unavailable: {reason}"));
    }
    if let warder_daemon::CapabilityState::Unavailable(reason) = probe.cgroups {
        blocked_reasons.push(format!("cgroups unavailable: {reason}"));
    }
    if let warder_daemon::CapabilityState::Unavailable(reason) = probe.btrfs {
        degraded_reasons.push(format!("Btrfs snapshots unavailable: {reason}"));
    }
    if let warder_daemon::CapabilityState::Unavailable(reason) = probe.ebpf {
        degraded_reasons.push(format!("live eBPF journals unavailable: {reason}"));
    }

    let level = if !blocked_reasons.is_empty() {
        ReadinessLevel::Blocked
    } else if !degraded_reasons.is_empty() {
        ReadinessLevel::Degraded
    } else {
        ReadinessLevel::Strong
    };

    HostReadinessReport {
        level,
        blocked_reasons,
        degraded_reasons,
    }
}

pub fn render_host_readiness(report: &HostReadinessReport) -> String {
    let mut lines = vec![format!(
        "host readiness: {}",
        readiness_level_label(report.level)
    )];
    append_reason_list("blocked reasons", &report.blocked_reasons, &mut lines);
    append_reason_list("degraded reasons", &report.degraded_reasons, &mut lines);
    lines.join("\n")
}

pub fn render_host_readiness_from_probe(probe: warder_daemon::CapabilityProbe) -> String {
    render_host_readiness(&assess_host_readiness(probe))
}

pub fn default_host_diagnostic_paths() -> HostDiagnosticPaths {
    HostDiagnosticPaths {
        proc_self_fd: PathBuf::from("/proc/self/fd"),
        proc_self_net_tcp: PathBuf::from("/proc/self/net/tcp"),
        proc_self_stat: PathBuf::from("/proc/self/stat"),
        cgroup_procs: PathBuf::from("/sys/fs/cgroup/cgroup.procs"),
        docker_env: PathBuf::from("/.dockerenv"),
        container_env: PathBuf::from("/run/.containerenv"),
    }
}

pub fn assess_host_doctor(
    probe: warder_daemon::CapabilityProbe,
    paths: &HostDiagnosticPaths,
) -> HostDoctorReport {
    let readiness = assess_host_readiness(probe);
    let mut diagnostics = Vec::new();

    let container_hint = std::env::var("container")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("container={value}"))
        .or_else(|| {
            paths
                .docker_env
                .exists()
                .then(|| format!("{} exists", paths.docker_env.display()))
        })
        .or_else(|| {
            paths
                .container_env
                .exists()
                .then(|| format!("{} exists", paths.container_env.display()))
        });
    diagnostics.push(match container_hint {
        Some(hint) => HostDiagnostic {
            label: "container detection".to_string(),
            status: HostDiagnosticStatus::Warning,
            message: format!("{hint}; process-tree and host-path visibility may be incomplete"),
        },
        None => HostDiagnostic {
            label: "container detection".to_string(),
            status: HostDiagnosticStatus::Ok,
            message: "no common container marker detected".to_string(),
        },
    });

    diagnostics.push(read_dir_diagnostic(
        "proc fd visibility",
        &paths.proc_self_fd,
        "current process file descriptors are readable",
        "current process file descriptors are not readable; procfs journal attribution may degrade",
    ));
    diagnostics.push(read_file_diagnostic(
        "proc network visibility",
        &paths.proc_self_net_tcp,
        "current network table is readable",
        "current network table is not readable; connected-socket snapshots may degrade",
    ));
    diagnostics.push(read_file_diagnostic(
        "proc process metadata",
        &paths.proc_self_stat,
        "current process metadata is readable",
        "current process metadata is not readable; descendant process attribution may degrade",
    ));
    diagnostics.push(path_presence_diagnostic(
        "cgroup launch tagging",
        &paths.cgroup_procs,
        "cgroup v2 root is visible; use --cgroup-root with a delegated writable subtree for launch tagging",
        "cgroup v2 root is not visible; required cgroup tagging will block launch",
    ));

    HostDoctorReport {
        readiness,
        diagnostics,
    }
}

pub fn render_host_doctor(report: &HostDoctorReport) -> String {
    let mut lines = vec![render_host_readiness(&report.readiness)];
    lines.push("host diagnostics:".to_string());
    for diagnostic in &report.diagnostics {
        lines.push(format!(
            "- {}: {}: {}",
            diagnostic.label,
            host_diagnostic_status_label(diagnostic.status),
            diagnostic.message
        ));
    }
    lines.join("\n")
}

pub fn render_host_doctor_from_probe(probe: warder_daemon::CapabilityProbe) -> String {
    render_host_doctor(&assess_host_doctor(probe, &default_host_diagnostic_paths()))
}

fn read_dir_diagnostic(
    label: &str,
    path: &Path,
    ok_message: &str,
    warning_message: &str,
) -> HostDiagnostic {
    match std::fs::read_dir(path) {
        Ok(_) => HostDiagnostic {
            label: label.to_string(),
            status: HostDiagnosticStatus::Ok,
            message: ok_message.to_string(),
        },
        Err(error) => HostDiagnostic {
            label: label.to_string(),
            status: HostDiagnosticStatus::Warning,
            message: format!("{warning_message}: {error}"),
        },
    }
}

fn read_file_diagnostic(
    label: &str,
    path: &Path,
    ok_message: &str,
    warning_message: &str,
) -> HostDiagnostic {
    match std::fs::read_to_string(path) {
        Ok(_) => HostDiagnostic {
            label: label.to_string(),
            status: HostDiagnosticStatus::Ok,
            message: ok_message.to_string(),
        },
        Err(error) => HostDiagnostic {
            label: label.to_string(),
            status: HostDiagnosticStatus::Warning,
            message: format!("{warning_message}: {error}"),
        },
    }
}

fn path_presence_diagnostic(
    label: &str,
    path: &Path,
    ok_message: &str,
    warning_message: &str,
) -> HostDiagnostic {
    if path.exists() {
        HostDiagnostic {
            label: label.to_string(),
            status: HostDiagnosticStatus::Ok,
            message: ok_message.to_string(),
        }
    } else {
        HostDiagnostic {
            label: label.to_string(),
            status: HostDiagnosticStatus::Warning,
            message: warning_message.to_string(),
        }
    }
}

fn host_diagnostic_status_label(status: HostDiagnosticStatus) -> &'static str {
    match status {
        HostDiagnosticStatus::Ok => "ok",
        HostDiagnosticStatus::Warning => "warning",
    }
}

fn assess_session_readiness(session: &SessionRecord) -> HostReadinessReport {
    let mut blocked_reasons = Vec::new();
    let mut degraded_reasons = session.degraded_reasons.clone();

    match &session.cgroup_status {
        CgroupStatus::Unsupported(reason) => {
            push_unique(
                &mut blocked_reasons,
                format!("cgroups unavailable: {reason}"),
            );
        }
        CgroupStatus::Degraded(reason) => {
            push_unique(&mut degraded_reasons, reason.clone());
        }
        _ => {}
    }
    match &session.landlock_status {
        LandlockStatus::Unsupported(reason) => {
            push_unique(
                &mut blocked_reasons,
                format!("Landlock unavailable: {reason}"),
            );
        }
        LandlockStatus::Degraded(reason) => {
            push_unique(&mut degraded_reasons, reason.clone());
        }
        _ => {}
    }
    if let SnapshotStatus::Failed(reason) = &session.snapshot_status {
        if session.status == SessionStatus::Failed {
            push_unique(
                &mut blocked_reasons,
                format!("snapshot unavailable: {reason}"),
            );
        } else {
            push_unique(&mut degraded_reasons, reason.clone());
        }
    }

    let level = if !blocked_reasons.is_empty() {
        ReadinessLevel::Blocked
    } else if !degraded_reasons.is_empty() {
        ReadinessLevel::Degraded
    } else {
        ReadinessLevel::Strong
    };

    HostReadinessReport {
        level,
        blocked_reasons,
        degraded_reasons,
    }
}

pub fn assess_environment_readiness(environment: &EnvironmentSupport) -> HostReadinessReport {
    let mut blocked_reasons = Vec::new();
    let mut degraded_reasons = Vec::new();

    if !environment.landlock {
        blocked_reasons.push("Landlock unavailable".to_string());
    }
    if !environment.cgroups {
        blocked_reasons.push("cgroups unavailable".to_string());
    }
    if environment.snapshot_backends.is_empty() {
        degraded_reasons.push("Btrfs snapshots unavailable".to_string());
    }
    if !environment.ebpf {
        degraded_reasons.push("live eBPF journals unavailable".to_string());
    }

    let level = if !blocked_reasons.is_empty() {
        ReadinessLevel::Blocked
    } else if !degraded_reasons.is_empty() {
        ReadinessLevel::Degraded
    } else {
        ReadinessLevel::Strong
    };

    HostReadinessReport {
        level,
        blocked_reasons,
        degraded_reasons,
    }
}

pub fn render_pre_launch_readiness(environment: &EnvironmentSupport) -> String {
    render_host_readiness(&assess_environment_readiness(environment))
}

fn readiness_level_label(level: ReadinessLevel) -> &'static str {
    match level {
        ReadinessLevel::Strong => "strong",
        ReadinessLevel::Degraded => "degraded",
        ReadinessLevel::Blocked => "blocked",
    }
}

fn append_reason_list(label: &str, reasons: &[String], lines: &mut Vec<String>) {
    if reasons.is_empty() {
        lines.push(format!("{label}: none"));
    } else {
        lines.push(format!("{label}:"));
        lines.extend(reasons.iter().map(|reason| format!("- {reason}")));
    }
}

fn verify_launched_daemon_runtime(
    runtime_path: &PathBuf,
    launched: &LaunchedDaemon,
    launcher: &impl DaemonLauncher,
) -> Result<warder_daemon::DaemonRuntimeReport, CliError> {
    let store = warder_daemon::DaemonRuntimeFile::new(runtime_path);
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if !launcher.is_alive(launched.pid) {
            return err(format!(
                "daemon process {} exited before runtime state was written",
                launched.pid
            ));
        }

        let report = store.read_status().map_err(runtime_file_error)?;
        if report.status == warder_daemon::DaemonRuntimeStatus::Running {
            if report.pid == Some(launched.pid)
                && report.socket_path == Some(launched.socket_path.clone())
            {
                return Ok(report);
            }
            return err(format!(
                "daemon runtime state did not match launched process {}; found pid {}",
                launched.pid,
                optional_pid_label(report.pid)
            ));
        }

        if Instant::now() >= deadline {
            return err(format!(
                "timed out waiting for daemon process {} to write runtime state",
                launched.pid
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn render_daemon_start_report(
    report: &warder_daemon::DaemonRuntimeReport,
    validation_warnings: &[String],
) -> String {
    let mut rendered = warder_daemon::render_daemon_runtime_report(report);
    for warning in validation_warnings {
        rendered.push('\n');
        rendered.push_str(&format!("warning: {warning}"));
    }
    rendered
}

fn session_status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Recorded => "recorded",
        SessionStatus::Starting => "starting",
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Failed => "failed",
        SessionStatus::Reverted => "reverted",
    }
}

fn optional_pid_label(pid: Option<u32>) -> String {
    pid.map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn optional_exit_code_label(exit_code: Option<i32>) -> String {
    exit_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn cgroup_status_label(status: &CgroupStatus, path: Option<&PathBuf>) -> String {
    match status {
        CgroupStatus::NotRequested => "not requested".to_string(),
        CgroupStatus::Pending => "pending".to_string(),
        CgroupStatus::Tagged => match path {
            Some(path) => format!("tagged ({})", path.display()),
            None => "tagged".to_string(),
        },
        CgroupStatus::Degraded(message) => format!("degraded: {message}"),
        CgroupStatus::Unsupported(message) => format!("unsupported: {message}"),
    }
}

fn structured_cgroup_status(
    status: &CgroupStatus,
    path: Option<&PathBuf>,
) -> StructuredReceiptStatus {
    match status {
        CgroupStatus::NotRequested => StructuredReceiptStatus {
            status: "not_requested",
            message: None,
            path: None,
            backend: None,
            snapshot_id: None,
        },
        CgroupStatus::Pending => StructuredReceiptStatus {
            status: "pending",
            message: None,
            path: path.map(|path| path.display().to_string()),
            backend: None,
            snapshot_id: None,
        },
        CgroupStatus::Tagged => StructuredReceiptStatus {
            status: "tagged",
            message: None,
            path: path.map(|path| path.display().to_string()),
            backend: None,
            snapshot_id: None,
        },
        CgroupStatus::Degraded(message) => StructuredReceiptStatus {
            status: "degraded",
            message: Some(message.clone()),
            path: path.map(|path| path.display().to_string()),
            backend: None,
            snapshot_id: None,
        },
        CgroupStatus::Unsupported(message) => StructuredReceiptStatus {
            status: "unsupported",
            message: Some(message.clone()),
            path: path.map(|path| path.display().to_string()),
            backend: None,
            snapshot_id: None,
        },
    }
}

fn landlock_status_label(status: &LandlockStatus) -> String {
    match status {
        LandlockStatus::NotRequested => "not requested".to_string(),
        LandlockStatus::Pending => "pending".to_string(),
        LandlockStatus::Applied => "applied".to_string(),
        LandlockStatus::Degraded(message) => format!("degraded: {message}"),
        LandlockStatus::Unsupported(message) => format!("unsupported: {message}"),
    }
}

fn structured_landlock_status(status: &LandlockStatus) -> StructuredReceiptStatus {
    match status {
        LandlockStatus::NotRequested => StructuredReceiptStatus {
            status: "not_requested",
            message: None,
            path: None,
            backend: None,
            snapshot_id: None,
        },
        LandlockStatus::Pending => StructuredReceiptStatus {
            status: "pending",
            message: None,
            path: None,
            backend: None,
            snapshot_id: None,
        },
        LandlockStatus::Applied => StructuredReceiptStatus {
            status: "applied",
            message: None,
            path: None,
            backend: None,
            snapshot_id: None,
        },
        LandlockStatus::Degraded(message) => StructuredReceiptStatus {
            status: "degraded",
            message: Some(message.clone()),
            path: None,
            backend: None,
            snapshot_id: None,
        },
        LandlockStatus::Unsupported(message) => StructuredReceiptStatus {
            status: "unsupported",
            message: Some(message.clone()),
            path: None,
            backend: None,
            snapshot_id: None,
        },
    }
}

fn snapshot_status_label(status: &SnapshotStatus) -> String {
    match status {
        SnapshotStatus::NotRequested => "not requested".to_string(),
        SnapshotStatus::Pending => "pending".to_string(),
        SnapshotStatus::Created {
            backend,
            snapshot_id,
            ..
        } => format!(
            "created via {} ({snapshot_id})",
            snapshot_backend_label(*backend)
        ),
        SnapshotStatus::Failed(message) => format!("failed: {message}"),
        SnapshotStatus::Reverted {
            backend,
            snapshot_id,
            ..
        } => format!(
            "reverted via {} ({snapshot_id})",
            snapshot_backend_label(*backend)
        ),
    }
}

fn structured_snapshot_status(status: &SnapshotStatus) -> StructuredReceiptStatus {
    match status {
        SnapshotStatus::NotRequested => StructuredReceiptStatus {
            status: "not_requested",
            message: None,
            path: None,
            backend: None,
            snapshot_id: None,
        },
        SnapshotStatus::Pending => StructuredReceiptStatus {
            status: "pending",
            message: None,
            path: None,
            backend: None,
            snapshot_id: None,
        },
        SnapshotStatus::Created {
            backend,
            snapshot_id,
            snapshot_root,
        } => StructuredReceiptStatus {
            status: "created",
            message: None,
            path: snapshot_root
                .as_ref()
                .map(|path| path.display().to_string()),
            backend: Some(snapshot_backend_label(*backend)),
            snapshot_id: Some(snapshot_id.clone()),
        },
        SnapshotStatus::Failed(message) => StructuredReceiptStatus {
            status: "failed",
            message: Some(message.clone()),
            path: None,
            backend: None,
            snapshot_id: None,
        },
        SnapshotStatus::Reverted {
            backend,
            snapshot_id,
            snapshot_root,
        } => StructuredReceiptStatus {
            status: "reverted",
            message: None,
            path: snapshot_root
                .as_ref()
                .map(|path| path.display().to_string()),
            backend: Some(snapshot_backend_label(*backend)),
            snapshot_id: Some(snapshot_id.clone()),
        },
    }
}

fn snapshot_backend_label(backend: warder_core::SnapshotBackend) -> &'static str {
    match backend {
        warder_core::SnapshotBackend::Btrfs => "btrfs",
        warder_core::SnapshotBackend::OverlayFs => "overlayfs",
    }
}

fn receipt_format_label(format: ReceiptFormat) -> &'static str {
    match format {
        ReceiptFormat::Text => "text",
        ReceiptFormat::Json => "json",
    }
}

fn profile_catalog_format_label(format: ProfileCatalogFormat) -> &'static str {
    match format {
        ProfileCatalogFormat::Text => "text",
        ProfileCatalogFormat::Json => "json",
    }
}

fn journal_kind_summary_label(kind: JournalKind) -> &'static str {
    match kind {
        JournalKind::File => "file journal",
        JournalKind::Network => "network journal",
        JournalKind::All => "all journals",
    }
}

fn write_policy_label(policy: WritePolicy) -> &'static str {
    match policy {
        WritePolicy::Deny => "deny",
        WritePolicy::Allow => "allow",
    }
}

fn snapshot_policy_label(policy: SnapshotPolicy) -> &'static str {
    match policy {
        SnapshotPolicy::Required => "required",
        SnapshotPolicy::BestEffort => "best-effort",
        SnapshotPolicy::Disabled => "disabled",
    }
}

fn landlock_plan_status_label(status: &LandlockPlanStatus) -> String {
    match status {
        LandlockPlanStatus::Apply => "will apply".to_string(),
        LandlockPlanStatus::NotRequested => "not requested".to_string(),
        LandlockPlanStatus::Degraded(message) => format!("degraded: {message}"),
        LandlockPlanStatus::Blocked(message) => format!("blocked: {message}"),
    }
}

fn network_journal_label(config: &WarderConfig, environment: &EnvironmentSupport) -> String {
    if !config.network.journal {
        "disabled".to_string()
    } else {
        match planned_ebpf_network_journal_attach(config, environment).status {
            warder_journal::EbpfNetworkJournalAttachStatus::Attach => "enabled".to_string(),
            warder_journal::EbpfNetworkJournalAttachStatus::Unavailable(message) => {
                format!("degraded: {message}")
            }
        }
    }
}

fn append_non_enforcing_network_policy_warning(config: &WarderConfig, warnings: &mut Vec<String>) {
    if !config.network.allowed_destinations.is_empty() {
        push_unique(
            warnings,
            "network.allowed_destinations is configured, but Warder does not enforce destination allowlists yet; current network policy is observation-only".to_string(),
        );
    }
}

fn planned_ebpf_network_journal_attach(
    config: &WarderConfig,
    environment: &EnvironmentSupport,
) -> warder_journal::EbpfNetworkJournalAttachPlan {
    warder_journal::plan_ebpf_network_journal_attach(warder_journal::EbpfNetworkJournalSupport {
        bpffs_available: config.network.journal && environment.ebpf,
        attach_available: warder_journal::live_ebpf_network_attach_available(),
    })
}

fn cgroup_tagging_label(config: &WarderConfig, environment: &EnvironmentSupport) -> String {
    match config.enforcement.cgroups {
        EnforcementRequirement::Disabled => "not requested".to_string(),
        EnforcementRequirement::Required if environment.cgroups => {
            "required (--cgroup-root must be provided for launch)".to_string()
        }
        EnforcementRequirement::Required => {
            "blocked: cgroups unavailable, but config requires cgroup session tagging".to_string()
        }
        EnforcementRequirement::BestEffort if environment.cgroups => {
            "best-effort (--cgroup-root enables tagging at launch)".to_string()
        }
        EnforcementRequirement::BestEffort => {
            "degraded: cgroups unavailable; session tagging is degraded".to_string()
        }
    }
}

fn snapshot_plan_label(plan: &SnapshotPlan) -> String {
    match plan {
        SnapshotPlan::Create { backend } => {
            format!("will create ({})", snapshot_plan_backend_label(backend))
        }
        SnapshotPlan::Skip(message) => format!("degraded: {message}"),
        SnapshotPlan::Block(message) => format!("blocked: {message}"),
        SnapshotPlan::NotRequested => "not requested".to_string(),
    }
}

fn snapshot_plan_backend_label(backend: &SnapshotBackend) -> &'static str {
    match backend {
        SnapshotBackend::Btrfs => "btrfs",
        SnapshotBackend::OverlayFs => "overlayfs",
        SnapshotBackend::Unsupported => "unsupported",
    }
}

fn load_config(config_path: &PathBuf) -> Result<WarderConfig, CliError> {
    let config_text = std::fs::read_to_string(config_path).map_err(|error| CliError {
        message: format!("failed to read config '{}': {error}", config_path.display()),
    })?;
    parse_config_text(config_path, &config_text).map_err(|error| CliError {
        message: format!(
            "failed to parse config '{}': {error:?}",
            config_path.display()
        ),
    })
}

fn parse_config_text(
    config_path: &Path,
    config_text: &str,
) -> Result<WarderConfig, ConfigParseError> {
    match config_path
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("yaml" | "yml") => WarderConfig::from_yaml(config_text),
        _ => WarderConfig::from_toml(config_text),
    }
}

fn render_policy_explain(config: &WarderConfig, environment: &EnvironmentSupport) -> String {
    let validation = config.validate(environment);
    let landlock_plan = planned_landlock_restrictions(config, environment);
    let snapshot_plan = planned_snapshot_plan(config, environment);

    let mut lines = vec![
        "policy explanation".to_string(),
        format!("protected zones: {}", config.zones.len()),
        format!(
            "agents: {}",
            config
                .agents
                .iter()
                .map(|agent| format!("{} ({})", agent.id, agent.label))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!(
            "network journal: {}",
            network_journal_label(config, environment)
        ),
        format!(
            "cgroup tagging: {}",
            cgroup_tagging_label(config, environment)
        ),
        format!(
            "landlock: {}",
            landlock_plan_status_label(&landlock_plan.status)
        ),
        format!("snapshot: {}", snapshot_plan_label(&snapshot_plan)),
    ];

    for zone in &config.zones {
        lines.push(format!(
            "zone: {} paths={} write={} snapshot={}",
            zone.id,
            zone.paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            write_policy_label(zone.write_policy),
            snapshot_policy_label(zone.snapshot)
        ));
    }
    for agent in &config.agents {
        lines.push(format!("agent: {} command={}", agent.id, agent.command));
    }

    let mut errors = validation
        .issues
        .iter()
        .filter(|issue| issue.severity == ConfigIssueSeverity::Error)
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    let mut warnings = validation
        .issues
        .iter()
        .filter(|issue| issue.severity == ConfigIssueSeverity::Warning)
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    if config.network.journal {
        if let warder_journal::EbpfNetworkJournalAttachStatus::Unavailable(message) =
            planned_ebpf_network_journal_attach(config, environment).status
        {
            push_unique(&mut warnings, message);
        }
    }
    append_non_enforcing_network_policy_warning(config, &mut warnings);
    append_snapshot_plan_validation(&snapshot_plan, &mut errors, &mut warnings);
    if errors.is_empty() && warnings.is_empty() {
        lines.push("validation: ok".to_string());
    } else {
        for error in errors {
            lines.push(format!("error: {error}"));
        }
        for warning in warnings {
            lines.push(format!("warning: {warning}"));
        }
    }

    lines.join("\n")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentProfileCatalogEntry {
    pub id: &'static str,
    pub declared_command: &'static str,
    pub summary: &'static str,
    pub preflight: &'static str,
    pub effect: &'static str,
    pub template: AgentProfileSetupTemplate,
}

#[derive(Serialize)]
pub struct AgentProfileCatalog {
    profiles: Vec<AgentProfileCatalogEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentProfileSetupTemplate {
    pub recommended_protected_paths: Vec<AgentProfileProtectedPathTemplate>,
    pub writable_roots: Vec<&'static str>,
    pub network_journal: bool,
    pub snapshot: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentProfileProtectedPathTemplate {
    pub label: &'static str,
    pub path: &'static str,
    pub read: bool,
    pub write: bool,
}

pub fn known_agent_profile_catalog() -> Vec<AgentProfileCatalogEntry> {
    [
        ("codex-cli", "codex"),
        ("claude-code", "claude"),
        ("goose-cli", "goose"),
        ("openclaw-cli", "openclaw"),
        ("openclaw-gateway", "openclaw gateway"),
        ("openclaw-agent", "openclaw agent"),
        ("local-script", "sh"),
        ("generic-cli", "<command>"),
    ]
    .into_iter()
    .map(|(profile, declared_command)| agent_profile_catalog_entry(profile, declared_command))
    .collect()
}

fn agent_profile_catalog_entry(
    profile: &'static str,
    declared_command: &'static str,
) -> AgentProfileCatalogEntry {
    AgentProfileCatalogEntry {
        id: profile,
        declared_command,
        summary: agent_profile_summary(profile),
        preflight: agent_profile_preflight(profile),
        effect: "transparent preset only; policy still comes from config and host support",
        template: agent_profile_setup_template(profile),
    }
}

fn agent_profile_setup_template(profile: &str) -> AgentProfileSetupTemplate {
    AgentProfileSetupTemplate {
        recommended_protected_paths: recommended_profile_paths(profile),
        writable_roots: recommended_writable_roots(profile),
        network_journal: matches!(
            profile,
            "codex-cli"
                | "claude-code"
                | "goose-cli"
                | "openclaw-cli"
                | "openclaw-gateway"
                | "openclaw-agent"
        ),
        snapshot: match profile {
            "codex-cli" | "claude-code" | "goose-cli" | "openclaw-cli" | "openclaw-gateway"
            | "openclaw-agent" | "local-script" => "best-effort",
            _ => "disabled",
        },
    }
}

fn recommended_profile_paths(profile: &str) -> Vec<AgentProfileProtectedPathTemplate> {
    match profile {
        "codex-cli" | "claude-code" | "goose-cli" => vec![
            protected_path_template("SSH keys", "$HOME/.ssh", true, true),
            protected_path_template("Shell credentials", "$HOME/.config", true, false),
            protected_path_template("User notes", "$HOME/notes", true, true),
        ],
        "openclaw-cli" | "openclaw-gateway" | "openclaw-agent" => vec![
            protected_path_template("SSH keys", "$HOME/.ssh", true, true),
            protected_path_template("Cloud credentials", "$HOME/.config", true, false),
            protected_path_template("User notes", "$HOME/notes", true, true),
            protected_path_template("User documents", "$HOME/Documents", true, true),
            protected_path_template("OpenClaw state", "$HOME/.openclaw", true, false),
        ],
        "local-script" => vec![
            protected_path_template("SSH keys", "$HOME/.ssh", true, true),
            protected_path_template("User notes", "$HOME/notes", true, true),
        ],
        _ => vec![protected_path_template(
            "SSH keys",
            "$HOME/.ssh",
            true,
            true,
        )],
    }
}

fn protected_path_template(
    label: &'static str,
    path: &'static str,
    read: bool,
    write: bool,
) -> AgentProfileProtectedPathTemplate {
    AgentProfileProtectedPathTemplate {
        label,
        path,
        read,
        write,
    }
}

fn recommended_writable_roots(profile: &str) -> Vec<&'static str> {
    match profile {
        "codex-cli" | "claude-code" | "goose-cli" | "openclaw-cli" | "openclaw-agent"
        | "local-script" => vec!["$PWD"],
        "openclaw-gateway" => vec!["$HOME/.openclaw/workspace"],
        _ => Vec::new(),
    }
}

fn agent_profile_summary(profile: &str) -> &'static str {
    match profile {
        "codex-cli" => "known local CLI agent; transparent preset for Codex-style shell workflows",
        "claude-code" => {
            "known local CLI agent; transparent preset for Claude Code-style shell workflows"
        }
        "goose-cli" => "known local CLI agent; transparent preset for Goose-style shell workflows",
        "openclaw-cli" => "OpenClaw command; Warder supervises the Linux process while OpenClaw controls app-level policy",
        "openclaw-gateway" => "OpenClaw Gateway; Warder supervises the host control-plane process and reports degraded coverage for unverified sandboxed tools",
        "openclaw-agent" => "OpenClaw agent run; Warder supervises the launched command and complements OpenClaw tool policy with host protected zones",
        "local-script" => "local script or wrapper; Warder treats the declared command literally",
        "generic-cli" => "generic local CLI command; no tool-specific assumptions are applied",
        _ => "unknown profile; Warder falls back to generic CLI handling",
    }
}

fn agent_profile_preflight(profile: &str) -> &'static str {
    match profile {
        "codex-cli" => {
            "confirm Codex workspace and approval settings match the protected-zone policy before launch"
        }
        "claude-code" => {
            "confirm Claude Code tool permissions match the protected-zone policy before launch"
        }
        "goose-cli" => {
            "confirm Goose extension and tool permissions match the protected-zone policy before launch"
        }
        "openclaw-cli" => {
            "run OpenClaw security audit when available and confirm gateway, tool, and sandbox policy match Warder's protected zones"
        }
        "openclaw-gateway" => {
            "confirm Gateway bind/auth, channel pairing, tool policy, sandbox mode, and state-directory permissions before launch"
        }
        "openclaw-agent" => {
            "confirm OpenClaw sandbox/tool policy and run-specific workspace access before launch"
        }
        "local-script" => "inspect the wrapper script path and arguments before launch",
        "generic-cli" => "confirm the declared command path and policy before launch",
        _ => "confirm the declared command path and policy before launch",
    }
}

fn render_agent_profile_summary(profile: Option<&str>, declared_command: &str) -> String {
    let profile = profile.unwrap_or("generic-cli");
    let description = agent_profile_summary(profile);
    let preflight = agent_profile_preflight(profile);
    [
        format!("profile: {profile}"),
        format!("profile summary: {description}"),
        format!("declared command: {declared_command}"),
        format!("profile preflight: {preflight}"),
        "profile effect: transparent preset only; policy still comes from config and host support"
            .to_string(),
    ]
    .join("\n")
}

pub fn render_agent_profile_catalog() -> String {
    let mut lines = vec![
        "transparent profiles".to_string(),
        "Profiles are explainable presets only; policy still comes from config and host support."
            .to_string(),
    ];
    for profile in known_agent_profile_catalog() {
        lines.push(String::new());
        lines.push(render_agent_profile_summary(
            Some(profile.id),
            profile.declared_command,
        ));
        lines.push(render_agent_profile_template(&profile.template));
    }
    lines.join("\n")
}

fn render_agent_profile_template(template: &AgentProfileSetupTemplate) -> String {
    let mut lines = vec![
        format!(
            "template network journal: {}",
            if template.network_journal {
                "enabled"
            } else {
                "disabled"
            }
        ),
        format!("template snapshot: {}", template.snapshot),
    ];
    if template.recommended_protected_paths.is_empty() {
        lines.push("template protected paths: none".to_string());
    } else {
        lines.push("template protected paths:".to_string());
        lines.extend(template.recommended_protected_paths.iter().map(|path| {
            format!(
                "- {}: {} read={} write={}",
                path.label, path.path, path.read, path.write
            )
        }));
    }
    if template.writable_roots.is_empty() {
        lines.push("template writable roots: none".to_string());
    } else {
        lines.push(format!(
            "template writable roots: {}",
            template.writable_roots.join(", ")
        ));
    }
    lines.join("\n")
}

pub fn render_agent_profile_catalog_json() -> Result<String, CliError> {
    serde_json::to_string_pretty(&AgentProfileCatalog {
        profiles: known_agent_profile_catalog(),
    })
    .map_err(|error| CliError {
        message: format!("failed to render profile catalog json: {error}"),
    })
}

#[cfg(test)]
fn effective_agent_profile(
    explicit_profile: Option<&str>,
    declared_command: &str,
) -> Option<String> {
    effective_agent_profile_for_run(explicit_profile, declared_command, &[])
}

fn effective_agent_profile_for_run(
    explicit_profile: Option<&str>,
    declared_command: &str,
    run_command: &[String],
) -> Option<String> {
    explicit_profile.map(ToString::to_string).or_else(|| {
        inferred_agent_profile_for_run(declared_command, run_command).map(ToString::to_string)
    })
}

fn inferred_agent_profile_for_run(
    declared_command: &str,
    run_command: &[String],
) -> Option<&'static str> {
    let command_name = Path::new(declared_command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(declared_command);

    match command_name {
        "codex" => Some("codex-cli"),
        "claude" | "claude-code" => Some("claude-code"),
        "goose" => Some("goose-cli"),
        "openclaw" => inferred_openclaw_profile(run_command),
        _ => None,
    }
}

fn inferred_openclaw_profile(run_command: &[String]) -> Option<&'static str> {
    let subcommand = run_command
        .iter()
        .skip(1)
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str);

    match subcommand {
        Some("gateway") | Some("onboard") => Some("openclaw-gateway"),
        Some("agent") => Some("openclaw-agent"),
        _ => Some("openclaw-cli"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenClawPreflightReport {
    binary_available: bool,
    audit_status: String,
    sandbox_status: String,
    warnings: Vec<String>,
}

fn append_openclaw_preflight_lines(
    profile: Option<&str>,
    command: &[String],
    lines: &mut Vec<String>,
) {
    let Some(profile) = profile.filter(|profile| is_openclaw_profile(profile)) else {
        return;
    };
    let report = openclaw_preflight_report(profile, command);
    lines.push("openclaw preflight:".to_string());
    lines.push(format!(
        "- binary: {}",
        if report.binary_available {
            "available"
        } else {
            "missing on PATH"
        }
    ));
    lines.push(format!("- security audit: {}", report.audit_status));
    lines.push(format!("- sandbox explain: {}", report.sandbox_status));
    if report.warnings.is_empty() {
        lines.push("- openclaw warnings: none detected".to_string());
    } else {
        lines.push("- openclaw warnings:".to_string());
        lines.extend(
            report
                .warnings
                .iter()
                .map(|warning| format!("  - {warning}")),
        );
    }
}

fn append_openclaw_preflight_warnings(
    profile: &str,
    command: &[String],
    warnings: &mut Vec<String>,
) {
    if !is_openclaw_profile(profile) {
        return;
    }
    for warning in openclaw_preflight_report(profile, command).warnings {
        push_unique(warnings, warning);
    }
}

fn openclaw_preflight_report(profile: &str, command: &[String]) -> OpenClawPreflightReport {
    let mut warnings = Vec::new();
    let binary = openclaw_preflight_binary(command);
    let audit = run_openclaw_json_command(&binary, &["security", "audit", "--json"]);
    let sandbox = run_openclaw_json_command(&binary, &["sandbox", "explain", "--json"]);
    let binary_available = !matches!(audit, OpenClawJsonCommandResult::Missing);

    let audit_status = match audit {
        OpenClawJsonCommandResult::Missing => {
            push_unique(
                &mut warnings,
                "OpenClaw missing on PATH; OpenClaw audit and sandbox posture were not verified"
                    .to_string(),
            );
            "skipped: openclaw not found".to_string()
        }
        OpenClawJsonCommandResult::Failed(message) => {
            push_unique(
                &mut warnings,
                format!("OpenClaw security audit unavailable: {message}"),
            );
            format!("unavailable: {message}")
        }
        OpenClawJsonCommandResult::InvalidJson(message) => {
            push_unique(
                &mut warnings,
                format!("OpenClaw security audit output was not valid JSON: {message}"),
            );
            format!("unparsed: {message}")
        }
        OpenClawJsonCommandResult::Json(value) => {
            let audit_warnings = openclaw_audit_warnings(&value);
            for warning in &audit_warnings {
                push_unique(&mut warnings, warning.clone());
            }
            format!("parsed: {} high-risk finding(s)", audit_warnings.len())
        }
    };

    let sandbox_status = match sandbox {
        OpenClawJsonCommandResult::Missing => "skipped: openclaw not found".to_string(),
        OpenClawJsonCommandResult::Failed(message) => {
            push_unique(
                &mut warnings,
                format!("OpenClaw sandbox explain unavailable: {message}"),
            );
            format!("unavailable: {message}")
        }
        OpenClawJsonCommandResult::InvalidJson(message) => {
            push_unique(
                &mut warnings,
                format!("OpenClaw sandbox explain output was not valid JSON: {message}"),
            );
            format!("unparsed: {message}")
        }
        OpenClawJsonCommandResult::Json(value) => {
            let sandbox_warnings = openclaw_sandbox_warnings(profile, &value);
            for warning in &sandbox_warnings {
                push_unique(&mut warnings, warning.clone());
            }
            openclaw_sandbox_status(&value)
        }
    };

    OpenClawPreflightReport {
        binary_available,
        audit_status,
        sandbox_status,
        warnings,
    }
}

enum OpenClawJsonCommandResult {
    Missing,
    Failed(String),
    InvalidJson(String),
    Json(serde_json::Value),
}

fn openclaw_preflight_binary(command: &[String]) -> String {
    command
        .first()
        .filter(|command| {
            Path::new(command)
                .file_name()
                .and_then(|name| name.to_str())
                == Some("openclaw")
        })
        .cloned()
        .unwrap_or_else(|| "openclaw".to_string())
}

fn run_openclaw_json_command(binary: &str, args: &[&str]) -> OpenClawJsonCommandResult {
    let output = match Command::new(binary).args(args).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return OpenClawJsonCommandResult::Missing;
        }
        Err(error) => return OpenClawJsonCommandResult::Failed(error.to_string()),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return OpenClawJsonCommandResult::Failed(if stderr.is_empty() {
            format!("openclaw exited with {}", output.status)
        } else {
            stderr
        });
    }
    serde_json::from_slice(&output.stdout).map_or_else(
        |error| OpenClawJsonCommandResult::InvalidJson(error.to_string()),
        OpenClawJsonCommandResult::Json,
    )
}

fn openclaw_audit_warnings(value: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();
    collect_openclaw_audit_warnings(value, &mut warnings);
    warnings
}

fn collect_openclaw_audit_warnings(value: &serde_json::Value, warnings: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_openclaw_audit_warnings(item, warnings);
            }
        }
        serde_json::Value::Object(map) => {
            let check_id = map
                .get("checkId")
                .or_else(|| map.get("check_id"))
                .or_else(|| map.get("id"))
                .and_then(serde_json::Value::as_str);
            let severity = map
                .get("severity")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if let Some(check_id) = check_id {
                if let Some(message) = openclaw_audit_check_warning(check_id, &severity) {
                    push_unique(warnings, message);
                }
            }
            for item in map.values() {
                collect_openclaw_audit_warnings(item, warnings);
            }
        }
        _ => {}
    }
}

fn openclaw_audit_check_warning(check_id: &str, severity: &str) -> Option<String> {
    let label = if check_id.contains("gateway.bind_no_auth")
        || check_id.contains("gateway.loopback_no_auth")
        || check_id.contains("gateway.http.no_auth")
    {
        "Gateway auth or bind exposure"
    } else if check_id.contains("gateway.tailscale_funnel") {
        "public Tailscale Funnel exposure"
    } else if check_id.contains("browser.") || check_id.contains("cdp") {
        "browser or CDP exposure"
    } else if check_id.contains("elevated") {
        "elevated host exec exposure"
    } else if check_id.contains("tools.exec.security_full") {
        "host exec is configured as full trust"
    } else if check_id.contains("sandbox.dangerous_bind_mount")
        || check_id.contains("sandbox.dangerous_network_mode")
        || check_id.contains("sandbox.dangerous_seccomp_profile")
        || check_id.contains("sandbox.dangerous_apparmor_profile")
    {
        "OpenClaw sandbox configuration weakens isolation"
    } else if check_id.contains("plugins.") || check_id.contains("skills.") {
        "plugin or skill supply-chain warning"
    } else if check_id.starts_with("fs.") {
        "OpenClaw state or credential permissions are risky"
    } else if check_id.contains("security.exposure.open") {
        "open channel or group can reach powerful tools"
    } else if severity == "critical" {
        "critical OpenClaw audit finding"
    } else {
        return None;
    };
    Some(format!("OpenClaw audit: {label} ({check_id})"))
}

fn openclaw_sandbox_status(value: &serde_json::Value) -> String {
    let backend = find_json_string_for_key(value, "backend");
    let mode = find_json_string_for_key(value, "mode").unwrap_or("unknown");
    let scope = find_json_string_for_key(value, "scope").unwrap_or("unknown");
    match backend {
        Some(backend) => format!("parsed: mode={mode}, backend={backend}, scope={scope}"),
        None => format!("parsed: mode={mode}, scope={scope}"),
    }
}

fn openclaw_sandbox_warnings(profile: &str, value: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();
    let backend = find_json_string_for_key(value, "backend").unwrap_or_default();
    let mode = find_json_string_for_key(value, "mode").unwrap_or_default();
    if is_openclaw_profile(profile) && mode == "off" {
        push_unique(
            &mut warnings,
            "OpenClaw sandbox mode is off; Warder only supervises the launched host process"
                .to_string(),
        );
    }
    if matches!(backend, "docker" | "ssh" | "openshell") {
        push_unique(
            &mut warnings,
            format!(
                "OpenClaw uses {backend} sandboxing; Warder coverage inside that sandbox is degraded unless process, cgroup, mount, and network visibility are verified"
            ),
        );
    }
    let strings = collect_json_strings(value);
    if strings
        .iter()
        .any(|value| value.contains("/var/run/docker.sock"))
    {
        push_unique(
            &mut warnings,
            "OpenClaw sandbox bind mounts the Docker socket; sandboxed tools can control the host Docker daemon"
                .to_string(),
        );
    }
    if strings.iter().any(|value| value == "host") {
        push_unique(
            &mut warnings,
            "OpenClaw sandbox appears to use host network mode; network isolation and Warder attribution may be degraded"
                .to_string(),
        );
    }
    warnings
}

fn find_json_string_for_key<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|item| find_json_string_for_key(item, key)),
        serde_json::Value::Object(map) => {
            map.get(key)
                .and_then(serde_json::Value::as_str)
                .or_else(|| {
                    map.values()
                        .find_map(|item| find_json_string_for_key(item, key))
                })
        }
        _ => None,
    }
}

fn collect_json_strings(value: &serde_json::Value) -> Vec<String> {
    let mut strings = Vec::new();
    collect_json_strings_into(value, &mut strings);
    strings
}

fn collect_json_strings_into(value: &serde_json::Value, strings: &mut Vec<String>) {
    match value {
        serde_json::Value::String(value) => strings.push(value.to_string()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings_into(item, strings);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_json_strings_into(item, strings);
            }
        }
        _ => {}
    }
}

fn is_openclaw_profile(profile: &str) -> bool {
    profile == "openclaw-cli"
        || profile == "openclaw-gateway"
        || profile == "openclaw-agent"
        || profile == "openclaw"
}

fn session_is_openclaw(session: &SessionRecord) -> bool {
    session
        .agent_profile
        .as_deref()
        .map(is_openclaw_profile)
        .unwrap_or(false)
        || session.command.first().and_then(|command| {
            Path::new(command)
                .file_name()
                .and_then(|name| name.to_str())
        }) == Some("openclaw")
}

fn dependency_change_summary(command: &[String]) -> DependencyChangeSummary {
    let joined = command.join(" ");
    let package_evidence = package_manager_evidence(command, &joined);
    if !package_evidence.is_empty() {
        return DependencyChangeSummary {
            status: "possible",
            reason: "command metadata references a package manager operation".to_string(),
            evidence: package_evidence,
        };
    }

    let dependency_file_evidence = dependency_file_evidence(&joined);
    if !dependency_file_evidence.is_empty() {
        return DependencyChangeSummary {
            status: "possible",
            reason: "command metadata references a dependency file".to_string(),
            evidence: dependency_file_evidence,
        };
    }

    DependencyChangeSummary {
        status: "none_detected",
        reason: "command metadata does not reference known package managers or dependency files"
            .to_string(),
        evidence: Vec::new(),
    }
}

fn render_dependency_file_change_line(change: &DependencyFileChange) -> String {
    format!(
        "- {} {}",
        dependency_file_change_status_label(change.status),
        change.path.display()
    )
}

fn dependency_file_change_status_label(status: DependencyFileChangeStatus) -> &'static str {
    match status {
        DependencyFileChangeStatus::Created => "created",
        DependencyFileChangeStatus::Modified => "modified",
        DependencyFileChangeStatus::Removed => "removed",
    }
}

fn file_activity_summary(file_events: &[FileJournalEvent]) -> StructuredFileActivitySummary {
    let mut summary = StructuredFileActivitySummary::empty();
    summary.total_events = file_events.len();
    for event in file_events {
        increment_count(
            &mut summary.zones,
            event
                .protected_zone_id
                .as_deref()
                .unwrap_or("unmatched")
                .to_string(),
        );
        increment_count(
            &mut summary.sources,
            journal_source_label(event.source).to_string(),
        );
        increment_count(
            &mut summary.attribution,
            warder_journal::attribution_label(event.attribution).to_string(),
        );
    }
    summary
}

fn network_activity_summary(
    network_events: &[NetworkJournalEvent],
) -> StructuredNetworkActivitySummary {
    let mut summary = StructuredNetworkActivitySummary::empty();
    summary.total_events = network_events.len();
    for event in network_events {
        increment_count(&mut summary.destinations, network_destination_label(event));
        increment_count(
            &mut summary.protocols,
            network_protocol_label(&event.protocol),
        );
        increment_count(
            &mut summary.sources,
            journal_source_label(event.source).to_string(),
        );
        increment_count(
            &mut summary.attribution,
            warder_journal::attribution_label(event.attribution).to_string(),
        );
    }
    summary
}

fn increment_count(counts: &mut std::collections::BTreeMap<String, usize>, label: String) {
    *counts.entry(label).or_default() += 1;
}

fn render_count_map(counts: &std::collections::BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn journal_source_label(source: warder_journal::JournalSource) -> &'static str {
    match source {
        warder_journal::JournalSource::Landlock => "Landlock",
        warder_journal::JournalSource::Inotify => "inotify",
        warder_journal::JournalSource::Ebpf => "eBPF",
        warder_journal::JournalSource::Procfs => "procfs",
        warder_journal::JournalSource::Cgroup => "cgroup",
        warder_journal::JournalSource::Snapshot => "snapshot",
        warder_journal::JournalSource::Manual => "manual",
    }
}

fn network_protocol_label(protocol: &warder_journal::NetworkProtocol) -> String {
    match protocol {
        warder_journal::NetworkProtocol::Tcp => "tcp".to_string(),
        warder_journal::NetworkProtocol::Udp => "udp".to_string(),
        warder_journal::NetworkProtocol::Icmp => "icmp".to_string(),
        warder_journal::NetworkProtocol::Other(value) => value.to_ascii_lowercase(),
    }
}

fn network_destination_label(event: &NetworkJournalEvent) -> String {
    match event.destination_port {
        Some(port) => format!("{}:{port}", event.destination),
        None => event.destination.clone(),
    }
}

fn receipt_review_guidance(
    session: &SessionRecord,
    file_activity: &StructuredFileActivitySummary,
    network_activity: &StructuredNetworkActivitySummary,
) -> Vec<String> {
    let mut guidance = Vec::new();
    if dependency_change_summary(&session.command).status == "possible"
        || !session.dependency_file_changes.is_empty()
    {
        guidance.push("Review dependency file changes before trusting the run output.".to_string());
    }
    if file_activity.total_events > 0 {
        guidance.push(
            "Inspect file activity rollups and raw journal events for unexpected protected-zone changes."
                .to_string(),
        );
        if file_activity.attribution.contains_key("session-window")
            && file_activity.sources.contains_key("inotify")
        {
            guidance.push(
                "Inotify session-window events are observational and are not PID-attributed enforcement evidence."
                .to_string(),
            );
        }
    } else if has_degraded_journal_coverage(session) {
        guidance.push(
            "File activity may be incomplete because journal coverage degraded; do not treat a quiet journal as proof that protected zones were untouched."
                .to_string(),
        );
    }
    if network_activity.total_events > 0 {
        guidance.push(
            "Inspect network activity rollups and raw network journal events for unexpected egress."
                .to_string(),
        );
        guidance.push(format!(
            "Network journal visibility is {}; review quiet or missing destinations against this limit.",
            warder_journal::network_visibility_contract()
        ));
    } else if has_degraded_network_journal_coverage(session) {
        guidance.push(
            "Network activity may be incomplete because live network journal coverage degraded; do not treat quiet egress as proof that no network access happened."
                .to_string(),
        );
    }
    if !session.degraded_reasons.is_empty() {
        guidance.push("Treat degraded coverage as incomplete protection, not success.".to_string());
    }
    if guidance.is_empty() {
        guidance.push("No extra review guidance generated for this receipt.".to_string());
    }
    guidance
}

fn has_degraded_journal_coverage(session: &SessionRecord) -> bool {
    session.degraded_reasons.iter().any(|reason| {
        let reason = reason.to_ascii_lowercase();
        reason.contains("journal")
    })
}

fn has_degraded_network_journal_coverage(session: &SessionRecord) -> bool {
    session.degraded_reasons.iter().any(|reason| {
        let reason = reason.to_ascii_lowercase();
        reason.contains("network") && reason.contains("journal")
    })
}

fn receipt_review_actions(
    session: &SessionRecord,
    file_activity: &StructuredFileActivitySummary,
    network_activity: &StructuredNetworkActivitySummary,
    db_path: Option<&Path>,
) -> Vec<StructuredReviewAction> {
    let mut actions = Vec::new();
    if session_is_openclaw(session) {
        actions.push(StructuredReviewAction {
            kind: "openclaw_security_audit",
            label: "Run OpenClaw security audit",
            command: Some("openclaw security audit --deep".to_string()),
            command_argv: Some(vec![
                "openclaw".to_string(),
                "security".to_string(),
                "audit".to_string(),
                "--deep".to_string(),
            ]),
            mutates: false,
            reason: Some(
                "OpenClaw app-level gateway, channel, tool, and sandbox policy should be reviewed alongside Warder host receipts"
                    .to_string(),
            ),
        });
        actions.push(StructuredReviewAction {
            kind: "openclaw_sandbox_explain",
            label: "Inspect OpenClaw sandbox posture",
            command: Some("openclaw sandbox explain --json".to_string()),
            command_argv: Some(vec![
                "openclaw".to_string(),
                "sandbox".to_string(),
                "explain".to_string(),
                "--json".to_string(),
            ]),
            mutates: false,
            reason: Some(
                "Warder observes the launched Linux process; OpenClaw sandbox backends may move tool execution into Docker, SSH, or OpenShell"
                    .to_string(),
            ),
        });
    }
    if let Some(reason) = dependency_review_reason(session) {
        actions.push(StructuredReviewAction {
            kind: "review_dependency_files",
            label: "Review dependency file changes",
            command: None,
            command_argv: None,
            mutates: false,
            reason: Some(reason),
        });
    }
    if file_activity.total_events > 0 && network_activity.total_events > 0 {
        let command_argv = all_journals_command_argv(db_path, &session.id);
        actions.push(StructuredReviewAction {
            kind: "inspect_all_journals",
            label: "Inspect all recorded journal activity",
            command: Some(shell_command_line(&command_argv)),
            command_argv: Some(command_argv),
            mutates: false,
            reason: Some("file and network activity were recorded".to_string()),
        });
    } else if file_activity.total_events > 0 {
        let command_argv = journal_command_argv(db_path, &session.id);
        actions.push(StructuredReviewAction {
            kind: "inspect_journal",
            label: "Inspect protected-zone file activity",
            command: Some(shell_command_line(&command_argv)),
            command_argv: Some(command_argv),
            mutates: false,
            reason: Some("protected-zone file activity was recorded".to_string()),
        });
    } else if has_degraded_journal_coverage(session) {
        actions.push(StructuredReviewAction {
            kind: "review_degraded_journal_coverage",
            label: "Review degraded journal coverage",
            command: None,
            command_argv: None,
            mutates: false,
            reason: Some(session.degraded_reasons.join("; ")),
        });
    }
    if network_activity.total_events == 0 && has_degraded_network_journal_coverage(session) {
        actions.push(StructuredReviewAction {
            kind: "review_degraded_network_journal_coverage",
            label: "Review degraded network journal coverage",
            command: None,
            command_argv: None,
            mutates: false,
            reason: Some(session.degraded_reasons.join("; ")),
        });
    }
    if network_activity.total_events > 0 && file_activity.total_events == 0 {
        let command_argv = network_journal_command_argv(db_path, &session.id);
        actions.push(StructuredReviewAction {
            kind: "inspect_network_journal",
            label: "Inspect network egress activity",
            command: Some(shell_command_line(&command_argv)),
            command_argv: Some(command_argv),
            mutates: false,
            reason: Some("network egress activity was recorded".to_string()),
        });
    }
    if !session.degraded_reasons.is_empty() {
        let command_argv = doctor_command_argv();
        actions.push(StructuredReviewAction {
            kind: "doctor",
            label: "Inspect host readiness",
            command: Some(shell_command_line(&command_argv)),
            command_argv: Some(command_argv),
            mutates: false,
            reason: Some(session.degraded_reasons.join("; ")),
        });
    }
    actions
}

fn dependency_review_reason(session: &SessionRecord) -> Option<String> {
    let mut reasons = Vec::new();
    let summary = dependency_change_summary(&session.command);
    if summary.status == "possible" {
        reasons.push(summary.reason);
    }
    if !session.dependency_file_changes.is_empty() {
        reasons.push("dependency file changes were recorded".to_string());
    }
    if reasons.is_empty() {
        None
    } else {
        Some(reasons.join("; "))
    }
}

fn receipt_recovery_guidance(
    session: &SessionRecord,
    file_activity: &StructuredFileActivitySummary,
    network_activity: &StructuredNetworkActivitySummary,
    db_path: Option<&Path>,
) -> Vec<String> {
    let mut guidance = Vec::new();
    if session_is_openclaw(session) {
        guidance.push(
            "OpenClaw controls app-level gateway, channel, tool, and sandbox policy; Warder constrains and observes the launched Linux host process."
                .to_string(),
        );
        guidance.push(
            "Before changing OpenClaw config after this run, export the Warder receipt and compare it with `openclaw security audit --deep`."
                .to_string(),
        );
    }
    if session.status == SessionStatus::Failed {
        guidance.push(
            "Inspect the command exit status and rerun only after correcting the failed agent command."
                .to_string(),
        );
        guidance.push(format!(
            "Run `{}` to preserve structured failure details before rerunning.",
            receipt_json_command(db_path, &session.id)
        ));
    }
    if file_activity.total_events > 0 && network_activity.total_events > 0 {
        guidance.push(format!(
            "Run `{}` to inspect recorded file and network activity together.",
            all_journals_command(db_path, &session.id)
        ));
    } else if file_activity.total_events > 0 {
        guidance.push(format!(
            "Run `{}` to inspect protected-zone file activity.",
            journal_command(db_path, &session.id)
        ));
    } else if network_activity.total_events > 0 {
        guidance.push(format!(
            "Run `{}` to inspect recorded network egress activity.",
            network_journal_command(db_path, &session.id)
        ));
    }
    if !session.dependency_file_changes.is_empty()
        || dependency_change_summary(&session.command).status == "possible"
    {
        guidance.push("Review and revert dependency changes with your package manager or VCS if they were unexpected.".to_string());
    }
    if !session.degraded_reasons.is_empty() {
        guidance.push(
            "Rerun after addressing degraded coverage if this session needed strong protection."
                .to_string(),
        );
        guidance.push(
            "Run `warder doctor` to inspect host readiness before rerunning a session that needed strong protection."
                .to_string(),
        );
    }
    match guarded_snapshot_restore_receipt_state(session) {
        GuardedSnapshotRestoreReceiptState::Available {
            snapshot_id,
            snapshot_root,
        } => guidance.push(format!(
            "Guarded snapshot restore is available with the original snapshot root: `{}`. Warder refuses to restore over existing target paths.",
            guarded_snapshot_restore_command_for_receipt(
                snapshot_id,
                Some(snapshot_root),
                db_path,
                &session.id
            )
        )),
        GuardedSnapshotRestoreReceiptState::PreviewOnly {
            snapshot_id,
            snapshot_root,
            message,
        } => guidance.push(format!(
            "{message} Preview with `{}` before changing recovery state.",
            guarded_snapshot_restore_preview_command(snapshot_id, snapshot_root)
        )),
        GuardedSnapshotRestoreReceiptState::Withheld(message) => guidance.push(message),
        GuardedSnapshotRestoreReceiptState::Unavailable => {}
    }
    if guidance.is_empty() {
        guidance.push("No recovery action suggested for this receipt.".to_string());
    }
    guidance
}

fn receipt_recovery_actions(
    session: &SessionRecord,
    file_activity: &StructuredFileActivitySummary,
    network_activity: &StructuredNetworkActivitySummary,
    db_path: Option<&Path>,
) -> Vec<StructuredRecoveryAction> {
    let mut actions = Vec::new();
    if session_is_openclaw(session) {
        let command_argv = receipt_json_command_argv(db_path, &session.id);
        actions.push(StructuredRecoveryAction {
            kind: "export_openclaw_receipt",
            label: "Export receipt before changing OpenClaw config",
            command: shell_command_line(&command_argv),
            command_argv,
            mutates: false,
            reason: Some(
                "preserve Warder's host-level record before adjusting OpenClaw gateway, tool, or sandbox policy"
                    .to_string(),
            ),
        });
    }
    if session.status == SessionStatus::Failed {
        let reason = session
            .exit_code
            .map(|code| format!("session failed with exit code {code}"))
            .unwrap_or_else(|| "session failed".to_string());
        let command_argv = receipt_json_command_argv(db_path, &session.id);
        actions.push(StructuredRecoveryAction {
            kind: "export_receipt",
            label: "Export structured failure receipt",
            command: shell_command_line(&command_argv),
            command_argv,
            mutates: false,
            reason: Some(reason),
        });
    }
    if file_activity.total_events > 0 && network_activity.total_events > 0 {
        let command_argv = all_journals_command_argv(db_path, &session.id);
        actions.push(StructuredRecoveryAction {
            kind: "inspect_all_journals",
            label: "Inspect all recorded journal activity",
            command: shell_command_line(&command_argv),
            command_argv,
            mutates: false,
            reason: Some("file and network activity were recorded".to_string()),
        });
    } else if file_activity.total_events > 0 {
        let command_argv = journal_command_argv(db_path, &session.id);
        actions.push(StructuredRecoveryAction {
            kind: "inspect_journal",
            label: "Inspect protected-zone file activity",
            command: shell_command_line(&command_argv),
            command_argv,
            mutates: false,
            reason: Some("protected-zone file activity was recorded".to_string()),
        });
    }
    if network_activity.total_events > 0 && file_activity.total_events == 0 {
        let command_argv = network_journal_command_argv(db_path, &session.id);
        actions.push(StructuredRecoveryAction {
            kind: "inspect_network_journal",
            label: "Inspect network egress activity",
            command: shell_command_line(&command_argv),
            command_argv,
            mutates: false,
            reason: Some("network egress activity was recorded".to_string()),
        });
    }
    if session.status != SessionStatus::Failed {
        if let Some(reason) = dependency_review_reason(session) {
            let command_argv = receipt_json_command_argv(db_path, &session.id);
            actions.push(StructuredRecoveryAction {
                kind: "export_dependency_receipt",
                label: "Export dependency-change receipt",
                command: shell_command_line(&command_argv),
                command_argv,
                mutates: false,
                reason: Some(reason),
            });
        }
    }
    if !session.degraded_reasons.is_empty() {
        let command_argv = doctor_command_argv();
        actions.push(StructuredRecoveryAction {
            kind: "doctor",
            label: "Inspect host readiness before rerun",
            command: shell_command_line(&command_argv),
            command_argv,
            mutates: false,
            reason: Some(session.degraded_reasons.join("; ")),
        });
    }
    match guarded_snapshot_restore_receipt_state(session) {
        GuardedSnapshotRestoreReceiptState::Available {
            snapshot_id,
            snapshot_root,
        } => {
            let preview_argv =
                guarded_snapshot_restore_preview_command_argv(snapshot_id, snapshot_root);
            actions.push(StructuredRecoveryAction {
                kind: "preview_snapshot_restore",
                label: "Preview guarded snapshot restore",
                command: shell_command_line(&preview_argv),
                command_argv: preview_argv,
                mutates: false,
                reason: Some(
                    "preview uses the recorded Btrfs snapshot root and makes no changes"
                        .to_string(),
                ),
            });
            let restore_argv = guarded_snapshot_restore_command_for_receipt_argv(
                snapshot_id,
                Some(snapshot_root),
                db_path,
                &session.id,
            );
            actions.push(StructuredRecoveryAction {
                kind: "restore_snapshot_guarded",
                label: "Restore snapshot with explicit snapshot root",
                command: shell_command_line(&restore_argv),
                command_argv: restore_argv,
                mutates: true,
                reason: Some(
                    "guarded restore refuses to overwrite existing target paths".to_string(),
                ),
            });
        }
        GuardedSnapshotRestoreReceiptState::PreviewOnly {
            snapshot_id,
            snapshot_root,
            message,
        } => {
            let preview_argv =
                guarded_snapshot_restore_preview_command_argv(snapshot_id, snapshot_root);
            actions.push(StructuredRecoveryAction {
                kind: "preview_snapshot_restore",
                label: "Preview guarded snapshot restore",
                command: shell_command_line(&preview_argv),
                command_argv: preview_argv,
                mutates: false,
                reason: Some(
                    "preview rechecks the recorded Btrfs snapshot manifest and makes no changes"
                        .to_string(),
                ),
            });
            let command_argv = receipt_json_command_argv(db_path, &session.id);
            actions.push(StructuredRecoveryAction {
                kind: "review_snapshot_restore_withheld",
                label: "Review withheld snapshot restore",
                command: shell_command_line(&command_argv),
                command_argv,
                mutates: false,
                reason: Some(message),
            });
        }
        GuardedSnapshotRestoreReceiptState::Withheld(message) => {
            let command_argv = receipt_json_command_argv(db_path, &session.id);
            actions.push(StructuredRecoveryAction {
                kind: "review_snapshot_restore_withheld",
                label: "Review withheld snapshot restore",
                command: shell_command_line(&command_argv),
                command_argv,
                mutates: false,
                reason: Some(message),
            });
        }
        GuardedSnapshotRestoreReceiptState::Unavailable => {}
    }
    actions
}

fn guarded_snapshot_restore_preview_command(snapshot_id: &str, snapshot_root: &Path) -> String {
    shell_command_line(&guarded_snapshot_restore_preview_command_argv(
        snapshot_id,
        snapshot_root,
    ))
}

fn guarded_snapshot_restore_preview_command_argv(
    snapshot_id: &str,
    snapshot_root: &Path,
) -> Vec<String> {
    let mut argv = guarded_snapshot_restore_command_argv(snapshot_id, Some(snapshot_root));
    argv.push("--preview".to_string());
    argv
}

enum GuardedSnapshotRestoreReceiptState<'a> {
    Available {
        snapshot_id: &'a str,
        snapshot_root: &'a Path,
    },
    PreviewOnly {
        snapshot_id: &'a str,
        snapshot_root: &'a Path,
        message: String,
    },
    Withheld(String),
    Unavailable,
}

fn guarded_snapshot_restore_receipt_state(
    session: &SessionRecord,
) -> GuardedSnapshotRestoreReceiptState<'_> {
    match &session.snapshot_status {
        SnapshotStatus::Created {
            backend,
            snapshot_id,
            snapshot_root,
        } => {
            if matches!(
                session.status,
                SessionStatus::Starting | SessionStatus::Running
            ) {
                return GuardedSnapshotRestoreReceiptState::Withheld(format!(
                    "Snapshot restore is withheld while the session is still {}; wait for the session to finish before recovery.",
                    session_status_label(session.status)
                ));
            }
            if session.status == SessionStatus::Reverted {
                return GuardedSnapshotRestoreReceiptState::Withheld(
                    "Snapshot restore is already recorded as reverted; no guarded restore action is offered."
                        .to_string(),
                );
            }
            if *backend != warder_core::SnapshotBackend::Btrfs {
                return GuardedSnapshotRestoreReceiptState::Withheld(format!(
                    "Guarded snapshot restore is unavailable because the recorded snapshot backend is {}; guarded restore currently supports btrfs only.",
                    snapshot_backend_label(*backend)
                ));
            }
            if let Some(snapshot_root) = snapshot_root {
                match guarded_snapshot_restore_receipt_readiness(snapshot_id, snapshot_root) {
                    Ok(()) => GuardedSnapshotRestoreReceiptState::Available {
                        snapshot_id,
                        snapshot_root,
                    },
                    Err(message) => GuardedSnapshotRestoreReceiptState::PreviewOnly {
                        snapshot_id,
                        snapshot_root,
                        message,
                    },
                }
            } else {
                GuardedSnapshotRestoreReceiptState::Withheld(format!(
                    "Guarded snapshot restore is unavailable because snapshot '{snapshot_id}' does not record a snapshot root."
                ))
            }
        }
        SnapshotStatus::Failed(message) => GuardedSnapshotRestoreReceiptState::Withheld(format!(
            "Do not rely on snapshot recovery for this session; snapshot creation failed: {message}."
        )),
        SnapshotStatus::Reverted { .. } => GuardedSnapshotRestoreReceiptState::Withheld(
            "Snapshot restore is already recorded as reverted; no guarded restore action is offered."
                .to_string(),
        ),
        _ => GuardedSnapshotRestoreReceiptState::Unavailable,
    }
}

fn guarded_snapshot_restore_receipt_readiness(
    snapshot_id: &str,
    snapshot_root: &Path,
) -> Result<(), String> {
    let manifest = load_snapshot_manifest(snapshot_root, snapshot_id)
        .map_err(|error| format!("Guarded snapshot restore is withheld: {}.", error.message))?;
    if manifest.backend != "btrfs" {
        return Err(format!(
            "Guarded snapshot restore is withheld because the manifest backend is {}; guarded restore currently supports btrfs only.",
            manifest.backend
        ));
    }
    if manifest.entries.is_empty() {
        return Err(
            "Guarded snapshot restore is withheld because the snapshot manifest has no entries."
                .to_string(),
        );
    }
    if let Some(blocked) = manifest
        .entries
        .iter()
        .find_map(|entry| revert_preview_entry_blocker(&entry.source_root, &entry.snapshot_path))
    {
        return Err(format!(
            "Guarded snapshot restore is withheld because the current restore plan is blocked: {blocked}."
        ));
    }
    Ok(())
}

fn revert_preview_entry_blocker(source_root: &str, snapshot_path: &str) -> Option<String> {
    let status = revert_preview_entry_status(source_root, snapshot_path);
    if !status.blocked {
        return None;
    }
    let blocked_path = if status.label == "blocked: snapshot path missing" {
        snapshot_path
    } else {
        source_root
    };
    Some(format!("{} at {}", status.label, blocked_path))
}

fn guarded_snapshot_restore_command_for_receipt(
    snapshot_id: &str,
    snapshot_root: Option<&Path>,
    db_path: Option<&Path>,
    session_id: &str,
) -> String {
    shell_command_line(&guarded_snapshot_restore_command_for_receipt_argv(
        snapshot_id,
        snapshot_root,
        db_path,
        session_id,
    ))
}

fn guarded_snapshot_restore_command_for_receipt_argv(
    snapshot_id: &str,
    snapshot_root: Option<&Path>,
    db_path: Option<&Path>,
    session_id: &str,
) -> Vec<String> {
    let mut command = guarded_snapshot_restore_command_argv(snapshot_id, snapshot_root);
    if let Some(db_path) = db_path {
        command.extend([
            "--db".to_string(),
            db_path.display().to_string(),
            "--session".to_string(),
            session_id.to_string(),
        ]);
    }
    command
}

fn guarded_snapshot_restore_command(snapshot_id: &str, snapshot_root: Option<&Path>) -> String {
    shell_command_line(&guarded_snapshot_restore_command_argv(
        snapshot_id,
        snapshot_root,
    ))
}

fn guarded_snapshot_restore_command_argv(
    snapshot_id: &str,
    snapshot_root: Option<&Path>,
) -> Vec<String> {
    vec![
        "warder".to_string(),
        "revert".to_string(),
        "--snapshot".to_string(),
        snapshot_id.to_string(),
        "--snapshot-root".to_string(),
        snapshot_root
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<path>".to_string()),
    ]
}

fn render_review_action_lines(actions: &[StructuredReviewAction]) -> Vec<String> {
    if actions.is_empty() {
        return vec!["- none".to_string()];
    }
    actions
        .iter()
        .map(|action| match &action.command {
            Some(command) => format!(
                "- {}: {command}{}",
                action.label,
                action_reason_suffix(action.reason.as_deref())
            ),
            None => format!(
                "- {}: manual review required{}",
                action.label,
                action_reason_suffix(action.reason.as_deref())
            ),
        })
        .collect()
}

fn render_recovery_action_lines(actions: &[StructuredRecoveryAction]) -> Vec<String> {
    if actions.is_empty() {
        return vec!["- none".to_string()];
    }
    actions
        .iter()
        .map(|action| {
            let mutation_label = if action.mutates { " (mutates)" } else { "" };
            format!(
                "- {}{}: {}{}",
                action.label,
                mutation_label,
                action.command,
                action_reason_suffix(action.reason.as_deref())
            )
        })
        .collect()
}

fn action_reason_suffix(reason: Option<&str>) -> String {
    reason
        .filter(|reason| !reason.is_empty())
        .map(|reason| format!(" (reason: {reason})"))
        .unwrap_or_default()
}

fn journal_command(db_path: Option<&Path>, session_id: &str) -> String {
    shell_command_line(&journal_command_argv(db_path, session_id))
}

fn network_journal_command(db_path: Option<&Path>, session_id: &str) -> String {
    shell_command_line(&network_journal_command_argv(db_path, session_id))
}

fn all_journals_command(db_path: Option<&Path>, session_id: &str) -> String {
    shell_command_line(&all_journals_command_argv(db_path, session_id))
}

fn journal_command_argv(db_path: Option<&Path>, session_id: &str) -> Vec<String> {
    let mut argv = base_journal_command_argv(db_path, session_id);
    argv.push("--file".to_string());
    argv
}

fn network_journal_command_argv(db_path: Option<&Path>, session_id: &str) -> Vec<String> {
    let mut argv = base_journal_command_argv(db_path, session_id);
    argv.push("--network".to_string());
    argv
}

fn all_journals_command_argv(db_path: Option<&Path>, session_id: &str) -> Vec<String> {
    let mut argv = base_journal_command_argv(db_path, session_id);
    argv.push("--all".to_string());
    argv
}

fn base_journal_command_argv(db_path: Option<&Path>, session_id: &str) -> Vec<String> {
    let mut argv = vec!["warder".to_string(), "journal".to_string()];
    if let Some(path) = db_path {
        argv.extend(["--db".to_string(), path.display().to_string()]);
    }
    argv.extend(["--session".to_string(), session_id.to_string()]);
    argv
}

fn receipt_json_command(db_path: Option<&Path>, session_id: &str) -> String {
    shell_command_line(&receipt_json_command_argv(db_path, session_id))
}

fn receipt_json_command_argv(db_path: Option<&Path>, session_id: &str) -> Vec<String> {
    let mut argv = vec!["warder".to_string(), "receipt".to_string()];
    if let Some(path) = db_path {
        argv.extend(["--db".to_string(), path.display().to_string()]);
    }
    argv.extend([
        "--session".to_string(),
        session_id.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ]);
    argv
}

fn doctor_command_argv() -> Vec<String> {
    vec!["warder".to_string(), "doctor".to_string()]
}

fn shell_command_line(command: &[String]) -> String {
    command
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-:+=,@%".contains(&byte))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn package_manager_evidence(command: &[String], joined: &str) -> Vec<String> {
    let mut evidence = Vec::new();
    let Some(program) = command.first().map(String::as_str) else {
        return evidence;
    };
    let action = command.get(1).map(String::as_str);
    match (program, action) {
        ("cargo", Some("add" | "remove" | "update" | "install")) => {
            evidence.push(format!("cargo {}", action.unwrap()));
        }
        ("npm" | "pnpm" | "yarn", Some("install" | "add" | "remove" | "update")) => {
            evidence.push(format!("{program} {}", action.unwrap()));
        }
        ("pip" | "pip3", Some("install" | "uninstall")) => {
            evidence.push(format!("{program} {}", action.unwrap()));
        }
        ("uv", Some("add" | "remove" | "sync" | "pip")) => {
            evidence.push(format!("uv {}", action.unwrap()));
        }
        ("poetry", Some("add" | "remove" | "update" | "install")) => {
            evidence.push(format!("poetry {}", action.unwrap()));
        }
        _ => {}
    }

    for marker in [
        " cargo add ",
        " npm install ",
        " pnpm add ",
        " yarn add ",
        " pip install ",
        " uv add ",
        " poetry add ",
    ] {
        if format!(" {joined} ").contains(marker) {
            evidence.push(marker.trim().to_string());
        }
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

fn dependency_file_evidence(joined: &str) -> Vec<String> {
    let mut evidence = Vec::new();
    for filename in [
        "Cargo.toml",
        "Cargo.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "pyproject.toml",
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
    ] {
        if joined.contains(filename) {
            evidence.push(filename.to_string());
        }
    }
    evidence
}

fn dependency_zone_roots(config: &WarderConfig) -> Vec<PathBuf> {
    config
        .zones
        .iter()
        .flat_map(|zone| zone.paths.iter().cloned())
        .collect()
}

fn scan_dependency_files(zone_roots: &[PathBuf]) -> Result<Vec<DependencyFileSnapshot>, CliError> {
    let mut snapshots = Vec::new();
    for root in zone_roots {
        scan_dependency_files_under_root(root, &mut snapshots)?;
    }
    snapshots.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(snapshots)
}

fn scan_dependency_files_under_root(
    root: &Path,
    snapshots: &mut Vec<DependencyFileSnapshot>,
) -> Result<(), CliError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| CliError {
            message: format!(
                "failed to list dependency scan directory '{}' for receipt diff: {error}",
                directory.display()
            ),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| CliError {
                message: format!(
                    "failed to read dependency scan entry below '{}' for receipt diff: {error}",
                    directory.display()
                ),
            })?;
            let file_type = entry.file_type().map_err(|error| CliError {
                message: format!(
                    "failed to inspect dependency scan entry '{}' for receipt diff: {error}",
                    entry.path().display()
                ),
            })?;
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|filename| KNOWN_DEPENDENCY_FILES.contains(&filename))
            {
                let bytes = std::fs::read(&path).map_err(|error| CliError {
                    message: format!(
                        "failed to read dependency file '{}' for receipt diff: {error}",
                        path.display()
                    ),
                })?;
                snapshots.push(DependencyFileSnapshot {
                    path,
                    content_hash: stable_content_hash(&bytes),
                });
            }
        }
    }
    Ok(())
}

fn diff_dependency_file_snapshots(
    before: &[DependencyFileSnapshot],
    after: &[DependencyFileSnapshot],
) -> Vec<DependencyFileChange> {
    let before_by_path = before
        .iter()
        .map(|snapshot| (&snapshot.path, &snapshot.content_hash))
        .collect::<std::collections::BTreeMap<_, _>>();
    let after_by_path = after
        .iter()
        .map(|snapshot| (&snapshot.path, &snapshot.content_hash))
        .collect::<std::collections::BTreeMap<_, _>>();
    let paths = before_by_path
        .keys()
        .chain(after_by_path.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>();

    paths
        .into_iter()
        .filter_map(
            |path| match (before_by_path.get(path), after_by_path.get(path)) {
                (None, Some(after_hash)) => Some(DependencyFileChange {
                    path: path.clone(),
                    before_hash: None,
                    after_hash: Some((*after_hash).to_string()),
                    status: DependencyFileChangeStatus::Created,
                }),
                (Some(before_hash), None) => Some(DependencyFileChange {
                    path: path.clone(),
                    before_hash: Some((*before_hash).to_string()),
                    after_hash: None,
                    status: DependencyFileChangeStatus::Removed,
                }),
                (Some(before_hash), Some(after_hash)) if before_hash != after_hash => {
                    Some(DependencyFileChange {
                        path: path.clone(),
                        before_hash: Some((*before_hash).to_string()),
                        after_hash: Some((*after_hash).to_string()),
                        status: DependencyFileChangeStatus::Modified,
                    })
                }
                _ => None,
            },
        )
        .collect()
}

fn stable_content_hash(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

const KNOWN_DEPENDENCY_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
];

fn planned_landlock_restrictions(
    config: &WarderConfig,
    environment: &EnvironmentSupport,
) -> warder_enforcement::LandlockPlan {
    let mut rules = config
        .enforcement
        .writable_roots
        .iter()
        .map(|path| LandlockRule {
            path: path.clone(),
            access: LandlockAccess::ReadWrite,
        })
        .collect::<Vec<_>>();
    rules.extend(
        config
            .zones
            .iter()
            .flat_map(|zone| {
                zone.paths.iter().map(|path| LandlockRule {
                    path: path.clone(),
                    access: match zone.write_policy {
                        WritePolicy::Deny => LandlockAccess::ReadOnly,
                        WritePolicy::Allow => LandlockAccess::ReadWrite,
                    },
                })
            })
            .collect::<Vec<_>>(),
    );
    plan_landlock_restrictions(
        match config.enforcement.landlock {
            EnforcementRequirement::Required => LandlockRequirement::Required,
            EnforcementRequirement::BestEffort => LandlockRequirement::BestEffort,
            EnforcementRequirement::Disabled => LandlockRequirement::Disabled,
        },
        LandlockSupport {
            kernel_available: environment.landlock,
            apply_available: landlock_apply_supported(),
        },
        rules,
    )
}

fn landlock_status_from_plan(status: &LandlockPlanStatus) -> LandlockStatus {
    match status {
        LandlockPlanStatus::Apply => LandlockStatus::Pending,
        LandlockPlanStatus::NotRequested => LandlockStatus::NotRequested,
        LandlockPlanStatus::Degraded(message) => LandlockStatus::Degraded(message.clone()),
        LandlockPlanStatus::Blocked(message) => LandlockStatus::Unsupported(message.clone()),
    }
}

fn cgroup_status_from_requirement(requirement: EnforcementRequirement) -> CgroupStatus {
    match requirement {
        EnforcementRequirement::Disabled => CgroupStatus::NotRequested,
        EnforcementRequirement::Required | EnforcementRequirement::BestEffort => {
            CgroupStatus::Pending
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LaunchCgroupTagPlan {
    Tag {
        root: PathBuf,
    },
    Skip {
        status: CgroupStatus,
        reason: Option<String>,
    },
    Blocked(String),
}

fn planned_launch_cgroup_tagging(
    config: &WarderConfig,
    cgroup_root: Option<&PathBuf>,
) -> LaunchCgroupTagPlan {
    match config.enforcement.cgroups {
        EnforcementRequirement::Disabled => LaunchCgroupTagPlan::Skip {
            status: CgroupStatus::NotRequested,
            reason: None,
        },
        EnforcementRequirement::Required => match cgroup_root {
            Some(root) => match cgroup_root_support_issue(root) {
                Some(message) => LaunchCgroupTagPlan::Blocked(message),
                None => LaunchCgroupTagPlan::Tag { root: root.clone() },
            },
            None => LaunchCgroupTagPlan::Blocked(
                "cgroup tagging is required, but --cgroup-root was not provided".to_string(),
            ),
        },
        EnforcementRequirement::BestEffort => match cgroup_root {
            Some(root) => match cgroup_root_support_issue(root) {
                Some(reason) => LaunchCgroupTagPlan::Skip {
                    status: CgroupStatus::Degraded(reason.clone()),
                    reason: Some(reason),
                },
                None => LaunchCgroupTagPlan::Tag { root: root.clone() },
            },
            None => {
                let reason =
                    "cgroup tagging skipped because --cgroup-root was not provided".to_string();
                LaunchCgroupTagPlan::Skip {
                    status: CgroupStatus::Degraded(reason.clone()),
                    reason: Some(reason),
                }
            }
        },
    }
}

fn cgroup_root_support_issue(root: &std::path::Path) -> Option<String> {
    if !root.exists() {
        return Some(format!("cgroup root '{}' does not exist", root.display()));
    }

    if !root.join("cgroup.procs").exists() {
        return Some(format!(
            "cgroup root '{}' does not look like cgroup v2: missing cgroup.procs",
            root.display()
        ));
    }

    None
}

fn start_inotify_file_journal(
    config: &WarderConfig,
) -> Result<InotifyFileJournalWatcher, warder_journal::FileJournalWatchError> {
    let zones = config
        .zones
        .iter()
        .map(|zone| ProtectedJournalZone {
            id: zone.id.clone(),
            root_paths: zone.paths.clone(),
        })
        .collect::<Vec<_>>();
    InotifyFileJournalWatcher::watch_zones(&zones)
}

fn start_ebpf_file_journal(
    config: &WarderConfig,
    environment: &EnvironmentSupport,
) -> Result<
    warder_journal::EbpfFileJournalCollector<warder_journal::LiveEbpfFileAccessReader>,
    warder_journal::FileJournalWatchError,
> {
    if let warder_journal::EbpfFileJournalAttachStatus::Unavailable(message) =
        planned_ebpf_file_journal_attach(environment).status
    {
        return Err(warder_journal::FileJournalWatchError { message });
    }

    let zones = config
        .zones
        .iter()
        .map(|zone| ProtectedJournalZone {
            id: zone.id.clone(),
            root_paths: zone.paths.clone(),
        })
        .collect::<Vec<_>>();
    let reader = warder_journal::LiveEbpfFileAccessReader::attach(
        warder_journal::EbpfFileJournalAttachOptions {
            bpf_fs: PathBuf::from("/sys/fs/bpf"),
        },
    )?;
    Ok(warder_journal::EbpfFileJournalCollector::new(reader, zones))
}

fn start_ebpf_network_journal(
    config: &WarderConfig,
    environment: &EnvironmentSupport,
) -> Result<
    warder_journal::EbpfNetworkJournalCollector<warder_journal::LiveEbpfNetworkEgressReader>,
    warder_journal::FileJournalWatchError,
> {
    if let warder_journal::EbpfNetworkJournalAttachStatus::Unavailable(message) =
        planned_ebpf_network_journal_attach(config, environment).status
    {
        return Err(warder_journal::FileJournalWatchError { message });
    }

    let reader = warder_journal::LiveEbpfNetworkEgressReader::attach(
        warder_journal::EbpfNetworkJournalAttachOptions {
            bpf_fs: PathBuf::from("/sys/fs/bpf"),
        },
    )?;
    Ok(warder_journal::EbpfNetworkJournalCollector::new(reader))
}

fn planned_ebpf_file_journal_attach(
    environment: &EnvironmentSupport,
) -> warder_journal::EbpfFileJournalAttachPlan {
    warder_journal::plan_ebpf_file_journal_attach(warder_journal::EbpfFileJournalSupport {
        bpffs_available: environment.ebpf,
        attach_available: warder_journal::live_ebpf_file_attach_available(),
    })
}

fn persist_inotify_file_journal_events(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    watcher: Option<&mut InotifyFileJournalWatcher>,
) -> Result<(), CliError> {
    let Some(watcher) = watcher else {
        return Ok(());
    };
    let events = watcher
        .read_available_events(session_id, None)
        .map_err(|error| CliError {
            message: error.message,
        })?;
    if events.is_empty() {
        return Ok(());
    }

    let db = WarderDb::open(db_path.into()).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    for event in events {
        db.insert_file_journal_event(&event).map_err(db_error)?;
    }
    Ok(())
}

fn wait_for_child_with_file_journals<R, N>(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    child: &mut Child,
    mut watcher: Option<&mut InotifyFileJournalWatcher>,
    mut ebpf_collector: Option<&mut warder_journal::EbpfFileJournalCollector<R>>,
    mut ebpf_network_collector: Option<&mut warder_journal::EbpfNetworkJournalCollector<N>>,
    mut procfs_network_reader: Option<&mut ProcfsNetworkSocketReader>,
) -> Result<Option<i32>, CliError>
where
    R: warder_journal::EbpfFileAccessReader,
    N: warder_journal::EbpfNetworkEgressReader,
{
    let db_path = db_path.into();
    loop {
        if let Some(watcher) = watcher.as_deref_mut() {
            persist_inotify_file_journal_events(&db_path, session_id, Some(watcher))?;
        }
        if let Some(collector) = ebpf_collector.as_deref_mut() {
            persist_ebpf_file_journal_events(&db_path, session_id, Some(collector))?;
        }
        if let Some(collector) = ebpf_network_collector.as_deref_mut() {
            persist_ebpf_network_journal_events(&db_path, session_id, Some(collector))?;
        }
        if let Some(reader) = procfs_network_reader.as_deref_mut() {
            persist_procfs_network_journal_events(&db_path, session_id, Some(reader))?;
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(watcher) = watcher.as_deref_mut() {
                    persist_inotify_file_journal_events(&db_path, session_id, Some(watcher))?;
                }
                if let Some(collector) = ebpf_collector.as_deref_mut() {
                    persist_ebpf_file_journal_events(&db_path, session_id, Some(collector))?;
                }
                if let Some(collector) = ebpf_network_collector.as_deref_mut() {
                    persist_ebpf_network_journal_events(&db_path, session_id, Some(collector))?;
                }
                if let Some(reader) = procfs_network_reader.as_deref_mut() {
                    persist_procfs_network_journal_events(&db_path, session_id, Some(reader))?;
                }
                let exit_code = status.code();
                finish_session(&db_path, session_id, exit_code, SystemTime::now())?;
                return Ok(exit_code);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let message = format!("failed to wait for supervised command: {error}");
                fail_session(&db_path, session_id, message.clone())?;
                return err(message);
            }
        }
    }
}

fn persist_ebpf_file_journal_events<R>(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    collector: Option<&mut warder_journal::EbpfFileJournalCollector<R>>,
) -> Result<(), CliError>
where
    R: warder_journal::EbpfFileAccessReader,
{
    let Some(collector) = collector else {
        return Ok(());
    };
    let events = collector
        .read_available_events(session_id)
        .map_err(|error| CliError {
            message: error.message,
        })?;
    if events.is_empty() {
        return Ok(());
    }

    let db = WarderDb::open(db_path.into()).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    for event in events {
        db.insert_file_journal_event(&event).map_err(db_error)?;
    }
    Ok(())
}

fn persist_ebpf_network_journal_events<R>(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    collector: Option<&mut warder_journal::EbpfNetworkJournalCollector<R>>,
) -> Result<(), CliError>
where
    R: warder_journal::EbpfNetworkEgressReader,
{
    let Some(collector) = collector else {
        return Ok(());
    };
    let events = collector
        .read_available_events(session_id)
        .map_err(|error| CliError {
            message: error.message,
        })?;
    if events.is_empty() {
        return Ok(());
    }

    let db = WarderDb::open(db_path.into()).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    for event in events {
        db.insert_network_journal_event(&event).map_err(db_error)?;
    }
    Ok(())
}

fn persist_procfs_network_journal_events(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    reader: Option<&mut ProcfsNetworkSocketReader>,
) -> Result<(), CliError> {
    let Some(reader) = reader else {
        return Ok(());
    };
    let events = reader
        .read_available_events()
        .map_err(|error| CliError {
            message: error.message,
        })?
        .into_iter()
        .map(|event| warder_journal::plan_procfs_network_socket_event(session_id, event))
        .collect::<Vec<_>>();
    if events.is_empty() {
        return Ok(());
    }

    let db = WarderDb::open(db_path.into()).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    for event in events {
        db.insert_network_journal_event(&event).map_err(db_error)?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PreparedLandlock {
    Prepared { ruleset_fd: i32 },
    NotRequested,
    Degraded(String),
}

fn prepare_landlock_for_launch(
    plan: &warder_enforcement::LandlockPlan,
) -> Result<PreparedLandlock, warder_enforcement::LandlockApplyError> {
    let mut kernel = SyscallLandlockKernel;
    match prepare_landlock_ruleset_with_kernel(plan, &mut kernel)? {
        LandlockPrepareStatus::Prepared { ruleset_fd } => {
            Ok(PreparedLandlock::Prepared { ruleset_fd })
        }
        LandlockPrepareStatus::NotRequested => Ok(PreparedLandlock::NotRequested),
        LandlockPrepareStatus::Degraded(message) => Ok(PreparedLandlock::Degraded(message)),
        LandlockPrepareStatus::Blocked(message) => {
            Err(warder_enforcement::LandlockApplyError { message })
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_landlock_child_setup(command: &mut Command, prepared: PreparedLandlock) {
    use std::os::unix::process::CommandExt;

    if let PreparedLandlock::Prepared { ruleset_fd } = prepared {
        unsafe {
            command.pre_exec(move || {
                warder_enforcement::restrict_current_process_to_landlock_ruleset(ruleset_fd)
                    .map_err(|error| std::io::Error::other(error.message))
            });
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_landlock_child_setup(_command: &mut Command, _prepared: PreparedLandlock) {}

fn landlock_apply_supported() -> bool {
    cfg!(target_os = "linux")
}

fn set_session_root_pid(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    root_pid: u32,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        session.root_pid = Some(root_pid);
        session.status = SessionStatus::Running;
    })
}

fn finish_session(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    exit_code: Option<i32>,
    ended_at: SystemTime,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        session.ended_at = Some(ended_at);
        session.exit_code = exit_code;
        session.status = match exit_code {
            Some(0) => SessionStatus::Completed,
            _ => SessionStatus::Failed,
        };
    })
}

#[cfg(test)]
fn finish_wait_result(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    wait_result: std::io::Result<ExitStatus>,
) -> Result<Option<i32>, CliError> {
    let db_path = db_path.into();
    match wait_result {
        Ok(status) => {
            let exit_code = status.code();
            finish_session(&db_path, session_id, exit_code, SystemTime::now())?;
            Ok(exit_code)
        }
        Err(error) => {
            let message = format!("failed to wait for supervised command: {error}");
            fail_session(&db_path, session_id, message.clone())?;
            err(message)
        }
    }
}

fn add_session_degraded_reason(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    reason: String,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        if !session
            .degraded_reasons
            .iter()
            .any(|current| current == &reason)
        {
            session.degraded_reasons.push(reason);
        }
    })
}

fn set_session_landlock_status(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    status: LandlockStatus,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        session.landlock_status = status;
    })
}

fn set_session_cgroup_status(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    status: CgroupStatus,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        session.cgroup_path = None;
        session.cgroup_status = status;
    })
}

fn set_session_dependency_file_changes(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    changes: Vec<DependencyFileChange>,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        session.dependency_file_changes = changes;
    })
}

fn fail_session(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    reason: String,
) -> Result<(), CliError> {
    update_session(db_path, session_id, |session| {
        session.status = SessionStatus::Failed;
        session.ended_at = Some(SystemTime::now());
        if !session
            .degraded_reasons
            .iter()
            .any(|current| current == &reason)
        {
            session.degraded_reasons.push(reason);
        }
    })
}

fn update_session(
    db_path: impl Into<PathBuf>,
    session_id: &str,
    update: impl FnOnce(&mut SessionRecord),
) -> Result<(), CliError> {
    let db = WarderDb::open(db_path.into()).map_err(db_error)?;
    db.migrate().map_err(db_error)?;
    let mut session = db
        .get_session(session_id)
        .map_err(db_error)?
        .ok_or_else(|| CliError {
            message: format!("session '{session_id}' was not found"),
        })?;
    update(&mut session);
    db.update_session(&session).map_err(db_error)
}

fn default_db_path() -> PathBuf {
    std::env::var_os("WARDER_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".warder/warder.sqlite3"))
}

fn default_daemon_runtime_path() -> PathBuf {
    std::env::var_os("WARDER_DAEMON_RUNTIME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".warder/daemon.state"))
}

fn generate_session_id() -> String {
    format!("session-{}", uuid::Uuid::new_v4().simple())
}

fn planned_snapshot_status(
    config: &WarderConfig,
    environment: &EnvironmentSupport,
    session_id: &str,
    snapshot_root: Option<&Path>,
) -> Result<SnapshotStatus, CliError> {
    let requirement = planned_snapshot_requirement(config);
    match planned_snapshot_plan_for_requirement(requirement, environment) {
        SnapshotPlan::Create { backend } => match snapshot_root {
            Some(snapshot_root) => {
                let request = SnapshotCreateRequest {
                    session_id: session_id.to_string(),
                    roots: config
                        .zones
                        .iter()
                        .flat_map(|zone| zone.paths.iter().cloned())
                        .collect(),
                };
                let result = match backend {
                    SnapshotBackend::Btrfs => {
                        let driver =
                            BtrfsSnapshotDriver::new(snapshot_root, SystemSnapshotCommandRunner);
                        driver.create_snapshot(&request)
                    }
                    SnapshotBackend::OverlayFs | SnapshotBackend::Unsupported => {
                        let driver = UnsupportedSnapshotDriver::new(
                            backend.clone(),
                            format!(
                                "{} snapshot backend driver is not implemented yet",
                                snapshot_plan_backend_label(&backend)
                            ),
                        );
                        driver.create_snapshot(&request)
                    }
                };
                match result {
                    Ok(outcome) => Ok(SnapshotStatus::Created {
                        backend: snapshot_status_backend_from_plan(outcome.backend),
                        snapshot_id: outcome.snapshot_id,
                        snapshot_root: Some(snapshot_root.to_path_buf()),
                    }),
                    Err(error) if requirement == SnapshotRequirement::Required => {
                        err(format!("snapshot required, but {}", error.message))
                    }
                    Err(error) => Ok(SnapshotStatus::Failed(error.message)),
                }
            }
            None => {
                let message = format!(
                    "{} snapshot creation requires --snapshot-root",
                    snapshot_plan_backend_label(&backend)
                );
                if requirement == SnapshotRequirement::Required {
                    err(format!("snapshot required, but {message}"))
                } else {
                    Ok(SnapshotStatus::Failed(message))
                }
            }
        },
        SnapshotPlan::Skip(_) | SnapshotPlan::NotRequested => Ok(SnapshotStatus::NotRequested),
        SnapshotPlan::Block(message) => err(message),
    }
}

fn snapshot_status_backend_from_plan(backend: SnapshotBackend) -> warder_core::SnapshotBackend {
    match backend {
        SnapshotBackend::Btrfs => warder_core::SnapshotBackend::Btrfs,
        SnapshotBackend::OverlayFs | SnapshotBackend::Unsupported => {
            warder_core::SnapshotBackend::OverlayFs
        }
    }
}

fn planned_snapshot_plan(config: &WarderConfig, environment: &EnvironmentSupport) -> SnapshotPlan {
    planned_snapshot_plan_for_requirement(planned_snapshot_requirement(config), environment)
}

fn planned_snapshot_requirement(config: &WarderConfig) -> SnapshotRequirement {
    config
        .zones
        .iter()
        .fold(SnapshotRequirement::Disabled, |current, zone| {
            strongest_snapshot_requirement(current, zone.snapshot)
        })
}

fn planned_snapshot_plan_for_requirement(
    requirement: SnapshotRequirement,
    environment: &EnvironmentSupport,
) -> SnapshotPlan {
    let has_btrfs = environment
        .snapshot_backends
        .contains(&warder_config::SnapshotBackend::Btrfs);
    if has_btrfs {
        return plan_snapshot(requirement, &[SnapshotBackend::Btrfs]);
    }

    let has_overlayfs = environment
        .snapshot_backends
        .contains(&warder_config::SnapshotBackend::OverlayFs);
    if has_overlayfs {
        return match requirement {
            SnapshotRequirement::Disabled => SnapshotPlan::NotRequested,
            SnapshotRequirement::Required => SnapshotPlan::Block(
                "snapshot required, but overlayfs snapshot backend driver is not implemented yet"
                    .to_string(),
            ),
            SnapshotRequirement::BestEffort => SnapshotPlan::Skip(
                "overlayfs snapshot backend driver is not implemented yet; skipping snapshot"
                    .to_string(),
            ),
        };
    }

    plan_snapshot(requirement, &[])
}

fn strongest_snapshot_requirement(
    current: SnapshotRequirement,
    snapshot: SnapshotPolicy,
) -> SnapshotRequirement {
    match (current, snapshot) {
        (SnapshotRequirement::Required, _) | (_, SnapshotPolicy::Required) => {
            SnapshotRequirement::Required
        }
        (SnapshotRequirement::BestEffort, _) | (_, SnapshotPolicy::BestEffort) => {
            SnapshotRequirement::BestEffort
        }
        _ => SnapshotRequirement::Disabled,
    }
}

#[cfg(test)]
mod tests;
