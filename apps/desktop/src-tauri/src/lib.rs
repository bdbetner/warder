use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use warder_cli::{
    assess_host_readiness, environment_support_from_probe, known_agent_profile_catalog,
    launch_supervised_run, render_all_journals_from_db, render_dry_run_from_config,
    render_host_readiness, render_pre_launch_readiness_for_run, render_revert_preview,
    render_session_receipt_from_db, render_session_receipt_from_db_with_format,
    restore_snapshot_from_root_for_session, CliCommand, ReadinessLevel, ReceiptFormat,
};
use warder_core::{SessionRecord, SessionStatus};
use warder_gui_support::config::{render_gui_config_toml, GuiConfigDraft};
use warder_gui_support::defaults::{recommended_protections, RecommendedProtection};

const MAX_DESKTOP_COMMAND_ARGS: usize = 64;
const MAX_DESKTOP_COMMAND_ARG_BYTES: usize = 4096;
const MAX_DESKTOP_SESSION_ID_BYTES: usize = 128;
const MAX_RECENT_SESSION_LIMIT: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRequest {
    pub config_path: PathBuf,
    pub db_path: PathBuf,
    pub agent_id: String,
    pub command: Vec<String>,
    pub require_enforcement: bool,
    pub receipt_key_path: Option<PathBuf>,
    pub accept_degraded: bool,
    pub readiness_reviewed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSessionResult {
    pub session_id: String,
    pub exit_code: Option<i32>,
    pub validation_warnings: Vec<String>,
    pub receipt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentSessionSummary {
    pub id: String,
    pub status: String,
    pub command: String,
    pub started_at_unix_seconds: u64,
    pub file_journal_events: usize,
    pub network_journal_events: usize,
    pub degraded_reasons: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostReadinessSummary {
    pub level: String,
    pub summary: String,
    pub blocked_reasons: Vec<String>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPaths {
    pub project_root: PathBuf,
    pub config_path: PathBuf,
    pub db_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileTemplateCatalogEntry {
    pub id: String,
    pub declared_command: String,
    pub summary: String,
    pub preflight: String,
    pub effect: String,
    pub template: ProfileSetupTemplate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSetupTemplate {
    pub recommended_protected_paths: Vec<ProfileProtectedPathTemplate>,
    pub writable_roots: Vec<String>,
    pub network_journal: bool,
    pub snapshot: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileProtectedPathTemplate {
    pub label: String,
    pub path: String,
    pub resolved_path: String,
    pub read: bool,
    pub write: bool,
}

pub fn load_recommended_protections_for_current_home() -> Result<Vec<RecommendedProtection>, String>
{
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(load_recommended_protections_for_home(PathBuf::from(home)))
}

pub fn load_recommended_protections_for_home(home: PathBuf) -> Vec<RecommendedProtection> {
    recommended_protections(home)
}

pub fn load_profile_templates() -> Result<Vec<ProfileTemplateCatalogEntry>, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let cwd =
        std::env::current_dir().map_err(|error| format!("failed to read current dir: {error}"))?;
    load_profile_templates_for_context(PathBuf::from(home), cwd)
}

pub fn default_desktop_paths() -> Result<DesktopPaths, String> {
    let project_root =
        std::env::current_dir().map_err(|error| format!("failed to read current dir: {error}"))?;
    Ok(DesktopPaths {
        config_path: project_root.join(".warder/gui.toml"),
        db_path: project_root.join(".warder/warder.sqlite3"),
        project_root,
    })
}

pub fn load_profile_templates_for_context(
    home: PathBuf,
    cwd: PathBuf,
) -> Result<Vec<ProfileTemplateCatalogEntry>, String> {
    let home = home.display().to_string();
    let cwd = cwd.display().to_string();
    Ok(known_agent_profile_catalog()
        .into_iter()
        .map(|entry| ProfileTemplateCatalogEntry {
            id: entry.id.to_string(),
            declared_command: entry.declared_command.to_string(),
            summary: entry.summary.to_string(),
            preflight: entry.preflight.to_string(),
            effect: entry.effect.to_string(),
            template: ProfileSetupTemplate {
                recommended_protected_paths: entry
                    .template
                    .recommended_protected_paths
                    .into_iter()
                    .map(|path| ProfileProtectedPathTemplate {
                        label: path.label.to_string(),
                        path: path.path.to_string(),
                        resolved_path: resolve_template_path(path.path, &home, &cwd),
                        read: path.read,
                        write: path.write,
                    })
                    .collect(),
                writable_roots: entry
                    .template
                    .writable_roots
                    .into_iter()
                    .map(|path| resolve_template_path(path, &home, &cwd))
                    .collect(),
                network_journal: entry.template.network_journal,
                snapshot: entry.template.snapshot.to_string(),
            },
        })
        .collect())
}

fn resolve_template_path(path: &str, home: &str, cwd: &str) -> String {
    path.replace("$HOME", home).replace("$PWD", cwd)
}

pub fn save_gui_config_file(config_path: PathBuf, draft: GuiConfigDraft) -> Result<(), String> {
    validate_desktop_path(&config_path, "config path")?;
    let rendered = render_gui_config_toml(&draft)?;
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create config directory: {error}"))?;
    }
    fs::write(&config_path, rendered).map_err(|error| {
        format!(
            "failed to write config '{}': {error}",
            config_path.display()
        )
    })
}

pub fn render_dry_run_text(
    config_path: PathBuf,
    agent_id: String,
    command: Vec<String>,
) -> Result<String, String> {
    validate_desktop_path(&config_path, "config path")?;
    validate_desktop_command(&command)?;
    let environment = environment_support_from_probe(warder_daemon::probe_current_host());
    render_dry_run_from_config(Some(config_path), &agent_id, &command, &environment)
        .map_err(|error| error.message)
}

pub fn host_readiness() -> Result<HostReadinessSummary, String> {
    let report = assess_host_readiness(warder_daemon::probe_current_host());
    Ok(HostReadinessSummary {
        level: readiness_level_label(report.level).to_string(),
        summary: render_host_readiness(&report),
        blocked_reasons: report.blocked_reasons,
        degraded_reasons: report.degraded_reasons,
    })
}

pub fn render_session_receipt_text(
    db_path: Option<PathBuf>,
    session_id: String,
) -> Result<String, String> {
    validate_optional_desktop_path(db_path.as_ref(), "database path")?;
    validate_desktop_session_id(&session_id)?;
    render_session_receipt_from_db(db_path, &session_id).map_err(|error| error.message)
}

pub fn render_session_receipt_json_text(
    db_path: Option<PathBuf>,
    session_id: String,
) -> Result<String, String> {
    validate_optional_desktop_path(db_path.as_ref(), "database path")?;
    validate_desktop_session_id(&session_id)?;
    render_session_receipt_from_db_with_format(db_path, &session_id, ReceiptFormat::Json)
        .map_err(|error| error.message)
}

pub fn render_session_journals_text(
    db_path: Option<PathBuf>,
    session_id: String,
) -> Result<String, String> {
    validate_optional_desktop_path(db_path.as_ref(), "database path")?;
    validate_desktop_session_id(&session_id)?;
    render_all_journals_from_db(db_path, Some(&session_id)).map_err(|error| error.message)
}

pub fn render_snapshot_revert_preview(
    snapshot_root: PathBuf,
    snapshot_id: String,
) -> Result<String, String> {
    validate_desktop_path(&snapshot_root, "snapshot root")?;
    validate_desktop_token(&snapshot_id, "snapshot id")?;
    render_revert_preview(snapshot_root, &snapshot_id).map_err(|error| error.message)
}

pub fn restore_snapshot_for_session(
    db_path: PathBuf,
    session_id: String,
    snapshot_root: PathBuf,
    snapshot_id: String,
) -> Result<String, String> {
    validate_desktop_path(&db_path, "database path")?;
    validate_desktop_path(&snapshot_root, "snapshot root")?;
    validate_desktop_session_id(&session_id)?;
    validate_desktop_token(&snapshot_id, "snapshot id")?;
    restore_snapshot_from_root_for_session(db_path, &session_id, snapshot_root, &snapshot_id)
        .map_err(|error| error.message)
}

pub fn list_recent_sessions(
    db_path: PathBuf,
    limit: usize,
) -> Result<Vec<RecentSessionSummary>, String> {
    validate_desktop_path(&db_path, "database path")?;
    let limit = limit.min(MAX_RECENT_SESSION_LIMIT);
    let db = warder_db::WarderDb::open(db_path).map_err(|error| format!("{error:?}"))?;
    db.migrate().map_err(|error| format!("{error:?}"))?;
    let mut sessions = db.list_sessions().map_err(|error| format!("{error:?}"))?;
    sessions.sort_by(|left, right| {
        right
            .started_at
            .cmp(&left.started_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    let mut summaries = Vec::new();
    for session in sessions.into_iter().take(limit) {
        let file_journal_events = db
            .list_file_journal_events(Some(&session.id))
            .map_err(|error| format!("{error:?}"))?
            .len();
        let network_journal_events = db
            .list_network_journal_events(Some(&session.id))
            .map_err(|error| format!("{error:?}"))?
            .len();
        summaries.push(recent_session_summary(
            session,
            file_journal_events,
            network_journal_events,
        ));
    }
    Ok(summaries)
}

pub fn build_launch_command_args(request: LaunchRequest) -> Result<Vec<String>, String> {
    validate_launch_request(&request)?;
    Ok(build_cli_run_command(
        request.config_path,
        request.db_path,
        request.agent_id,
        request.command,
        request.require_enforcement,
        request.receipt_key_path.clone(),
        request.accept_degraded,
    ))
}

pub fn launch_session(request: LaunchRequest) -> Result<LaunchSessionResult, String> {
    validate_launch_request(&request)?;
    if !request.readiness_reviewed {
        return Err(
            "launch refused until launch readiness has been reviewed in the desktop app"
                .to_string(),
        );
    }
    let environment = environment_support_from_probe(warder_daemon::probe_current_host());
    let command = launch_request_to_cli_command(request.clone());
    let outcome = launch_supervised_run(&command, &environment, SystemTime::now())
        .map_err(|error| error.message)?;
    let receipt = warder_cli::render_session_receipt_from_db_with_options(
        Some(request.db_path),
        &outcome.session_id,
        ReceiptFormat::Text,
        request.receipt_key_path.as_deref(),
        None,
    )
    .map_err(|error| error.message)?;

    Ok(LaunchSessionResult {
        session_id: outcome.session_id,
        exit_code: outcome.exit_code,
        validation_warnings: outcome.validation_warnings,
        receipt,
    })
}

pub fn render_launch_readiness_text(request: LaunchRequest) -> Result<String, String> {
    validate_launch_request(&request)?;
    let environment = environment_support_from_probe(warder_daemon::probe_current_host());
    let command = launch_request_to_cli_command(request);
    render_pre_launch_readiness_for_run(&command, &environment).map_err(|error| error.message)
}

fn launch_request_to_cli_command(request: LaunchRequest) -> CliCommand {
    CliCommand::Run {
        config: Some(request.config_path),
        db: Some(request.db_path),
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: request.require_enforcement,
        receipt_key: request.receipt_key_path,
        accept_degraded: request.accept_degraded,
        allow_root: false,
        agent: request.agent_id,
        command: request.command,
    }
}

fn validate_launch_request(request: &LaunchRequest) -> Result<(), String> {
    validate_desktop_path(&request.config_path, "config path")?;
    validate_desktop_path(&request.db_path, "database path")?;
    validate_optional_desktop_path(request.receipt_key_path.as_ref(), "receipt key path")?;
    validate_desktop_token(&request.agent_id, "agent id")?;
    validate_desktop_command(&request.command)
}

fn validate_optional_desktop_path(path: Option<&PathBuf>, label: &str) -> Result<(), String> {
    match path {
        Some(path) => validate_desktop_path(path, label),
        None => Ok(()),
    }
}

fn validate_desktop_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be absolute"));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(format!("{label} must not contain traversal components"));
    }
    Ok(())
}

fn validate_desktop_session_id(session_id: &str) -> Result<(), String> {
    validate_desktop_token(session_id, "session id")
}

fn validate_desktop_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_DESKTOP_SESSION_ID_BYTES {
        return Err(format!("{label} length is invalid"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

fn validate_desktop_command(command: &[String]) -> Result<(), String> {
    if command.is_empty() {
        return Err("command must not be empty".to_string());
    }
    if command.len() > MAX_DESKTOP_COMMAND_ARGS {
        return Err(format!(
            "command has too many arguments; maximum is {MAX_DESKTOP_COMMAND_ARGS}"
        ));
    }
    if command
        .iter()
        .any(|argument| argument.is_empty() || argument.len() > MAX_DESKTOP_COMMAND_ARG_BYTES)
    {
        return Err(format!(
            "command arguments must be non-empty and at most {MAX_DESKTOP_COMMAND_ARG_BYTES} bytes"
        ));
    }
    if command
        .iter()
        .any(|argument| argument.as_bytes().contains(&0))
    {
        return Err("command arguments must not contain NUL bytes".to_string());
    }
    Ok(())
}

pub fn build_cli_run_command(
    config_path: PathBuf,
    db_path: PathBuf,
    agent_id: String,
    command: Vec<String>,
    require_enforcement: bool,
    receipt_key_path: Option<PathBuf>,
    accept_degraded: bool,
) -> Vec<String> {
    let mut args = vec![
        "warder".to_string(),
        "run".to_string(),
        "--launch".to_string(),
        "--config".to_string(),
        config_path.display().to_string(),
        "--db".to_string(),
        db_path.display().to_string(),
    ];
    if require_enforcement {
        args.push("--require-enforcement".to_string());
    }
    if let Some(path) = receipt_key_path {
        args.extend(["--receipt-key".to_string(), path.display().to_string()]);
    }
    if accept_degraded {
        args.push("--accept-degraded".to_string());
    }
    args.extend(["--agent".to_string(), agent_id, "--".to_string()]);
    args.extend(command);
    args
}

fn recent_session_summary(
    session: SessionRecord,
    file_journal_events: usize,
    network_journal_events: usize,
) -> RecentSessionSummary {
    let degraded_reasons = session.degraded_reasons.len();
    RecentSessionSummary {
        id: session.id,
        status: session_status_label(session.status).to_string(),
        command: session.command.join(" "),
        started_at_unix_seconds: session
            .started_at
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
        file_journal_events,
        network_journal_events,
        degraded_reasons,
    }
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

fn readiness_level_label(level: ReadinessLevel) -> &'static str {
    match level {
        ReadinessLevel::Strong => "strong",
        ReadinessLevel::Degraded => "degraded",
        ReadinessLevel::Blocked => "blocked",
    }
}

#[tauri::command]
fn load_recommended_protections() -> Result<Vec<RecommendedProtection>, String> {
    load_recommended_protections_for_current_home()
}

#[tauri::command]
fn load_profile_template_catalog() -> Result<Vec<ProfileTemplateCatalogEntry>, String> {
    load_profile_templates()
}

#[tauri::command]
fn save_gui_config(config_path: PathBuf, draft: GuiConfigDraft) -> Result<(), String> {
    save_gui_config_file(config_path, draft)
}

#[tauri::command]
fn dry_run_text(
    config_path: PathBuf,
    agent_id: String,
    command: Vec<String>,
) -> Result<String, String> {
    render_dry_run_text(config_path, agent_id, command)
}

#[tauri::command]
fn session_receipt_text(db_path: Option<PathBuf>, session_id: String) -> Result<String, String> {
    render_session_receipt_text(db_path, session_id)
}

#[tauri::command]
fn session_receipt_json(db_path: Option<PathBuf>, session_id: String) -> Result<String, String> {
    render_session_receipt_json_text(db_path, session_id)
}

#[tauri::command]
fn session_journals_text(db_path: Option<PathBuf>, session_id: String) -> Result<String, String> {
    render_session_journals_text(db_path, session_id)
}

#[tauri::command]
fn snapshot_revert_preview(snapshot_root: PathBuf, snapshot_id: String) -> Result<String, String> {
    render_snapshot_revert_preview(snapshot_root, snapshot_id)
}

#[tauri::command]
fn snapshot_revert_session(
    db_path: PathBuf,
    session_id: String,
    snapshot_root: PathBuf,
    snapshot_id: String,
) -> Result<String, String> {
    restore_snapshot_for_session(db_path, session_id, snapshot_root, snapshot_id)
}

#[tauri::command]
fn recent_sessions(
    db_path: PathBuf,
    limit: Option<usize>,
) -> Result<Vec<RecentSessionSummary>, String> {
    list_recent_sessions(db_path, limit.unwrap_or(20))
}

#[tauri::command]
fn host_readiness_summary() -> Result<HostReadinessSummary, String> {
    host_readiness()
}

#[tauri::command]
fn desktop_default_paths() -> Result<DesktopPaths, String> {
    default_desktop_paths()
}

#[tauri::command]
fn build_launch_command(request: LaunchRequest) -> Result<Vec<String>, String> {
    build_launch_command_args(request)
}

#[tauri::command]
fn launch_session_command(request: LaunchRequest) -> Result<LaunchSessionResult, String> {
    launch_session(request)
}

#[tauri::command]
fn launch_readiness_text(request: LaunchRequest) -> Result<String, String> {
    render_launch_readiness_text(request)
}

#[tauri::command]
fn app_ready() -> &'static str {
    "warder desktop ready"
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_ready,
            load_recommended_protections,
            load_profile_template_catalog,
            save_gui_config,
            dry_run_text,
            session_receipt_text,
            session_receipt_json,
            session_journals_text,
            snapshot_revert_preview,
            snapshot_revert_session,
            recent_sessions,
            host_readiness_summary,
            desktop_default_paths,
            build_launch_command,
            launch_readiness_text,
            launch_session_command
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Warder desktop");
}

#[cfg(test)]
mod tests;
