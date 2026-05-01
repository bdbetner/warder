use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use warder_cli::{
    assess_host_readiness, environment_support_from_probe, known_agent_profile_catalog,
    launch_supervised_run, render_all_journals_from_db, render_dry_run_from_config,
    render_host_readiness, render_session_receipt_from_db, CliCommand, ReadinessLevel,
};
use warder_core::{SessionRecord, SessionStatus};
use warder_gui_support::config::{render_gui_config_toml, GuiConfigDraft};
use warder_gui_support::defaults::{recommended_protections, RecommendedProtection};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRequest {
    pub config_path: PathBuf,
    pub db_path: PathBuf,
    pub agent_id: String,
    pub command: Vec<String>,
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
    render_session_receipt_from_db(db_path, &session_id).map_err(|error| error.message)
}

pub fn render_session_journals_text(
    db_path: Option<PathBuf>,
    session_id: String,
) -> Result<String, String> {
    render_all_journals_from_db(db_path, Some(&session_id)).map_err(|error| error.message)
}

pub fn list_recent_sessions(
    db_path: PathBuf,
    limit: usize,
) -> Result<Vec<RecentSessionSummary>, String> {
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

pub fn build_launch_command_args(request: LaunchRequest) -> Vec<String> {
    build_cli_run_command(
        request.config_path,
        request.db_path,
        request.agent_id,
        request.command,
    )
}

pub fn launch_session(request: LaunchRequest) -> Result<LaunchSessionResult, String> {
    let environment = environment_support_from_probe(warder_daemon::probe_current_host());
    let command = CliCommand::Run {
        config: Some(request.config_path),
        db: Some(request.db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        agent: request.agent_id,
        command: request.command,
    };
    let outcome = launch_supervised_run(&command, &environment, SystemTime::now())
        .map_err(|error| error.message)?;
    let receipt = render_session_receipt_from_db(Some(request.db_path), &outcome.session_id)
        .map_err(|error| error.message)?;

    Ok(LaunchSessionResult {
        session_id: outcome.session_id,
        exit_code: outcome.exit_code,
        validation_warnings: outcome.validation_warnings,
        receipt,
    })
}

pub fn build_cli_run_command(
    config_path: PathBuf,
    db_path: PathBuf,
    agent_id: String,
    command: Vec<String>,
) -> Vec<String> {
    let mut args = vec![
        "warder".to_string(),
        "run".to_string(),
        "--launch".to_string(),
        "--config".to_string(),
        config_path.display().to_string(),
        "--db".to_string(),
        db_path.display().to_string(),
        "--agent".to_string(),
        agent_id,
        "--".to_string(),
    ];
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
fn session_journals_text(db_path: Option<PathBuf>, session_id: String) -> Result<String, String> {
    render_session_journals_text(db_path, session_id)
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
fn build_launch_command(request: LaunchRequest) -> Vec<String> {
    build_launch_command_args(request)
}

#[tauri::command]
fn launch_session_command(request: LaunchRequest) -> Result<LaunchSessionResult, String> {
    launch_session(request)
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
            session_journals_text,
            recent_sessions,
            host_readiness_summary,
            build_launch_command,
            launch_session_command
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Warder desktop");
}

#[cfg(test)]
mod tests;
