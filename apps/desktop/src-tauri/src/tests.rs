use crate::{
    build_cli_run_command, host_readiness, launch_session, list_recent_sessions,
    load_profile_templates_for_context, load_recommended_protections_for_home, render_dry_run_text,
    render_launch_readiness_text, render_session_journals_text, render_session_receipt_json_text,
    render_session_receipt_text, restore_snapshot_for_session, save_gui_config_file, LaunchRequest,
};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};
use warder_core::{CgroupStatus, LandlockStatus, SessionRecord, SessionStatus, SnapshotStatus};
use warder_gui_support::config::{GuiAgentConfig, GuiConfigDraft, GuiProtectedPath};

#[test]
fn recommended_protections_are_available_to_frontend() {
    let protections = load_recommended_protections_for_home(PathBuf::from("/home/alex"));
    assert!(protections
        .iter()
        .any(|item| item.path == "/home/alex/.ssh"));
    assert!(protections.iter().any(|item| item.path == "/etc"));
}

#[test]
fn profile_templates_are_available_to_setup_wizard() {
    let templates = load_profile_templates_for_context(
        PathBuf::from("/home/alex"),
        PathBuf::from("/home/alex/project"),
    )
    .expect("profile templates");
    let codex = templates
        .iter()
        .find(|template| template.id == "codex-cli")
        .expect("codex template");

    assert_eq!(codex.declared_command, "codex");
    assert!(codex.template.network_journal);
    assert_eq!(codex.template.snapshot, "best-effort");
    assert_eq!(codex.template.writable_roots, vec!["/home/alex/project"]);
    assert!(codex
        .template
        .recommended_protected_paths
        .iter()
        .any(|path| path.path == "$HOME/.ssh"
            && path.resolved_path == "/home/alex/.ssh"
            && path.read
            && path.write));
}

#[test]
fn build_cli_run_command_includes_launch_and_db() {
    let command = build_cli_run_command(
        PathBuf::from("/tmp/warder/config.toml"),
        PathBuf::from("/tmp/warder/warder.sqlite3"),
        "codex".to_string(),
        vec!["codex".to_string(), "--yolo".to_string()],
        true,
        Some(PathBuf::from("/run/warder-key")),
        false,
    );

    assert_eq!(
        command,
        vec![
            "warder",
            "run",
            "--launch",
            "--config",
            "/tmp/warder/config.toml",
            "--db",
            "/tmp/warder/warder.sqlite3",
            "--require-enforcement",
            "--receipt-key",
            "/run/warder-key",
            "--agent",
            "codex",
            "--",
            "codex",
            "--yolo"
        ]
    );
}

#[test]
fn build_cli_run_command_includes_degraded_acknowledgement_when_requested() {
    let command = build_cli_run_command(
        PathBuf::from("/tmp/warder/config.toml"),
        PathBuf::from("/tmp/warder/warder.sqlite3"),
        "codex".to_string(),
        vec!["codex".to_string()],
        false,
        None,
        true,
    );

    assert!(command
        .iter()
        .any(|argument| argument == "--accept-degraded"));
    assert!(!command
        .iter()
        .any(|argument| argument == "--require-enforcement"));
}

#[test]
fn render_launch_readiness_text_reports_gui_launch_decision() {
    let root =
        std::env::temp_dir().join(format!("warder-desktop-readiness-{}", std::process::id()));
    let protected = root.join("protected");
    let config_path = root.join("gui.toml");
    let db_path = root.join("warder.sqlite3");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&protected).expect("protected root");

    save_gui_config_file(
        config_path.clone(),
        GuiConfigDraft {
            agent: GuiAgentConfig {
                id: "local-agent".to_string(),
                label: "Local Agent".to_string(),
                command: "sh".to_string(),
                profile: None,
            },
            protected_paths: vec![GuiProtectedPath {
                id: "protected".to_string(),
                label: "Protected".to_string(),
                path: protected.display().to_string(),
                read_protected: false,
                write_protected: true,
                snapshot: false,
            }],
            network_journal: false,
        },
    )
    .expect("config saved");

    let readiness = render_launch_readiness_text(LaunchRequest {
        config_path,
        db_path,
        agent_id: "local-agent".to_string(),
        require_enforcement: false,
        receipt_key_path: None,
        accept_degraded: true,
        readiness_reviewed: false,
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    })
    .expect("launch readiness");

    assert!(readiness.contains("launch readiness: degraded"));
    assert!(readiness.contains("launch visibility limits:"));
    assert!(readiness.contains("fd-write and mmap eBPF observations"));
    assert!(readiness.contains("launch decision: degraded launch accepted"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn desktop_commands_reject_traversal_paths_and_oversized_commands() {
    let error = render_dry_run_text(
        PathBuf::from("relative.toml"),
        "local-agent".to_string(),
        vec!["sh".to_string()],
    )
    .unwrap_err();
    assert!(error.contains("config path must be absolute"));

    let error = render_dry_run_text(
        PathBuf::from("/tmp/../tmp/warder.toml"),
        "local-agent".to_string(),
        vec!["sh".to_string()],
    )
    .unwrap_err();
    assert!(error.contains("config path must not contain traversal"));

    let error = render_dry_run_text(
        PathBuf::from("/tmp/warder.toml"),
        "local-agent".to_string(),
        vec!["sh".to_string(); 65],
    )
    .unwrap_err();
    assert!(error.contains("too many arguments"));
}

#[test]
fn desktop_receipt_reader_rejects_invalid_session_ids() {
    let error = render_session_receipt_text(
        Some(PathBuf::from("/tmp/warder.sqlite3")),
        "../session".to_string(),
    )
    .unwrap_err();

    assert!(error.contains("session id contains unsupported characters"));
}

#[test]
fn desktop_capability_file_keeps_plugin_permissions_narrow() {
    let capability_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("capabilities/main.json");
    let capability = std::fs::read_to_string(capability_path).expect("capability file");

    assert!(capability.contains("\"windows\": [\"main\"]"));
    assert!(capability.contains("\"core:default\""));
    for forbidden in [
        "fs:", "shell:", "dialog:", "http:", "updater:", "opener:", "process:",
    ] {
        assert!(
            !capability.contains(forbidden),
            "desktop capability should not include broad plugin permission {forbidden}"
        );
    }
}

#[test]
fn desktop_tauri_config_sets_restrictive_csp() {
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");
    let config = std::fs::read_to_string(config_path).expect("tauri config");
    let csp_line = config
        .lines()
        .find(|line| line.contains("\"csp\""))
        .expect("csp line");

    assert!(csp_line.contains("\"csp\": \"default-src 'self'"));
    assert!(csp_line.contains("object-src 'none'"));
    assert!(csp_line.contains("frame-ancestors 'none'"));
    for forbidden in ["\"csp\": null", "'unsafe-eval'", "https:", "http://*"] {
        assert!(
            !csp_line.contains(forbidden),
            "desktop CSP should not include {forbidden}"
        );
    }
}

#[test]
fn desktop_frontend_does_not_render_untrusted_html() {
    let frontend_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../src");
    let mut checked_files = 0;
    let entries = std::fs::read_dir(frontend_root).expect("frontend src dir");

    for entry in entries {
        let path = entry.expect("frontend entry").path();
        if !matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("tsx") | Some("ts")
        ) {
            continue;
        }

        checked_files += 1;
        let source = std::fs::read_to_string(&path).expect("frontend source");
        assert!(
            !source.contains("dangerouslySetInnerHTML"),
            "{} must not bypass React escaping for receipt or config text",
            path.display()
        );
        assert!(
            !source.contains(".innerHTML"),
            "{} must not assign raw HTML from receipt or config text",
            path.display()
        );
    }

    assert!(
        checked_files > 0,
        "frontend XSS audit did not inspect files"
    );
}

#[test]
fn desktop_tauri_config_rebuilds_cli_before_packaging() {
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json");
    let config = std::fs::read_to_string(config_path).expect("tauri config");

    assert!(config.contains(
        "\"beforeBuildCommand\": \"npm run build && cargo build --release -p warder-cli\""
    ));
    assert!(config.contains("\"/usr/bin/warder\": \"../../../target/release/warder\""));
}

#[test]
fn host_readiness_is_available_to_frontend() {
    let readiness = host_readiness().expect("host readiness");

    assert!(["strong", "degraded", "blocked"].contains(&readiness.level.as_str()));
    assert!(!readiness.summary.trim().is_empty());
    assert_eq!(
        readiness.blocked_reasons.is_empty(),
        !readiness.summary.contains("blocked reasons:")
    );
}

#[test]
fn save_gui_config_writes_valid_toml() {
    let config_path =
        std::env::temp_dir().join(format!("warder-desktop-test-{}.toml", std::process::id()));
    let _ = std::fs::remove_file(&config_path);

    save_gui_config_file(
        config_path.clone(),
        GuiConfigDraft {
            agent: GuiAgentConfig {
                id: "local-agent".to_string(),
                label: "Local Agent".to_string(),
                command: "codex".to_string(),
                profile: Some("codex-cli".to_string()),
            },
            protected_paths: vec![GuiProtectedPath {
                id: "ssh".to_string(),
                label: "SSH keys".to_string(),
                path: "/home/alex/.ssh".to_string(),
                read_protected: true,
                write_protected: true,
                snapshot: false,
            }],
            network_journal: false,
        },
    )
    .expect("config saved");

    let saved = std::fs::read_to_string(&config_path).expect("saved config");
    assert!(saved.contains("id = \"ssh\""));
    assert!(saved.contains("profile = \"codex-cli\""));
    warder_config::WarderConfig::from_toml(&saved).expect("valid Warder config");

    let _ = std::fs::remove_file(config_path);
}

#[test]
fn missing_session_receipt_returns_readable_error() {
    let db_path = std::env::temp_dir().join(format!(
        "warder-desktop-missing-session-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db_path);
    let db = warder_db::WarderDb::open(&db_path).expect("db opened");
    db.migrate().expect("db migrated");

    let error = render_session_receipt_text(Some(db_path.clone()), "missing-session".to_string())
        .unwrap_err();
    assert!(error.contains("session"));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn session_receipt_json_returns_structured_receipt_for_log_viewer() {
    let db_path = std::env::temp_dir().join(format!(
        "warder-desktop-receipt-json-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db_path);
    let db = warder_db::WarderDb::open(&db_path).expect("db opened");
    db.migrate().expect("db migrated");
    db.create_session(&session_record(
        "json-session",
        UNIX_EPOCH + Duration::from_secs(25),
        SessionStatus::Completed,
    ))
    .expect("session");

    let receipt =
        render_session_receipt_json_text(Some(db_path.clone()), "json-session".to_string())
            .expect("json receipt");

    assert!(receipt.contains("\"session_id\": \"json-session\""));
    assert!(receipt.contains("\"status\": \"completed\""));
    assert!(receipt.contains("\"landlock\": {"));
    assert!(receipt.contains("\"status\": \"not_requested\""));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn desktop_recovery_commands_reject_unsafe_inputs_before_restore() {
    let error = restore_snapshot_for_session(
        PathBuf::from("/tmp/warder.sqlite3"),
        "../session".to_string(),
        PathBuf::from("/tmp/snapshots"),
        "snapshot-id".to_string(),
    )
    .unwrap_err();
    assert!(error.contains("session id contains unsupported characters"));

    let error = restore_snapshot_for_session(
        PathBuf::from("/tmp/warder.sqlite3"),
        "session-id".to_string(),
        PathBuf::from("/tmp/../snapshots"),
        "snapshot-id".to_string(),
    )
    .unwrap_err();
    assert!(error.contains("snapshot root must not contain traversal"));
}

#[test]
fn recent_sessions_are_listed_newest_first_for_log_viewer() {
    let db_path = std::env::temp_dir().join(format!(
        "warder-desktop-sessions-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db_path);
    let db = warder_db::WarderDb::open(&db_path).expect("db opened");
    db.migrate().expect("db migrated");

    db.create_session(&session_record(
        "older-session",
        UNIX_EPOCH + Duration::from_secs(10),
        SessionStatus::Completed,
    ))
    .expect("older session");
    db.create_session(&session_record(
        "newer-session",
        UNIX_EPOCH + Duration::from_secs(20),
        SessionStatus::Failed,
    ))
    .expect("newer session");

    let sessions = list_recent_sessions(db_path.clone(), 10).expect("recent sessions");

    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].id, "newer-session");
    assert_eq!(sessions[0].status, "failed");
    assert_eq!(sessions[0].command, "sh -c false");
    assert_eq!(sessions[1].id, "older-session");

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn recent_sessions_include_review_counts_for_log_viewer() {
    let db_path = std::env::temp_dir().join(format!(
        "warder-desktop-session-counts-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db_path);
    let db = warder_db::WarderDb::open(&db_path).expect("db opened");
    db.migrate().expect("db migrated");

    let mut session = session_record(
        "counted-session",
        UNIX_EPOCH + Duration::from_secs(40),
        SessionStatus::Completed,
    );
    session
        .degraded_reasons
        .push("cgroup tagging unavailable".to_string());
    db.create_session(&session).expect("session");
    db.insert_file_journal_event(&warder_journal::FileJournalEvent {
        session_id: "counted-session".to_string(),
        timestamp: UNIX_EPOCH + Duration::from_secs(41),
        process_id: Some(4242),
        protected_zone_id: Some("protected".to_string()),
        path: PathBuf::from("/tmp/protected/notes.md"),
        operation: warder_journal::FileOperation::Write,
        decision: warder_journal::FileDecision::Observed,
        source: warder_journal::JournalSource::Inotify,
        confidence: warder_journal::JournalConfidence::Observed,
        attribution: warder_journal::JournalAttribution::SessionWindow,
        message: "file activity observed by inotify".to_string(),
    })
    .expect("file event");
    db.insert_network_journal_event(&warder_journal::NetworkJournalEvent {
        session_id: "counted-session".to_string(),
        timestamp: UNIX_EPOCH + Duration::from_secs(42),
        process_id: Some(4242),
        destination: "203.0.113.10".to_string(),
        destination_port: Some(443),
        protocol: warder_journal::NetworkProtocol::Tcp,
        decision: warder_journal::NetworkDecision::Observed,
        source: warder_journal::JournalSource::Ebpf,
        confidence: warder_journal::JournalConfidence::Observed,
        attribution: warder_journal::JournalAttribution::DirectProcess,
        message: "network egress observed by eBPF".to_string(),
    })
    .expect("network event");

    let sessions = list_recent_sessions(db_path.clone(), 10).expect("recent sessions");

    assert_eq!(sessions[0].id, "counted-session");
    assert_eq!(sessions[0].file_journal_events, 1);
    assert_eq!(sessions[0].network_journal_events, 1);
    assert_eq!(sessions[0].degraded_reasons, 1);

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn session_journals_text_reads_recorded_file_activity_for_log_viewer() {
    let db_path = std::env::temp_dir().join(format!(
        "warder-desktop-journals-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db_path);
    let db = warder_db::WarderDb::open(&db_path).expect("db opened");
    db.migrate().expect("db migrated");
    db.create_session(&session_record(
        "journal-session",
        UNIX_EPOCH + Duration::from_secs(30),
        SessionStatus::Completed,
    ))
    .expect("session");
    db.insert_file_journal_event(&warder_journal::FileJournalEvent {
        session_id: "journal-session".to_string(),
        timestamp: UNIX_EPOCH + Duration::from_secs(31),
        process_id: Some(4242),
        protected_zone_id: Some("protected".to_string()),
        path: PathBuf::from("/tmp/protected/notes.md"),
        operation: warder_journal::FileOperation::Write,
        decision: warder_journal::FileDecision::Observed,
        source: warder_journal::JournalSource::Inotify,
        confidence: warder_journal::JournalConfidence::Observed,
        attribution: warder_journal::JournalAttribution::SessionWindow,
        message: "file activity observed by inotify".to_string(),
    })
    .expect("file event");

    let journals =
        render_session_journals_text(Some(db_path.clone()), "journal-session".to_string())
            .expect("journals");

    assert!(journals.contains("file journal: 1 event(s)"));
    assert!(journals.contains("/tmp/protected/notes.md"));
    assert!(journals.contains("network journal: no events"));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn launch_session_runs_supervised_command_and_returns_receipt() {
    let root = std::env::temp_dir().join(format!("warder-desktop-launch-{}", std::process::id()));
    let protected = root.join("protected");
    let config_path = root.join("gui.toml");
    let db_path = root.join("warder.sqlite3");
    let touched_path = protected.join("hello.txt");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&protected).expect("protected root");

    save_gui_config_file(
        config_path.clone(),
        GuiConfigDraft {
            agent: GuiAgentConfig {
                id: "local-agent".to_string(),
                label: "Local Agent".to_string(),
                command: "sh".to_string(),
                profile: None,
            },
            protected_paths: vec![GuiProtectedPath {
                id: "protected".to_string(),
                label: "Protected".to_string(),
                path: protected.display().to_string(),
                read_protected: false,
                write_protected: true,
                snapshot: false,
            }],
            network_journal: false,
        },
    )
    .expect("config saved");

    let result = launch_session(LaunchRequest {
        config_path: config_path.clone(),
        db_path: db_path.clone(),
        agent_id: "local-agent".to_string(),
        require_enforcement: false,
        receipt_key_path: None,
        accept_degraded: true,
        readiness_reviewed: true,
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printf hi > '{}'", touched_path.display()),
        ],
    })
    .expect("session launched");

    assert!(result.receipt.contains("status: completed"));
    assert!(result.receipt.contains("cgroup: degraded"));
    assert_eq!(result.exit_code, Some(0));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn launch_session_refuses_without_desktop_readiness_review() {
    let error = launch_session(LaunchRequest {
        config_path: PathBuf::from("/tmp/warder/gui.toml"),
        db_path: PathBuf::from("/tmp/warder/warder.sqlite3"),
        agent_id: "local-agent".to_string(),
        require_enforcement: false,
        receipt_key_path: None,
        accept_degraded: true,
        readiness_reviewed: false,
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    })
    .unwrap_err();

    assert!(error.contains("launch readiness has been reviewed"));
}

fn session_record(
    id: &str,
    started_at: std::time::SystemTime,
    status: SessionStatus,
) -> SessionRecord {
    SessionRecord {
        id: id.to_string(),
        agent_id: "local-agent".to_string(),
        agent_label: "Local Agent".to_string(),
        agent_profile: Some("codex-cli".to_string()),
        command: vec!["sh".to_string(), "-c".to_string(), "false".to_string()],
        protected_zone_ids: vec!["protected".to_string()],
        status,
        exit_code: Some(1),
        started_at,
        ended_at: Some(started_at + Duration::from_secs(1)),
        root_pid: None,
        cgroup_path: None,
        cgroup_status: CgroupStatus::NotRequested,
        landlock_status: LandlockStatus::NotRequested,
        snapshot_status: SnapshotStatus::NotRequested,
        dependency_file_changes: Vec::new(),
        degraded_reasons: Vec::new(),
    }
}
