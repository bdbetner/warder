use super::*;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use warder_config::{EnvironmentSupport, SnapshotBackend as ConfigSnapshotBackend};
use warder_core::{CgroupStatus, SessionStatus, SnapshotStatus};
use warder_db::WarderDb;

#[test]
fn parses_run_command_after_separator() {
    let command = parse_args([
        "warder",
        "run",
        "--config",
        "/tmp/warder.toml",
        "--db",
        "/tmp/warder.sqlite3",
        "--cgroup-root",
        "/tmp/cgroup",
        "--snapshot-root",
        "/tmp/snapshots",
        "--launch",
        "--require-enforcement",
        "--accept-degraded",
        "--agent",
        "local",
        "--",
        "sh",
        "-c",
        "true",
    ])
    .unwrap();

    assert_eq!(
        command,
        CliCommand::Run {
            config: Some(PathBuf::from("/tmp/warder.toml")),
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            cgroup_root: Some(PathBuf::from("/tmp/cgroup")),
            snapshot_root: Some(PathBuf::from("/tmp/snapshots")),
            launch: true,
            require_enforcement: true,
            receipt_key: None,
            accept_degraded: true,

            agent: "local".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        }
    );
}

#[test]
fn parses_run_command_with_receipt_key() {
    let command = parse_args([
        "warder",
        "run",
        "--config",
        "/tmp/warder.toml",
        "--launch",
        "--require-enforcement",
        "--receipt-key",
        "/run/warder-key",
        "--agent",
        "local",
        "--",
        "true",
    ])
    .unwrap();

    let CliCommand::Run { receipt_key, .. } = command else {
        panic!("expected run command");
    };
    assert_eq!(receipt_key, Some(PathBuf::from("/run/warder-key")));
}

#[test]
fn run_command_requires_clear_session_tagging_inputs() {
    let error = parse_args(["warder", "run", "--", "sh"]).unwrap_err();

    assert!(error.message.contains("--agent"));
}

#[test]
fn parses_start_command_with_optional_config() {
    assert_eq!(
        parse_args(["warder", "start"]).unwrap(),
        CliCommand::Start { config: None }
    );
    assert_eq!(
        parse_args(["warder", "start", "--config", "/tmp/warder.toml"]).unwrap(),
        CliCommand::Start {
            config: Some(PathBuf::from("/tmp/warder.toml"))
        }
    );
}

#[test]
fn parses_status_and_journal_commands() {
    assert_eq!(
        parse_args(["warder", "status"]).unwrap(),
        CliCommand::Status
    );
    assert_eq!(
        parse_args(["warder", "doctor"]).unwrap(),
        CliCommand::Doctor { config: None }
    );
    assert_eq!(
        parse_args(["warder", "doctor", "--config", "/tmp/warder.toml"]).unwrap(),
        CliCommand::Doctor {
            config: Some(PathBuf::from("/tmp/warder.toml"))
        }
    );
    assert_eq!(
        parse_args(["warder", "journal", "--session", "session-1"]).unwrap(),
        CliCommand::Journal {
            db: None,
            session_id: Some("session-1".to_string()),
            kind: JournalKind::File,
        }
    );
    assert_eq!(
        parse_args([
            "warder",
            "journal",
            "--db",
            "/tmp/warder.sqlite3",
            "--session",
            "session-1"
        ])
        .unwrap(),
        CliCommand::Journal {
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            session_id: Some("session-1".to_string()),
            kind: JournalKind::File,
        }
    );
    assert_eq!(
        parse_args([
            "warder",
            "journal",
            "--all",
            "--db",
            "/tmp/warder.sqlite3",
            "--session",
            "session-1"
        ])
        .unwrap(),
        CliCommand::Journal {
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            session_id: Some("session-1".to_string()),
            kind: JournalKind::All,
        }
    );
    assert_eq!(
        parse_args([
            "warder",
            "journal",
            "--network",
            "--db",
            "/tmp/warder.sqlite3",
            "--session",
            "session-1"
        ])
        .unwrap(),
        CliCommand::Journal {
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            session_id: Some("session-1".to_string()),
            kind: JournalKind::Network,
        }
    );
}

#[test]
fn parses_profiles_command() {
    assert_eq!(
        parse_args(["warder", "profiles"]).unwrap(),
        CliCommand::Profiles {
            format: ProfileCatalogFormat::Text,
        }
    );
}

#[test]
fn parses_profiles_command_with_json_format() {
    assert_eq!(
        parse_args(["warder", "profiles", "--format", "json"]).unwrap(),
        CliCommand::Profiles {
            format: ProfileCatalogFormat::Json,
        }
    );
}

#[test]
fn parses_init_command_with_starter_config_options() {
    assert_eq!(
        parse_args([
            "warder",
            "init",
            "--output",
            "/tmp/warder.toml",
            "--profile",
            "local-script",
            "--protected-path",
            "/tmp/protected",
            "--agent-command",
            "python3",
            "--force"
        ])
        .unwrap(),
        CliCommand::Init {
            output: PathBuf::from("/tmp/warder.toml"),
            profile: "local-script".to_string(),
            protected_paths: vec![PathBuf::from("/tmp/protected")],
            agent_command: Some("python3".to_string()),
            force: true,
            print: false,
        }
    );
}

#[test]
fn parses_init_print_command() {
    assert_eq!(
        parse_args([
            "warder",
            "init",
            "--print",
            "--profile",
            "local-script",
            "--protected-path",
            "/tmp/protected"
        ])
        .unwrap(),
        CliCommand::Init {
            output: PathBuf::from("warder.toml"),
            profile: "local-script".to_string(),
            protected_paths: vec![PathBuf::from("/tmp/protected")],
            agent_command: None,
            force: false,
            print: true,
        }
    );
}

#[test]
fn init_command_requires_protected_path() {
    let error = parse_args(["warder", "init", "--output", "/tmp/warder.toml"]).unwrap_err();

    assert_eq!(error.message, "init requires at least one --protected-path");
}

#[test]
fn init_print_rejects_force() {
    let error = parse_args([
        "warder",
        "init",
        "--print",
        "--force",
        "--protected-path",
        "/tmp/protected",
    ])
    .unwrap_err();

    assert_eq!(
        error.message,
        "init --print cannot be combined with --force"
    );
}

#[test]
fn init_print_rejects_missing_option_values() {
    let error = parse_args(["warder", "init", "--print", "--profile"]).unwrap_err();

    assert_eq!(error.message, "--profile requires a value");
}

#[test]
fn render_starter_config_writes_parseable_toml() {
    let config = render_starter_config(
        "local-script",
        &[PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")],
        Some("python3"),
    )
    .unwrap();
    let parsed = warder_config::WarderConfig::from_toml(&config).unwrap();

    assert!(config.contains("landlock = \"best-effort\""));
    assert!(config.contains("journal = true"));
    assert_eq!(
        parsed.zones[0].paths,
        vec![PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")]
    );
    assert_eq!(parsed.agents[0].id, "local-script");
    assert_eq!(parsed.agents[0].command, "python3");
    assert_eq!(parsed.agents[0].profile.as_deref(), Some("local-script"));
}

#[test]
fn render_starter_config_normalizes_relative_paths() {
    let config = render_starter_config(
        "local-script",
        &[PathBuf::from("relative-zone")],
        Some("sh"),
    )
    .unwrap();
    let parsed = warder_config::WarderConfig::from_toml(&config).unwrap();

    assert!(parsed.zones[0].paths[0].is_absolute());
    assert!(parsed.zones[0].paths[0].ends_with("relative-zone"));
}

#[test]
fn render_starter_config_escapes_toml_special_characters() {
    let config = render_starter_config(
        "custom-profile",
        &[
            PathBuf::from("/tmp/quote\"path"),
            PathBuf::from("/tmp/tab\tpath"),
        ],
        Some("runner \"quoted\"\targ"),
    )
    .unwrap();
    let parsed = warder_config::WarderConfig::from_toml(&config).unwrap();

    assert_eq!(
        parsed.zones[0].paths,
        vec![
            PathBuf::from("/tmp/quote\"path"),
            PathBuf::from("/tmp/tab\tpath")
        ]
    );
    assert_eq!(parsed.agents[0].id, "custom-profile");
    assert_eq!(parsed.agents[0].command, "runner \"quoted\"\targ");
    assert_eq!(parsed.agents[0].profile.as_deref(), Some("custom-profile"));
}

#[test]
fn render_starter_config_rejects_profile_that_would_make_invalid_config_id() {
    let error = render_starter_config(
        "custom profile",
        &[PathBuf::from("/tmp/protected")],
        Some("sh"),
    )
    .unwrap_err();

    assert!(error
        .message
        .contains("starter config profile 'custom profile'"));
    assert!(error.message.contains("may only contain ASCII"));
}

#[test]
fn render_starter_config_trims_profile_and_defaults_blank_command() {
    let config = render_starter_config(
        " local-script ",
        &[PathBuf::from("/tmp/protected")],
        Some("  "),
    )
    .unwrap();
    let parsed = warder_config::WarderConfig::from_toml(&config).unwrap();

    assert_eq!(parsed.agents[0].id, "local-script");
    assert_eq!(parsed.agents[0].command, "sh");
}

#[test]
fn write_starter_config_refuses_to_overwrite_without_force() {
    let output = temp_file("warder-cli-init-config", "toml");
    std::fs::write(&output, "existing").unwrap();

    let error = write_starter_config(
        &output,
        "local-script",
        &[PathBuf::from("/tmp/protected")],
        None,
        false,
    )
    .unwrap_err();

    assert!(error.message.contains("failed to create starter config"));
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "existing");

    let _ = std::fs::remove_file(output);
}

#[test]
fn write_starter_config_force_overwrites_existing_file() {
    let output = temp_file("warder-cli-init-force-config", "toml");
    std::fs::write(&output, "existing").unwrap();

    let status = write_starter_config(
        &output,
        "codex-cli",
        &[PathBuf::from("/tmp/protected")],
        None,
        true,
    )
    .unwrap();
    let config = std::fs::read_to_string(&output).unwrap();

    assert!(status.contains("wrote starter config"));
    assert!(config.contains("profile = \"codex-cli\""));
    assert!(config.contains("command = \"codex\""));

    let _ = std::fs::remove_file(output);
}

#[test]
fn profiles_command_rejects_unknown_format() {
    let error = parse_args(["warder", "profiles", "--format", "yaml"]).unwrap_err();

    assert_eq!(error.message, "unknown profiles format 'yaml'");
}

#[test]
fn journal_command_rejects_conflicting_selectors() {
    let error = parse_args(["warder", "journal", "--file", "--network"]).unwrap_err();

    assert_eq!(
        error.message,
        "journal selectors --file, --network, and --all cannot be combined"
    );

    let error = parse_args(["warder", "journal", "--network", "--file"]).unwrap_err();

    assert_eq!(
        error.message,
        "journal selectors --file, --network, and --all cannot be combined"
    );

    let error = parse_args(["warder", "journal", "--all", "--file"]).unwrap_err();

    assert_eq!(
        error.message,
        "journal selectors --file, --network, and --all cannot be combined"
    );
}

#[test]
fn usage_centers_no_daemon_run_workflow() {
    let usage = usage();

    assert!(usage.contains(
            "primary: warder run --config <path> --launch --agent <id> [--require-enforcement --receipt-key <path>] [--accept-degraded] [--cgroup-root <path>] [--snapshot-root <path>] -- <agent command>"
        ));
    assert!(
        usage.contains("record only: warder run --config <path> --agent <id> -- <agent command>")
    );
    assert!(
        usage.contains("preflight: warder dry-run --config <path> --agent <id> -- <agent command>")
    );
    assert!(usage.contains("init: warder init --protected-path <path>"));
    assert!(usage.contains("[--force] [--print]"));
    assert!(usage.contains("profiles: warder profiles [--format text|json]"));
    assert!(usage.contains("readiness: warder doctor"));
    assert!(usage.contains(
            "recovery: warder revert --snapshot <id> --snapshot-root <path> [--preview | --db <path> --session <id>]"
        ));
    assert!(usage.contains(
            "inspect: warder receipt [--db <path>] --session <id> [--format text|json] [--signing-key-file <path>|--receipt-key <path>] [--verify-signature <hex>] | warder verify-receipts [--db <path>] [--external-key <path>|--receipt-key <path>] | warder journal [--db <path>] [--file|--network|--all] [--session <id>] | warder status"
        ));
    assert!(usage.contains("daemon optional"));
}

#[test]
fn render_host_readiness_reports_strong_when_core_support_is_available() {
    let report = assess_host_readiness(warder_daemon::CapabilityProbe {
        landlock: warder_daemon::CapabilityState::Available,
        cgroups: warder_daemon::CapabilityState::Available,
        btrfs: warder_daemon::CapabilityState::Available,
        overlayfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
        ebpf: warder_daemon::CapabilityState::Available,
    });

    assert_eq!(report.level, ReadinessLevel::Strong);
    let rendered = render_host_readiness(&report);
    assert!(rendered.contains("host readiness: strong"));
    assert!(rendered.contains("blocked reasons: none"));
    assert!(rendered.contains("degraded reasons: none"));
}

#[test]
fn render_host_readiness_reports_degraded_when_optional_support_is_missing() {
    let report = assess_host_readiness(warder_daemon::CapabilityProbe {
        landlock: warder_daemon::CapabilityState::Available,
        cgroups: warder_daemon::CapabilityState::Available,
        btrfs: warder_daemon::CapabilityState::Unavailable(
            "Btrfs filesystem is unavailable".to_string(),
        ),
        overlayfs: warder_daemon::CapabilityState::Unavailable(
            "OverlayFS filesystem is unavailable".to_string(),
        ),
        ebpf: warder_daemon::CapabilityState::Unavailable("bpffs is unavailable".to_string()),
    });

    assert_eq!(report.level, ReadinessLevel::Degraded);
    let rendered = render_host_readiness(&report);
    assert!(rendered.contains("host readiness: degraded"));
    assert!(rendered.contains("Btrfs snapshots unavailable"));
    assert!(rendered.contains("live eBPF journals unavailable"));
}

#[test]
fn render_host_readiness_reports_blocked_when_core_support_is_missing() {
    let report = assess_host_readiness(warder_daemon::CapabilityProbe {
        landlock: warder_daemon::CapabilityState::Unavailable(
            "Landlock ABI path is unavailable".to_string(),
        ),
        cgroups: warder_daemon::CapabilityState::Unavailable(
            "cgroup v2 root is unavailable".to_string(),
        ),
        btrfs: warder_daemon::CapabilityState::Available,
        overlayfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
        ebpf: warder_daemon::CapabilityState::Available,
    });

    assert_eq!(report.level, ReadinessLevel::Blocked);
    let rendered = render_host_readiness(&report);
    assert!(rendered.contains("host readiness: blocked"));
    assert!(rendered.contains("Landlock unavailable"));
    assert!(rendered.contains("cgroups unavailable"));
}

#[test]
fn render_host_doctor_adds_proc_and_cgroup_diagnostics() {
    let root = temp_dir("warder-cli-doctor-diagnostics");
    let proc_fd = root.join("proc/self/fd");
    let proc_net = root.join("proc/self/net");
    let cgroup = root.join("sys/fs/cgroup");
    std::fs::create_dir_all(&proc_fd).unwrap();
    std::fs::create_dir_all(&proc_net).unwrap();
    std::fs::create_dir_all(&cgroup).unwrap();
    std::fs::write(proc_net.join("tcp"), "sl local_address rem_address\n").unwrap();
    std::fs::write(root.join("proc/self/stat"), "123 (warder) R\n").unwrap();
    std::fs::write(cgroup.join("cgroup.procs"), "").unwrap();
    std::fs::write(root.join(".dockerenv"), "").unwrap();

    let report = assess_host_doctor(
        warder_daemon::CapabilityProbe {
            landlock: warder_daemon::CapabilityState::Available,
            cgroups: warder_daemon::CapabilityState::Available,
            btrfs: warder_daemon::CapabilityState::Available,
            overlayfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
            ebpf: warder_daemon::CapabilityState::Available,
        },
        &HostDiagnosticPaths {
            proc_self_fd: proc_fd,
            proc_self_net_tcp: proc_net.join("tcp"),
            proc_self_stat: root.join("proc/self/stat"),
            cgroup_procs: cgroup.join("cgroup.procs"),
            docker_env: root.join(".dockerenv"),
            container_env: root.join("run/.containerenv"),
        },
    );

    let rendered = render_host_doctor(&report);

    assert_eq!(report.readiness.level, ReadinessLevel::Strong);
    assert!(rendered.contains("host readiness: strong"));
    assert!(rendered.contains("host diagnostics:"));
    assert!(rendered.contains("container detection: warning"));
    assert!(rendered.contains("proc fd visibility: ok"));
    assert!(rendered.contains("proc network visibility: ok"));
    assert!(rendered.contains("proc process metadata: ok"));
    assert!(rendered.contains("cgroup launch tagging: ok"));
}

#[test]
fn render_host_doctor_warns_when_proc_surfaces_are_hidden() {
    let root = temp_dir("warder-cli-doctor-hidden-proc");
    std::fs::create_dir_all(&root).unwrap();

    let report = assess_host_doctor(
        warder_daemon::CapabilityProbe {
            landlock: warder_daemon::CapabilityState::Unavailable(
                "Landlock ABI path is unavailable".to_string(),
            ),
            cgroups: warder_daemon::CapabilityState::Unavailable(
                "cgroup v2 root is unavailable".to_string(),
            ),
            btrfs: warder_daemon::CapabilityState::Unavailable(
                "Btrfs filesystem is unavailable".to_string(),
            ),
            overlayfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
            ebpf: warder_daemon::CapabilityState::Unavailable("bpffs is unavailable".to_string()),
        },
        &HostDiagnosticPaths {
            proc_self_fd: root.join("missing/fd"),
            proc_self_net_tcp: root.join("missing/net/tcp"),
            proc_self_stat: root.join("missing/stat"),
            cgroup_procs: root.join("missing/cgroup.procs"),
            docker_env: root.join("missing/.dockerenv"),
            container_env: root.join("missing/.containerenv"),
        },
    );

    let rendered = render_host_doctor(&report);

    assert_eq!(report.readiness.level, ReadinessLevel::Blocked);
    assert!(rendered.contains("host readiness: blocked"));
    assert!(rendered.contains("proc fd visibility: warning"));
    assert!(rendered.contains("proc network visibility: warning"));
    assert!(rendered.contains("proc process metadata: warning"));
    assert!(rendered.contains("cgroup launch tagging: warning"));
}

#[test]
fn render_host_doctor_with_config_checks_agent_command_resolution() {
    let config_path = temp_file("warder-cli-doctor-command-config", "toml");
    std::fs::write(
        &config_path,
        r#"
            [enforcement]
            landlock = "disabled"
            cgroups = "disabled"

            [[zones]]
            id = "notes"
            name = "Notes"
            paths = ["/tmp/warder-notes"]
            snapshot = "disabled"

            [[agents]]
            id = "shell"
            label = "Shell"
            command = "sh -c true"

            [[agents]]
            id = "missing"
            label = "Missing"
            command = "definitely-missing-warder-command"
        "#,
    )
    .unwrap();

    let rendered = render_host_doctor_from_probe_with_config(
        warder_daemon::CapabilityProbe {
            landlock: warder_daemon::CapabilityState::Available,
            cgroups: warder_daemon::CapabilityState::Available,
            btrfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
            overlayfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
            ebpf: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
        },
        Some(config_path),
    )
    .unwrap();

    assert!(rendered.contains("agent command shell: ok"));
    assert!(rendered.contains("agent command missing: warning"));
    assert!(rendered.contains("definitely-missing-warder-command"));
}

#[cfg(unix)]
#[test]
fn render_host_doctor_with_config_handles_quoted_and_non_executable_commands() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_dir("warder-cli-doctor-quoted-command");
    let bin_dir = root.join("bin dir");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let executable = bin_dir.join("agent tool");
    let non_executable = bin_dir.join("not executable");
    std::fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::write(&non_executable, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o600)).unwrap();

    let config_path = root.join("warder.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
            [enforcement]
            landlock = "disabled"
            cgroups = "disabled"

            [[zones]]
            id = "notes"
            name = "Notes"
            paths = ["/tmp/warder-notes"]
            snapshot = "disabled"

            [[agents]]
            id = "quoted"
            label = "Quoted"
            command = "'{}' --flag"

            [[agents]]
            id = "not-executable"
            label = "Not Executable"
            command = "'{}'"
        "#,
            executable.display(),
            non_executable.display()
        ),
    )
    .unwrap();

    let rendered = render_host_doctor_from_probe_with_config(
        warder_daemon::CapabilityProbe {
            landlock: warder_daemon::CapabilityState::Available,
            cgroups: warder_daemon::CapabilityState::Available,
            btrfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
            overlayfs: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
            ebpf: warder_daemon::CapabilityState::Unavailable("not used".to_string()),
        },
        Some(config_path),
    )
    .unwrap();

    assert!(rendered.contains("agent command quoted: ok"));
    assert!(rendered.contains("agent command not-executable: warning"));
}

#[test]
fn parses_top_level_help_and_version() {
    assert_eq!(parse_args(["warder", "--help"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["warder", "-h"]).unwrap(), CliCommand::Help);
    assert_eq!(parse_args(["warder", "help"]).unwrap(), CliCommand::Help);
    assert_eq!(
        parse_args(["warder", "--version"]).unwrap(),
        CliCommand::Version
    );
    assert_eq!(parse_args(["warder", "-V"]).unwrap(), CliCommand::Version);
    assert!(version().starts_with("warder "));
}

#[test]
fn parses_receipt_command_with_default_text_format() {
    assert_eq!(
        parse_args(["warder", "receipt", "--session", "session-1"]).unwrap(),
        CliCommand::Receipt {
            db: None,
            session_id: "session-1".to_string(),
            format: ReceiptFormat::Text,
            signing_key_file: None,
            verify_signature: None,
        }
    );
}

#[test]
fn parses_receipt_command_with_db_and_json_format() {
    assert_eq!(
        parse_args([
            "warder",
            "receipt",
            "--db",
            "/tmp/warder.sqlite3",
            "--session",
            "session-1",
            "--format",
            "json",
        ])
        .unwrap(),
        CliCommand::Receipt {
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            session_id: "session-1".to_string(),
            format: ReceiptFormat::Json,
            signing_key_file: None,
            verify_signature: None,
        }
    );
}

#[test]
fn parses_receipt_command_with_signing_options() {
    assert_eq!(
        parse_args([
            "warder",
            "receipt",
            "--db",
            "/tmp/warder.sqlite3",
            "--session",
            "session-1",
            "--signing-key-file",
            "/tmp/warder.key",
            "--verify-signature",
            "abc123",
        ])
        .unwrap(),
        CliCommand::Receipt {
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            session_id: "session-1".to_string(),
            format: ReceiptFormat::Text,
            signing_key_file: Some(PathBuf::from("/tmp/warder.key")),
            verify_signature: Some("abc123".to_string()),
        }
    );
}

#[test]
fn parses_receipt_command_with_external_receipt_key_alias() {
    assert_eq!(
        parse_args([
            "warder",
            "receipt",
            "--session",
            "session-1",
            "--receipt-key",
            "/run/warder-key",
        ])
        .unwrap(),
        CliCommand::Receipt {
            db: None,
            session_id: "session-1".to_string(),
            format: ReceiptFormat::Text,
            signing_key_file: Some(PathBuf::from("/run/warder-key")),
            verify_signature: None,
        }
    );
}

#[test]
fn parses_receipt_key_init_command() {
    assert_eq!(
        parse_args([
            "warder",
            "receipt-key",
            "init",
            "--output",
            "/tmp/warder.key",
            "--force",
        ])
        .unwrap(),
        CliCommand::ReceiptKey {
            output: PathBuf::from("/tmp/warder.key"),
            force: true,
        }
    );
}

#[test]
fn parses_verify_receipts_command() {
    assert_eq!(
        parse_args(["warder", "verify-receipts", "--db", "/tmp/warder.sqlite3",]).unwrap(),
        CliCommand::VerifyReceipts {
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            external_key: None,
        }
    );
}

#[test]
fn parses_verify_receipts_external_key_alias() {
    assert_eq!(
        parse_args([
            "warder",
            "verify-receipts",
            "--db",
            "/tmp/warder.sqlite3",
            "--external-key",
            "/run/warder-key",
        ])
        .unwrap(),
        CliCommand::VerifyReceipts {
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            external_key: Some(PathBuf::from("/run/warder-key")),
        }
    );
}

#[test]
fn receipt_command_rejects_unknown_format() {
    let error = parse_args([
        "warder",
        "receipt",
        "--session",
        "session-1",
        "--format",
        "xml",
    ])
    .unwrap_err();

    assert!(error.message.contains("unknown receipt format"));
}

#[test]
fn parses_snapshot_and_revert_commands() {
    assert_eq!(
        parse_args(["warder", "snapshot", "--session", "session-1"]).unwrap(),
        CliCommand::Snapshot {
            session_id: "session-1".to_string(),
            config: None,
            snapshot_root: None
        }
    );
    assert_eq!(
        parse_args([
            "warder",
            "snapshot",
            "--session",
            "session-1",
            "--config",
            "/tmp/warder.toml",
            "--snapshot-root",
            "/tmp/snapshots",
        ])
        .unwrap(),
        CliCommand::Snapshot {
            session_id: "session-1".to_string(),
            config: Some(PathBuf::from("/tmp/warder.toml")),
            snapshot_root: Some(PathBuf::from("/tmp/snapshots"))
        }
    );
    assert_eq!(
        parse_args([
            "warder",
            "revert",
            "--snapshot",
            "snap-1",
            "--snapshot-root",
            "/tmp/snapshots",
            "--preview",
        ])
        .unwrap(),
        CliCommand::Revert {
            snapshot_id: "snap-1".to_string(),
            snapshot_root: Some(PathBuf::from("/tmp/snapshots")),
            db: None,
            session_id: None,
            preview: true
        }
    );
    assert_eq!(
        parse_args([
            "warder",
            "revert",
            "--snapshot",
            "snap-1",
            "--snapshot-root",
            "/tmp/snapshots",
            "--db",
            "/tmp/warder.sqlite3",
            "--session",
            "session-1",
        ])
        .unwrap(),
        CliCommand::Revert {
            snapshot_id: "snap-1".to_string(),
            snapshot_root: Some(PathBuf::from("/tmp/snapshots")),
            db: Some(PathBuf::from("/tmp/warder.sqlite3")),
            session_id: Some("session-1".to_string()),
            preview: false
        }
    );
    assert!(parse_args([
        "warder",
        "revert",
        "--snapshot",
        "snap-1",
        "--snapshot-root",
        "/tmp/snapshots",
        "--db",
        "/tmp/warder.sqlite3",
    ])
    .unwrap_err()
    .message
    .contains("--session"));
    assert!(parse_args([
        "warder",
        "revert",
        "--snapshot",
        "snap-1",
        "--snapshot-root",
        "/tmp/snapshots",
        "--preview",
        "--db",
        "/tmp/warder.sqlite3",
        "--session",
        "session-1",
    ])
    .unwrap_err()
    .message
    .contains("cannot be combined"));
}

#[test]
fn snapshot_and_revert_summaries_report_guarded_status() {
    assert!(command_summary(&CliCommand::Snapshot {
        session_id: "session-1".to_string(),
        config: None,
        snapshot_root: None
    })
    .contains("--config and --snapshot-root are required"));
    assert!(command_summary(&CliCommand::Snapshot {
        session_id: "session-1".to_string(),
        config: Some(PathBuf::from("/tmp/warder.toml")),
        snapshot_root: Some(PathBuf::from("/tmp/snapshots"))
    })
    .contains("snapshot requested for session"));
    assert!(command_summary(&CliCommand::Revert {
        snapshot_id: "snap-1".to_string(),
        snapshot_root: None,
        db: None,
        session_id: None,
        preview: false
    })
    .contains("--snapshot-root is required"));
    assert!(command_summary(&CliCommand::Revert {
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(PathBuf::from("/tmp/snapshots")),
        db: None,
        session_id: None,
        preview: false
    })
    .contains("guarded revert requested"));
    assert!(command_summary(&CliCommand::Revert {
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(PathBuf::from("/tmp/snapshots")),
        db: None,
        session_id: None,
        preview: true
    })
    .contains("revert preview requested"));
}

#[test]
fn journal_command_summary_names_selected_stream() {
    assert_eq!(
        command_summary(&CliCommand::Journal {
            db: None,
            session_id: Some("session-1".to_string()),
            kind: JournalKind::File,
        }),
        "file journal requested for session 'session-1'"
    );
    assert_eq!(
        command_summary(&CliCommand::Journal {
            db: None,
            session_id: Some("session-1".to_string()),
            kind: JournalKind::Network,
        }),
        "network journal requested for session 'session-1'"
    );
    assert_eq!(
        command_summary(&CliCommand::Journal {
            db: None,
            session_id: None,
            kind: JournalKind::All,
        }),
        "all journals requested for recent sessions"
    );
}

#[test]
fn run_command_summary_distinguishes_launch_from_record_only() {
    let launched = CliCommand::Run {
        config: Some(PathBuf::from("/tmp/warder.toml")),
        db: None,
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    };
    let recorded = CliCommand::Run {
        config: Some(PathBuf::from("/tmp/warder.toml")),
        db: None,
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    };

    assert!(command_summary(&launched).contains("supervised launch requested"));
    assert!(command_summary(&recorded).contains("record-only session requested"));

    let quoted = CliCommand::Run {
        config: Some(PathBuf::from("/tmp/warder.toml")),
        db: None,
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo hello > /tmp/warder out.txt".to_string(),
        ],
    };
    assert!(command_summary(&quoted).contains("command: sh -c 'echo hello > /tmp/warder out.txt'"));
}

#[test]
fn snapshot_and_revert_commands_return_missing_guard_errors() {
    assert!(command_not_implemented_error(&CliCommand::Snapshot {
        session_id: "session-1".to_string(),
        config: None,
        snapshot_root: None
    })
    .unwrap()
    .message
    .contains("--config and --snapshot-root are required"));
    assert!(command_not_implemented_error(&CliCommand::Snapshot {
        session_id: "session-1".to_string(),
        config: Some(PathBuf::from("/tmp/warder.toml")),
        snapshot_root: Some(PathBuf::from("/tmp/snapshots"))
    })
    .is_none());
    assert!(command_not_implemented_error(&CliCommand::Revert {
        snapshot_id: "snap-1".to_string(),
        snapshot_root: None,
        db: None,
        session_id: None,
        preview: false
    })
    .unwrap()
    .message
    .contains("--snapshot-root is required"));
    assert!(command_not_implemented_error(&CliCommand::Revert {
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(PathBuf::from("/tmp/snapshots")),
        db: None,
        session_id: None,
        preview: false
    })
    .is_none());
    assert!(command_not_implemented_error(&CliCommand::Status).is_none());
}

#[test]
fn render_revert_preview_loads_snapshot_manifest_without_restoring() {
    let snapshot_root = temp_dir("warder-cli-revert-preview");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&snapshot_dir).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();

    let preview = render_revert_preview(&snapshot_root, "snap-1").unwrap();

    assert!(preview.contains("snapshot: snap-1"));
    assert!(preview.contains("restore: preview only; no changes made"));
    assert!(preview.contains("restore readiness: ready"));
    assert!(preview.contains(&format!(
        "{} <= {}",
        source_root.display(),
        snapshot_path.display()
    )));
}

#[test]
fn render_revert_preview_marks_existing_targets_as_blocked() {
    let snapshot_root = temp_dir("warder-cli-revert-preview-existing");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("project");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(&source_root).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();

    let preview = render_revert_preview(&snapshot_root, "snap-1").unwrap();

    assert!(preview.contains("restore readiness: blocked"));
    assert!(preview.contains("blocked: target exists"));
    assert!(preview.contains(&format!(
        "{} <= {}",
        source_root.display(),
        snapshot_path.display()
    )));
}

#[test]
fn render_revert_preview_marks_missing_snapshot_paths_as_blocked() {
    let snapshot_root = temp_dir("warder-cli-revert-preview-missing-snapshot");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("missing-project");
    let source_root = snapshot_root.join("restored").join("project");
    std::fs::create_dir_all(&snapshot_dir).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();

    let preview = render_revert_preview(&snapshot_root, "snap-1").unwrap();

    assert!(preview.contains("blocked: snapshot path missing"));
    assert!(preview.contains(&format!(
        "{} <= {}",
        source_root.display(),
        snapshot_path.display()
    )));
}

#[test]
fn render_revert_preview_marks_missing_target_parents_as_blocked() {
    let snapshot_root = temp_dir("warder-cli-revert-preview-missing-parent");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("missing-parent").join("project");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();

    let preview = render_revert_preview(&snapshot_root, "snap-1").unwrap();

    assert!(preview.contains("blocked: target parent missing"));
    assert!(preview.contains(&format!(
        "{} <= {}",
        source_root.display(),
        snapshot_path.display()
    )));
}

#[test]
fn render_revert_preview_marks_non_btrfs_manifest_as_blocked() {
    let snapshot_root = temp_dir("warder-cli-revert-preview-overlay");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"overlayfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();

    let preview = render_revert_preview(&snapshot_root, "snap-1").unwrap();

    assert!(preview.contains("restore readiness: blocked"));
    assert!(preview.contains("blocked: manifest backend is overlayfs"));
}

#[test]
fn render_revert_preview_marks_empty_manifest_as_blocked() {
    let snapshot_root = temp_dir("warder-cli-revert-preview-empty");
    let snapshot_dir = snapshot_root.join("snap-1");
    std::fs::create_dir_all(&snapshot_dir).unwrap();
    std::fs::write(
        snapshot_dir.join("manifest.json"),
        r#"{"snapshot_id":"snap-1","backend":"btrfs","entries":[]}"#,
    )
    .unwrap();

    let preview = render_revert_preview(&snapshot_root, "snap-1").unwrap();

    assert!(preview.contains("restore readiness: blocked"));
    assert!(preview.contains("blocked: manifest has no entries"));
}

#[derive(Clone, Debug, Default)]
struct RecordingSnapshotRunner {
    commands: RecordedSnapshotCommands,
}

type RecordedSnapshotCommands = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>;

impl RecordingSnapshotRunner {
    fn commands(&self) -> Vec<(String, Vec<String>)> {
        self.commands.lock().unwrap().clone()
    }
}

impl warder_snapshot::SnapshotCommandRunner for RecordingSnapshotRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<(), warder_snapshot::SnapshotError> {
        self.commands
            .lock()
            .unwrap()
            .push((program.to_string(), args.to_vec()));
        Ok(())
    }
}

#[test]
fn create_snapshot_from_config_runs_btrfs_snapshot() {
    let config_path = temp_file("warder-cli-standalone-snapshot-config", "toml");
    let snapshot_root = temp_dir("warder-cli-standalone-snapshot-root");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "required"),
    )
    .unwrap();
    let runner = RecordingSnapshotRunner::default();

    let report = create_snapshot_from_config_with_runner(
        &config_path,
        &snapshot_root,
        "session-1",
        runner.clone(),
    )
    .unwrap();

    assert!(report.contains("snapshot created: session-1-btrfs via btrfs"));
    assert!(report.contains(&format!(
        "warder revert --snapshot session-1-btrfs --snapshot-root {}",
        snapshot_root.display()
    )));
    assert_eq!(
        runner.commands(),
        vec![(
            "btrfs".to_string(),
            vec![
                "subvolume".to_string(),
                "snapshot".to_string(),
                "-r".to_string(),
                "/tmp/notes".to_string(),
                snapshot_root
                    .join("session-1-btrfs")
                    .join("notes")
                    .display()
                    .to_string(),
            ]
        )]
    );
    assert!(snapshot_root
        .join("session-1-btrfs")
        .join("manifest.json")
        .exists());
}

#[test]
fn create_snapshot_from_config_validates_policy_before_btrfs() {
    let config_path = temp_file("warder-cli-standalone-snapshot-invalid-config", "toml");
    let snapshot_root = temp_dir("warder-cli-standalone-snapshot-invalid-root");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "disabled"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["relative/notes"]
                snapshot = "required"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();
    let runner = RecordingSnapshotRunner::default();

    let error = create_snapshot_from_config_with_runner(
        &config_path,
        &snapshot_root,
        "session-1",
        runner.clone(),
    )
    .unwrap_err();

    assert!(error.message.contains("config validation failed"));
    assert!(error.message.contains("absolute"));
    assert!(runner.commands().is_empty());
}

#[test]
fn restore_snapshot_from_root_runs_guarded_btrfs_restore() {
    let snapshot_root = temp_dir("warder-cli-revert-exec");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let runner = RecordingSnapshotRunner::default();

    let report =
        restore_snapshot_from_root_with_runner(&snapshot_root, "snap-1", runner.clone()).unwrap();

    assert!(report.contains("snapshot restored: snap-1 via btrfs"));
    assert_eq!(
        runner.commands(),
        vec![(
            "btrfs".to_string(),
            vec![
                "subvolume".to_string(),
                "snapshot".to_string(),
                snapshot_path.display().to_string(),
                source_root.display().to_string(),
            ],
        )]
    );
}

#[test]
fn restore_snapshot_for_session_records_reverted_receipt_state() {
    let snapshot_root = temp_dir("warder-cli-revert-session");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    let db_path = temp_file("warder-cli-revert-session-db", "sqlite3");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };
    db.create_session(&session).unwrap();

    let report = restore_snapshot_from_root_for_session_with_runner(
        &db_path,
        "session-1",
        &snapshot_root,
        "snap-1",
        RecordingSnapshotRunner::default(),
    )
    .unwrap();

    assert!(report.contains("session recorded as reverted: session-1"));
    let updated = db.get_session("session-1").unwrap().unwrap();
    assert_eq!(updated.status, SessionStatus::Reverted);
    assert!(matches!(
        updated.snapshot_status,
        SnapshotStatus::Reverted {
            backend: warder_core::SnapshotBackend::Btrfs,
            ref snapshot_id,
            snapshot_root: Some(ref root),
        } if snapshot_id == "snap-1" && root == &snapshot_root
    ));
}

#[test]
fn restore_snapshot_for_session_refuses_mismatched_snapshot_before_restore() {
    let snapshot_root = temp_dir("warder-cli-revert-session-mismatch");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    let db_path = temp_file("warder-cli-revert-session-mismatch-db", "sqlite3");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "other-snap".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };
    db.create_session(&session).unwrap();
    let runner = RecordingSnapshotRunner::default();

    let error = restore_snapshot_from_root_for_session_with_runner(
        &db_path,
        "session-1",
        &snapshot_root,
        "snap-1",
        runner.clone(),
    )
    .unwrap_err();

    assert!(error.message.contains("does not match session snapshot"));
    assert!(runner.commands().is_empty());
}

#[test]
fn restore_snapshot_for_session_refuses_repeated_revert_before_restore() {
    let snapshot_root = temp_dir("warder-cli-revert-session-repeated");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    let db_path = temp_file("warder-cli-revert-session-repeated-db", "sqlite3");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.status = SessionStatus::Reverted;
    session.snapshot_status = SnapshotStatus::Reverted {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };
    db.create_session(&session).unwrap();
    let runner = RecordingSnapshotRunner::default();

    let error = restore_snapshot_from_root_for_session_with_runner(
        &db_path,
        "session-1",
        &snapshot_root,
        "snap-1",
        runner.clone(),
    )
    .unwrap_err();

    assert!(error.message.contains("already recorded as reverted"));
    assert!(runner.commands().is_empty());
}

#[test]
fn restore_snapshot_for_session_refuses_failed_snapshot_before_restore() {
    let snapshot_root = temp_dir("warder-cli-revert-session-failed");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    let db_path = temp_file("warder-cli-revert-session-failed-db", "sqlite3");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Failed("btrfs unavailable".to_string());
    db.create_session(&session).unwrap();
    let runner = RecordingSnapshotRunner::default();

    let error = restore_snapshot_from_root_for_session_with_runner(
        &db_path,
        "session-1",
        &snapshot_root,
        "snap-1",
        runner.clone(),
    )
    .unwrap_err();

    assert!(error.message.contains("snapshot creation failed"));
    assert!(error.message.contains("btrfs unavailable"));
    assert!(runner.commands().is_empty());
}

#[test]
fn restore_snapshot_for_session_refuses_missing_recorded_snapshot_root_before_restore() {
    let snapshot_root = temp_dir("warder-cli-revert-session-missing-root");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    let db_path = temp_file("warder-cli-revert-session-missing-root-db", "sqlite3");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: None,
    };
    db.create_session(&session).unwrap();
    let runner = RecordingSnapshotRunner::default();

    let error = restore_snapshot_from_root_for_session_with_runner(
        &db_path,
        "session-1",
        &snapshot_root,
        "snap-1",
        runner.clone(),
    )
    .unwrap_err();

    assert!(error.message.contains("does not record a snapshot root"));
    assert!(runner.commands().is_empty());
}

#[test]
fn restore_snapshot_for_session_refuses_non_btrfs_snapshot_before_restore() {
    let snapshot_root = temp_dir("warder-cli-revert-session-overlay");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    let db_path = temp_file("warder-cli-revert-session-overlay-db", "sqlite3");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::OverlayFs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };
    db.create_session(&session).unwrap();
    let runner = RecordingSnapshotRunner::default();

    let error = restore_snapshot_from_root_for_session_with_runner(
        &db_path,
        "session-1",
        &snapshot_root,
        "snap-1",
        runner.clone(),
    )
    .unwrap_err();

    assert!(error.message.contains("snapshot backend is overlayfs"));
    assert!(runner.commands().is_empty());
}

#[test]
fn restore_snapshot_for_session_refuses_active_session_before_restore() {
    let snapshot_root = temp_dir("warder-cli-revert-session-active");
    let snapshot_dir = snapshot_root.join("snap-1");
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("restored").join("project");
    let db_path = temp_file("warder-cli-revert-session-active-db", "sqlite3");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
    std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.status = SessionStatus::Running;
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };
    db.create_session(&session).unwrap();
    let runner = RecordingSnapshotRunner::default();

    let error = restore_snapshot_from_root_for_session_with_runner(
        &db_path,
        "session-1",
        &snapshot_root,
        "snap-1",
        runner.clone(),
    )
    .unwrap_err();

    assert!(error.message.contains("is still running"));
    assert!(runner.commands().is_empty());
}

#[test]
fn parses_explain_command_with_config() {
    assert_eq!(
        parse_args(["warder", "explain", "--config", "/tmp/warder.toml"]).unwrap(),
        CliCommand::Explain {
            config: PathBuf::from("/tmp/warder.toml")
        }
    );
}

#[test]
fn parses_dry_run_command_after_separator() {
    assert_eq!(
        parse_args([
            "warder",
            "dry-run",
            "--config",
            "/tmp/warder.toml",
            "--agent",
            "local",
            "--",
            "sh",
            "-c",
            "true",
        ])
        .unwrap(),
        CliCommand::DryRun {
            config: PathBuf::from("/tmp/warder.toml"),
            agent: "local".to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        }
    );
}

#[test]
fn dry_run_requires_separator_and_command() {
    let missing_separator = parse_args([
        "warder",
        "dry-run",
        "--config",
        "/tmp/warder.toml",
        "--agent",
        "local",
        "sh",
    ])
    .unwrap_err();
    assert!(missing_separator.message.contains("'--'"));

    let missing_command = parse_args([
        "warder",
        "dry-run",
        "--config",
        "/tmp/warder.toml",
        "--agent",
        "local",
        "--",
    ])
    .unwrap_err();
    assert!(missing_command.message.contains("command"));
}

#[test]
fn create_run_session_loads_config_and_persists_pending_session() {
    let config_path = temp_file("warder-cli-config", "toml");
    let db_path = temp_file("warder-cli-db", "sqlite3");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "required"
                cgroups = "required"
                writable-roots = ["/var/tmp"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path.clone()),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    };

    let outcome = create_run_session(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap();

    assert_valid_random_session_id(&outcome.session_id);
    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("live attach is not implemented yet")));

    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.agent_id, "local");
    assert_eq!(session.agent_label, "Local Agent");
    assert_eq!(session.command, vec!["sh", "-c", "true"]);
    assert_eq!(session.protected_zone_ids, vec!["notes"]);
    assert_eq!(session.status, SessionStatus::Recorded);
    assert_eq!(session.cgroup_status, CgroupStatus::Pending);
    assert_eq!(session.landlock_status, LandlockStatus::Pending);
    assert_eq!(session.snapshot_status, SnapshotStatus::NotRequested);
    assert!(session
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("live attach is not implemented yet")));
}

#[test]
fn create_run_session_persists_allowed_destination_non_enforcement_warning() {
    let config_path = temp_file("warder-cli-network-allowlist-config", "toml");
    let db_path = temp_file("warder-cli-network-allowlist-db", "sqlite3");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "disabled"

                [network]
                journal = false
                allowed-destinations = ["example.com:443"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    };

    let outcome = create_run_session(&command, &supported_environment(), fixed_time()).unwrap();

    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("network.allowed_destinations is configured")));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert!(session
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("does not enforce destination allowlists yet")));
}

#[test]
fn create_run_session_rejects_required_snapshot_without_snapshot_root() {
    let config_path = temp_file("warder-cli-required-snapshot-unwired-config", "toml");
    let db_path = temp_file("warder-cli-required-snapshot-unwired-db", "sqlite3");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "required"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };

    let error = create_run_session(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap_err();

    assert!(error.message.contains("snapshot required"));
    assert!(error
        .message
        .contains("btrfs snapshot creation requires --snapshot-root"));
}

#[test]
fn create_run_session_rejects_required_overlayfs_snapshot_driver() {
    let config_path = temp_file("warder-cli-required-overlayfs-snapshot-config", "toml");
    let db_path = temp_file("warder-cli-required-overlayfs-snapshot-db", "sqlite3");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "required"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };

    let error = create_run_session(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::OverlayFs],
        },
        fixed_time(),
    )
    .unwrap_err();

    assert!(error.message.contains("snapshot required"));
    assert!(error
        .message
        .contains("overlayfs snapshot backend driver is not implemented yet"));
}

#[test]
fn create_run_session_marks_best_effort_snapshot_failed_without_snapshot_root() {
    let config_path = temp_file("warder-cli-best-effort-unwired-config", "toml");
    let db_path = temp_file("warder-cli-best-effort-unwired-db", "sqlite3");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "best-effort"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };

    let outcome = create_run_session(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap();

    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert!(matches!(
        session.snapshot_status,
        SnapshotStatus::Failed(ref message)
            if message.contains("btrfs snapshot creation requires --snapshot-root")
    ));
    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| { warning.contains("btrfs snapshot creation requires --snapshot-root") }));
}

#[test]
fn render_policy_explain_reports_overlayfs_snapshot_driver_unimplemented() {
    let config_path = temp_file("warder-cli-overlayfs-snapshot-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "best-effort"),
    )
    .unwrap();
    let explanation = render_policy_explain_from_config(
        Some(config_path),
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::OverlayFs],
        },
    )
    .unwrap();

    assert!(explanation.contains(
            "snapshot: degraded: overlayfs snapshot backend driver is not implemented yet; skipping snapshot"
        ));
    assert!(explanation.contains(
        "warning: overlayfs snapshot backend driver is not implemented yet; skipping snapshot"
    ));
    assert!(!explanation.contains("snapshot: will create (overlayfs)"));
    assert!(!explanation.contains("validation: ok"));
}

#[test]
fn render_policy_explain_reports_required_overlayfs_snapshot_as_error() {
    let config_path = temp_file("warder-cli-overlayfs-required-explain-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "required"),
    )
    .unwrap();
    let explanation = render_policy_explain_from_config(
        Some(config_path),
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::OverlayFs],
        },
    )
    .unwrap();

    assert!(explanation.contains(
            "snapshot: blocked: snapshot required, but overlayfs snapshot backend driver is not implemented yet"
        ));
    assert!(explanation.contains(
        "error: snapshot required, but overlayfs snapshot backend driver is not implemented yet"
    ));
    assert!(!explanation.contains("validation: ok"));
}

#[test]
fn environment_support_from_probe_does_not_expose_unimplemented_overlayfs_driver() {
    let environment = environment_support_from_probe(warder_daemon::CapabilityProbe {
        landlock: warder_daemon::CapabilityState::Available,
        cgroups: warder_daemon::CapabilityState::Available,
        btrfs: warder_daemon::CapabilityState::Unavailable("not btrfs".to_string()),
        overlayfs: warder_daemon::CapabilityState::Available,
        ebpf: warder_daemon::CapabilityState::Available,
    });

    assert!(environment.landlock);
    assert!(environment.cgroups);
    assert!(environment.ebpf);
    assert!(environment.snapshot_backends.is_empty());
}

#[test]
fn create_run_session_infers_known_agent_profile_when_not_declared() {
    let config_path = temp_file("warder-cli-inferred-profile-config", "toml");
    let db_path = temp_file("warder-cli-inferred-profile-db", "sqlite3");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "required"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                snapshot = "disabled"

                [[agents]]
                id = "codex"
                label = "Codex CLI"
                command = "codex"
            "#,
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "codex".to_string(),
        command: vec!["codex".to_string()],
    };

    let outcome = create_run_session(&command, &supported_environment(), fixed_time()).unwrap();

    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.agent_profile.as_deref(), Some("codex-cli"));
}

#[test]
fn create_run_session_marks_disabled_cgroups_not_requested() {
    let config_path = temp_file("warder-cli-disabled-cgroup-config", "toml");
    let db_path = temp_file("warder-cli-disabled-cgroup-db", "sqlite3");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "disabled"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };

    let outcome = create_run_session(&command, &supported_environment(), fixed_time()).unwrap();

    let db = WarderDb::open(db_path.clone()).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.cgroup_status, CgroupStatus::NotRequested);
    let receipt = render_session_receipt_from_db(Some(db_path), &outcome.session_id).unwrap();
    assert!(receipt.contains("cgroup: not requested"));
}

#[test]
fn create_run_session_rejects_invalid_config_without_persisting() {
    let config_path = temp_file("warder-cli-invalid-config", "toml");
    let db_path = temp_file("warder-cli-invalid-db", "sqlite3");
    std::fs::write(
        &config_path,
        r#"
                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["relative/path"]

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };

    let error = create_run_session(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap_err();

    assert!(error.message.contains("absolute path"));
}

#[test]
fn create_run_session_marks_best_effort_snapshot_unrequested_without_backend() {
    let config_path = temp_file("warder-cli-best-effort-config", "toml");
    let db_path = temp_file("warder-cli-best-effort-db", "sqlite3");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "required"
                cgroups = "required"

                [[zones]]
                id = "research"
                name = "Research"
                paths = ["/tmp/research"]
                snapshot = "best-effort"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };

    let outcome = create_run_session(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![],
        },
        fixed_time(),
    )
    .unwrap();

    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.snapshot_status, SnapshotStatus::NotRequested);
    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("snapshot backend unavailable")));
}

#[test]
fn apply_cgroup_tag_result_updates_session_as_tagged() {
    let config_path = temp_file("warder-cli-cgroup-config", "toml");
    let db_path = temp_file("warder-cli-cgroup-db", "sqlite3");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };
    let outcome = create_run_session(&command, &supported_environment(), fixed_time()).unwrap();
    let cgroup_path = PathBuf::from("/sys/fs/cgroup/warder/session-1");

    apply_cgroup_tag_result(
        db_path.clone(),
        &outcome.session_id,
        CgroupTagResult {
            cgroup_path: Some(cgroup_path.clone()),
            status: CgroupTagStatus::Tagged,
        },
    )
    .unwrap();

    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.cgroup_path, Some(cgroup_path));
    assert_eq!(session.cgroup_status, CgroupStatus::Tagged);
}

#[test]
fn apply_cgroup_tag_result_records_unsupported_as_degraded_reason() {
    let config_path = temp_file("warder-cli-cgroup-unsupported-config", "toml");
    let db_path = temp_file("warder-cli-cgroup-unsupported-db", "sqlite3");
    std::fs::write(&config_path, valid_config("disabled")).unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };
    let outcome = create_run_session(&command, &supported_environment(), fixed_time()).unwrap();

    apply_cgroup_tag_result(
        db_path.clone(),
        &outcome.session_id,
        CgroupTagResult {
            cgroup_path: None,
            status: CgroupTagStatus::Unsupported("cgroup root missing".to_string()),
        },
    )
    .unwrap();

    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(
        session.cgroup_status,
        CgroupStatus::Unsupported("cgroup root missing".to_string())
    );
    assert!(session
        .degraded_reasons
        .iter()
        .any(|reason| reason == "cgroup root missing"));
    apply_cgroup_tag_result(
        db_path.clone(),
        &outcome.session_id,
        CgroupTagResult {
            cgroup_path: None,
            status: CgroupTagStatus::Unsupported("cgroup root missing".to_string()),
        },
    )
    .unwrap();

    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(
        session
            .degraded_reasons
            .iter()
            .filter(|reason| reason.as_str() == "cgroup root missing")
            .count(),
        1
    );
}

#[test]
fn prepare_supervised_run_records_session_and_applies_cgroup_tag() {
    let config_path = temp_file("warder-cli-prepare-config", "toml");
    let db_path = temp_file("warder-cli-prepare-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-prepare-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root.clone()),
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };

    let outcome = prepare_supervised_run(
        &command,
        &supported_environment(),
        fixed_time(),
        cgroup_root.clone(),
        4242,
    )
    .unwrap();

    assert_valid_random_session_id(&outcome.session_id);
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.cgroup_status, CgroupStatus::Tagged);
    assert_eq!(
        session.cgroup_path,
        Some(cgroup_root.join("warder").join(&outcome.session_id))
    );
}

#[test]
fn launch_supervised_run_spawns_child_tags_pid_and_marks_completed() {
    let config_path = temp_file("warder-cli-launch-config", "toml");
    let db_path = temp_file("warder-cli-launch-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root.clone()),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
    };

    let outcome = launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    assert_eq!(outcome.exit_code, Some(0));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Completed);
    assert!(session.root_pid.is_some());
    assert_eq!(session.cgroup_status, CgroupStatus::Tagged);
    let procs = std::fs::read_to_string(
        cgroup_root
            .join("warder")
            .join(&outcome.session_id)
            .join("cgroup.procs"),
    )
    .unwrap();
    assert_eq!(procs.trim(), "0");
}

#[test]
fn launch_supervised_run_persists_nonzero_exit_code() {
    let config_path = temp_file("warder-cli-launch-nonzero-config", "toml");
    let db_path = temp_file("warder-cli-launch-nonzero-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-nonzero-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
    };

    let outcome = launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    assert_eq!(outcome.exit_code, Some(7));
    let receipt = render_session_receipt_from_db(Some(db_path), &outcome.session_id).unwrap();
    assert!(receipt.contains("status: failed"));
    assert!(receipt.contains("exit code: 7"));
}

#[test]
fn launch_supervised_run_blocks_required_cgroups_without_root() {
    let config_path = temp_file("warder-cli-launch-required-cgroup-config", "toml");
    let db_path = temp_file("warder-cli-launch-required-cgroup-db", "sqlite3");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path),
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
    };

    let error =
        launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap_err();

    assert!(error.message.contains("cgroup tagging is required"));
}

#[test]
fn launch_supervised_run_degrades_best_effort_cgroups_without_root() {
    let config_path = temp_file("warder-cli-launch-best-effort-cgroup-config", "toml");
    let db_path = temp_file("warder-cli-launch-best-effort-cgroup-db", "sqlite3");
    let protected_root = temp_dir("warder-cli-launch-best-effort-cgroup-zone");
    std::fs::create_dir_all(&protected_root).unwrap();
    std::fs::write(
        &config_path,
        config_with_zone_root_and_cgroups(&protected_root, "disabled", "best-effort", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
    };

    let outcome = launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    assert_eq!(outcome.exit_code, Some(0));
    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("--cgroup-root")));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Completed);
    assert_eq!(
        session.cgroup_status,
        CgroupStatus::Degraded(
            "cgroup tagging skipped because --cgroup-root was not provided".to_string()
        )
    );
    assert!(session.cgroup_path.is_none());
}

#[test]
fn launch_supervised_run_refuses_degraded_launch_without_acknowledgement_before_spawn() {
    let config_path = temp_file("warder-cli-launch-degraded-refused-config", "toml");
    let db_path = temp_file("warder-cli-launch-degraded-refused-db", "sqlite3");
    let protected_root = temp_dir("warder-cli-launch-degraded-refused-zone");
    let marker_path = temp_file("warder-cli-launch-degraded-refused-marker", "txt");
    let _ = std::fs::remove_file(&marker_path);
    std::fs::create_dir_all(&protected_root).unwrap();
    std::fs::write(
        &config_path,
        config_with_zone_root_and_cgroups(&protected_root, "disabled", "best-effort", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printf launched > {}", marker_path.display()),
        ],
    };

    let error =
        launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap_err();

    assert!(error.message.contains("degraded launch refused"));
    assert!(error.message.contains("--accept-degraded"));
    assert!(error.message.contains("--cgroup-root"));
    assert!(!marker_path.exists());
    assert!(!db_path.exists());
}

#[test]
fn render_pre_launch_readiness_for_run_reports_launch_decision() {
    let config_path = temp_file("warder-cli-launch-readiness-config", "toml");
    let protected_root = temp_dir("warder-cli-launch-readiness-zone");
    std::fs::create_dir_all(&protected_root).unwrap();
    std::fs::write(
        &config_path,
        config_with_zone_root_and_cgroups(&protected_root, "disabled", "best-effort", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: None,
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    };

    let readiness =
        render_pre_launch_readiness_for_run(&command, &supported_environment()).unwrap();

    assert!(readiness.contains("host readiness: strong"));
    assert!(readiness.contains("launch readiness: degraded"));
    assert!(readiness.contains("launch degraded reasons:"));
    assert!(readiness.contains("--cgroup-root"));
    assert!(readiness.contains("eBPF file journaling unavailable"));
    assert!(readiness.contains("launch visibility limits:"));
    assert!(readiness.contains("fd-write and mmap eBPF observations"));
    assert!(readiness.contains("connected-socket writes"));
    assert!(readiness.contains("launch decision: refused unless --accept-degraded"));

    let mut accepted_command = command.clone();
    if let CliCommand::Run {
        accept_degraded, ..
    } = &mut accepted_command
    {
        *accept_degraded = true;
    }
    let accepted =
        render_pre_launch_readiness_for_run(&accepted_command, &supported_environment()).unwrap();

    assert!(accepted.contains("launch decision: degraded launch accepted by --accept-degraded"));
}

#[test]
fn launch_supervised_run_blocks_required_cgroups_with_invalid_root_before_launch() {
    let config_path = temp_file("warder-cli-launch-invalid-required-cgroup-config", "toml");
    let db_path = temp_file("warder-cli-launch-invalid-required-cgroup-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-missing-required-cgroup");
    let marker_path = temp_file("warder-cli-launch-required-cgroup-marker", "txt");
    let _ = std::fs::remove_dir_all(&cgroup_root);
    let _ = std::fs::remove_file(&marker_path);
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("printf launched > {}", marker_path.display()),
        ],
    };

    let error =
        launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap_err();

    assert!(error.message.contains("cgroup root"));
    assert!(error.message.contains("does not exist"));
    assert!(!marker_path.exists());
}

#[test]
fn launch_supervised_run_degrades_best_effort_cgroups_with_invalid_root() {
    let config_path = temp_file(
        "warder-cli-launch-invalid-best-effort-cgroup-config",
        "toml",
    );
    let db_path = temp_file("warder-cli-launch-invalid-best-effort-cgroup-db", "sqlite3");
    let protected_root = temp_dir("warder-cli-launch-invalid-best-effort-cgroup-zone");
    let cgroup_root = temp_dir("warder-cli-launch-missing-best-effort-cgroup");
    let _ = std::fs::remove_dir_all(&cgroup_root);
    std::fs::create_dir_all(&protected_root).unwrap();
    std::fs::write(
        &config_path,
        config_with_zone_root_and_cgroups(&protected_root, "disabled", "best-effort", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
    };

    let outcome = launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    assert_eq!(outcome.exit_code, Some(0));
    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("cgroup root") && warning.contains("does not exist")));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Completed);
    assert!(matches!(
        session.cgroup_status,
        CgroupStatus::Degraded(ref message)
            if message.contains("cgroup root") && message.contains("does not exist")
    ));
    assert!(session.cgroup_path.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn launch_supervised_run_persists_inotify_file_journal_events() {
    let config_path = temp_file("warder-cli-launch-inotify-config", "toml");
    let db_path = temp_file("warder-cli-launch-inotify-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-inotify-cgroup");
    let protected_root = temp_dir("warder-cli-launch-inotify-zone");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::create_dir_all(&protected_root).unwrap();
    std::fs::write(
        &config_path,
        format!(
            r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "required"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["{}"]
                write-policy = "allow"
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
            protected_root.display()
        ),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "printf hello > {}",
                protected_root.join("todo.md").display()
            ),
        ],
    };

    launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session_id = db.list_sessions().unwrap()[0].id.clone();
    let events = db.list_file_journal_events(Some(&session_id)).unwrap();
    assert!(events.iter().any(|event| {
        event.protected_zone_id == Some("notes".to_string())
            && event.path == protected_root.join("todo.md")
            && event.source == warder_journal::JournalSource::Inotify
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn launch_supervised_run_persists_inotify_events_inside_created_directories() {
    let config_path = temp_file("warder-cli-launch-inotify-dynamic-config", "toml");
    let db_path = temp_file("warder-cli-launch-inotify-dynamic-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-inotify-dynamic-cgroup");
    let protected_root = temp_dir("warder-cli-launch-inotify-dynamic-zone");
    let dynamic_root = protected_root.join("new-workspace");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::create_dir_all(&protected_root).unwrap();
    std::fs::write(
        &config_path,
        format!(
            r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "required"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["{}"]
                write-policy = "allow"
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
            protected_root.display()
        ),
    )
    .unwrap();
    let command_text = format!(
        "mkdir -p {dynamic} && sleep 0.1 && printf hello > {file}",
        dynamic = dynamic_root.display(),
        file = dynamic_root.join("todo.md").display()
    );
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), command_text],
    };

    launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session_id = db.list_sessions().unwrap()[0].id.clone();
    let events = db.list_file_journal_events(Some(&session_id)).unwrap();
    assert!(events.iter().any(|event| {
        event.protected_zone_id == Some("notes".to_string())
            && event.path == dynamic_root.join("todo.md")
            && event.source == warder_journal::JournalSource::Inotify
            && event.attribution == warder_journal::JournalAttribution::SessionWindow
    }));
}

#[test]
fn launch_supervised_run_records_dependency_file_diff() {
    let config_path = temp_file("warder-cli-launch-dependency-diff-config", "toml");
    let db_path = temp_file("warder-cli-launch-dependency-diff-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-dependency-diff-cgroup");
    let zone_root = temp_dir("warder-cli-launch-dependency-diff-zone");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::create_dir_all(&zone_root).unwrap();
    std::fs::write(
        zone_root.join("Cargo.toml"),
        "[package]\nname = \"before\"\n",
    )
    .unwrap();
    std::fs::write(
        &config_path,
        config_with_zone_root(&zone_root, "disabled", "disabled"),
    )
    .unwrap();
    let command_text = format!(
        "printf '[package]\\nname = \"after\"\\n' > {}",
        zone_root.join("Cargo.toml").display()
    );
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), command_text],
    };

    let outcome = launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.dependency_file_changes.len(), 1);
    assert_eq!(
        session.dependency_file_changes[0].path,
        zone_root.join("Cargo.toml")
    );
    assert_eq!(
        session.dependency_file_changes[0].status,
        DependencyFileChangeStatus::Modified
    );
    assert_ne!(
        session.dependency_file_changes[0].before_hash,
        session.dependency_file_changes[0].after_hash
    );
}

#[test]
fn launch_supervised_run_records_ebpf_journal_degraded_reason() {
    let config_path = temp_file("warder-cli-launch-ebpf-config", "toml");
    let db_path = temp_file("warder-cli-launch-ebpf-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-ebpf-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
    };

    let outcome = launch_supervised_run(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: false,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap();

    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("eBPF")));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert!(session
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("eBPF")));
}

#[test]
fn launch_supervised_run_records_unwired_ebpf_attach_reason() {
    let config_path = temp_file("warder-cli-launch-ebpf-attach-config", "toml");
    let db_path = temp_file("warder-cli-launch-ebpf-attach-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-ebpf-attach-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
    };

    let outcome = launch_supervised_run(
        &command,
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap();

    assert!(outcome.validation_warnings.iter().any(|warning| warning
        .contains("eBPF file journaling unavailable: live attach is not implemented yet")));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert!(session.degraded_reasons.iter().any(|reason| reason
        .contains("eBPF file journaling unavailable: live attach is not implemented yet")));
}

#[test]
fn launch_supervised_run_blocks_when_landlock_is_required_but_kernel_is_unavailable() {
    let config_path = temp_file("warder-cli-launch-landlock-required-config", "toml");
    let db_path = temp_file("warder-cli-launch-landlock-required-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-landlock-required-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(&config_path, valid_config("disabled")).unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 99".to_string()],
    };

    let error = launch_supervised_run(
        &command,
        &EnvironmentSupport {
            landlock: false,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap_err();

    assert!(error.message.contains("kernel does not expose Landlock"));
}

#[test]
fn launch_supervised_run_strict_mode_blocks_degraded_write_lockout() {
    let config_path = temp_file("warder-cli-launch-strict-landlock-config", "toml");
    let db_path = temp_file("warder-cli-launch-strict-landlock-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-strict-landlock-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_writable_roots("best-effort", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: true,
        receipt_key: None,
        accept_degraded: false,
        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "exit 99".to_string()],
    };

    let error = launch_supervised_run(
        &command,
        &EnvironmentSupport {
            landlock: false,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap_err();

    assert!(error.message.contains("--require-enforcement refused"));
    assert!(error.message.contains("Landlock unavailable"));
    assert!(!db_path.exists());
}

#[test]
fn launch_supervised_run_best_effort_still_records_degraded_write_lockout() {
    let config_path = temp_file("warder-cli-launch-best-effort-landlock-config", "toml");
    let db_path = temp_file("warder-cli-launch-best-effort-landlock-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-best-effort-landlock-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_writable_roots("best-effort", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,
        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
    };

    let outcome = launch_supervised_run(
        &command,
        &EnvironmentSupport {
            landlock: false,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
        fixed_time(),
    )
    .unwrap();

    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert!(matches!(
        session.landlock_status,
        LandlockStatus::Degraded(ref message) if message.contains("Landlock unavailable")
    ));
    assert!(session
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("Landlock unavailable")));
}

#[test]
fn planned_landlock_restrictions_apply_when_kernel_is_available() {
    let config =
        WarderConfig::from_toml(&valid_config_with_writable_roots("required", "disabled")).unwrap();

    let plan = planned_landlock_restrictions(&config, &supported_environment());

    assert_eq!(plan.status, LandlockPlanStatus::Apply);
}

#[test]
fn planned_landlock_restrictions_blocks_without_writable_roots() {
    let config = WarderConfig::from_toml(&valid_config("disabled")).unwrap();

    let plan = planned_landlock_restrictions(&config, &supported_environment());

    assert!(
        matches!(plan.status, LandlockPlanStatus::Blocked(message) if message.contains("writable root"))
    );
}

#[test]
fn launch_supervised_run_marks_session_failed_when_spawn_fails() {
    let config_path = temp_file("warder-cli-launch-spawn-fails-config", "toml");
    let db_path = temp_file("warder-cli-launch-spawn-fails-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-spawn-fails-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["/definitely/missing/warder-test-command".to_string()],
    };

    let error =
        launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap_err();

    assert!(error
        .message
        .contains("failed to launch supervised command"));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let sessions = db.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, SessionStatus::Failed);
    assert!(sessions[0].ended_at.is_some());
    assert!(sessions[0].root_pid.is_none());
    assert!(sessions[0]
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("failed to launch supervised command")));
}

#[test]
fn launch_supervised_run_marks_session_failed_when_cgroup_tagging_errors() {
    let config_path = temp_file("warder-cli-launch-tag-fails-config", "toml");
    let db_path = temp_file("warder-cli-launch-tag-fails-db", "sqlite3");
    let cgroup_root = temp_dir("warder-cli-launch-tag-fails-cgroup");
    std::fs::create_dir_all(&cgroup_root).unwrap();
    std::fs::write(cgroup_root.join("cgroup.procs"), "").unwrap();
    std::fs::write(cgroup_root.join("warder"), "not a directory").unwrap();
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: Some(cgroup_root),
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local".to_string(),
        command: vec!["sh".to_string(), "-c".to_string(), "sleep 5".to_string()],
    };

    let error =
        launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap_err();

    assert!(error.message.contains("failed to create cgroup"));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let sessions = db.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, SessionStatus::Failed);
    assert!(sessions[0].ended_at.is_some());
    assert!(sessions[0].root_pid.is_none());
    assert!(sessions[0]
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("failed to create cgroup")));
}

#[test]
fn wait_failure_marks_session_failed_with_reason() {
    let config_path = temp_file("warder-cli-wait-fails-config", "toml");
    let db_path = temp_file("warder-cli-wait-fails-db", "sqlite3");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let command = CliCommand::Run {
        config: Some(config_path),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: false,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: false,

        agent: "local".to_string(),
        command: vec!["sh".to_string()],
    };
    let outcome = create_run_session(&command, &supported_environment(), fixed_time()).unwrap();

    let error = finish_wait_result(
        &db_path,
        &outcome.session_id,
        Err(std::io::Error::other("wait failed")),
    )
    .unwrap_err();

    assert!(error
        .message
        .contains("failed to wait for supervised command"));
    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let session = db.get_session(&outcome.session_id).unwrap().unwrap();
    assert_eq!(session.status, SessionStatus::Failed);
    assert!(session.ended_at.is_some());
    assert!(session
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("wait failed")));
}

#[test]
fn render_session_receipt_summarizes_enforcement_state() {
    let session = receipt_test_session();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("session: session-1"));
    assert!(receipt.contains("profile: codex-cli"));
    assert!(receipt.contains("status: completed"));
    assert!(receipt.contains("exit code: 0"));
    assert!(receipt.contains("cgroup: tagged"));
    assert!(receipt.contains("landlock: degraded: Landlock unavailable"));
    assert!(receipt.contains("snapshot: not requested"));
    assert!(receipt.contains("degraded coverage: 1 reason(s)"));
    assert!(receipt.contains("degraded reasons:"));
    assert!(receipt.contains("Landlock unavailable"));
    assert!(receipt.contains("receipt limitations:"));
    assert!(receipt.contains("commands run directly outside Warder are not contained"));
    assert!(receipt.contains("Protected-path reads are not blocked by default"));
    assert!(
        receipt.contains("limited to inotify protected-path changes plus live eBPF observations")
    );
    assert!(receipt.contains("fd writes"));
    assert!(receipt.contains("Network policy is visibility-only in this alpha"));
    assert!(receipt.contains("not tamper-proof forensics"));
}

#[test]
fn render_session_receipt_uses_shared_readiness_language() {
    let session = receipt_test_session();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("session readiness: degraded"));
    assert!(receipt.contains("blocked reasons: none"));
    assert!(receipt.contains("degraded reasons:"));
    assert!(receipt.contains("- Landlock unavailable"));
}

#[test]
fn render_session_receipt_readiness_is_strong_without_blocked_or_degraded_reasons() {
    let mut session = receipt_test_session();
    session.landlock_status = warder_core::LandlockStatus::Applied;
    session.cgroup_status = CgroupStatus::NotRequested;
    session.cgroup_path = None;
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("session readiness: strong"));
    assert!(receipt.contains("blocked reasons: none"));
    assert!(receipt.contains("degraded reasons: none"));
    assert!(receipt.contains("coverage degraded reasons: none"));
}

#[test]
fn render_session_receipt_readiness_blocks_unsupported_cgroups() {
    let mut session = receipt_test_session();
    session.cgroup_status = CgroupStatus::Unsupported("cgroup v2 unavailable".to_string());
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("session readiness: blocked"));
    assert!(receipt.contains("blocked reasons:"));
    assert!(receipt.contains("- cgroups unavailable: cgroup v2 unavailable"));
    assert!(receipt.contains("degraded reasons: none"));
}

#[test]
fn render_session_receipt_readiness_blocks_unsupported_landlock() {
    let mut session = receipt_test_session();
    session.landlock_status =
        warder_core::LandlockStatus::Unsupported("kernel ABI missing".to_string());
    session.cgroup_status = CgroupStatus::NotRequested;
    session.cgroup_path = None;
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("session readiness: blocked"));
    assert!(receipt.contains("- Landlock unavailable: kernel ABI missing"));
    assert!(receipt.contains("degraded reasons: none"));
}

#[test]
fn render_session_receipt_readiness_degrades_best_effort_snapshot_failure() {
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Failed("Btrfs snapshots unavailable".to_string());
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("session readiness: degraded"));
    assert!(receipt.contains("blocked reasons: none"));
    assert!(receipt.contains("- Btrfs snapshots unavailable"));
}

#[test]
fn render_session_receipt_readiness_blocks_failed_snapshot_session() {
    let mut session = receipt_test_session();
    session.status = SessionStatus::Failed;
    session.exit_code = Some(1);
    session.snapshot_status = SnapshotStatus::Failed("Btrfs snapshots unavailable".to_string());
    session.cgroup_status = CgroupStatus::NotRequested;
    session.cgroup_path = None;
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("session readiness: blocked"));
    assert!(receipt.contains("- snapshot unavailable: Btrfs snapshots unavailable"));
    assert!(receipt.contains("degraded reasons: none"));
}

#[test]
fn render_session_receipt_quotes_command_arguments_with_spaces() {
    let mut session = receipt_test_session();
    session.command = vec![
        "sh".to_string(),
        "-c".to_string(),
        "echo hello > /tmp/warder out.txt".to_string(),
    ];

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("command: sh -c 'echo hello > /tmp/warder out.txt'"));
}

#[test]
fn dependency_summary_flags_package_manager_command() {
    let summary =
        dependency_change_summary(&["cargo".to_string(), "add".to_string(), "serde".to_string()]);

    assert_eq!(summary.status, "possible");
    assert!(summary.reason.contains("package manager"));
    assert!(summary.evidence.contains(&"cargo add".to_string()));
}

#[test]
fn dependency_summary_flags_dependency_file_command() {
    let summary = dependency_change_summary(&[
        "sh".to_string(),
        "-c".to_string(),
        "cat Cargo.toml".to_string(),
    ]);

    assert_eq!(summary.status, "possible");
    assert!(summary.reason.contains("dependency file"));
    assert!(summary.evidence.contains(&"Cargo.toml".to_string()));
}

#[test]
fn dependency_summary_reports_no_signal_for_unrelated_command() {
    let summary =
        dependency_change_summary(&["sh".to_string(), "-c".to_string(), "true".to_string()]);

    assert_eq!(summary.status, "none_detected");
    assert!(summary.evidence.is_empty());
}

#[test]
fn dependency_file_snapshot_scans_known_files_in_zone_roots() {
    let zone_root = temp_dir("warder-cli-dependency-scan-zone");
    std::fs::create_dir_all(&zone_root).unwrap();
    std::fs::write(zone_root.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
    std::fs::write(zone_root.join("notes.md"), "not a dependency file\n").unwrap();

    let snapshot = scan_dependency_files(std::slice::from_ref(&zone_root)).unwrap();

    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].path, zone_root.join("Cargo.toml"));
    assert!(!snapshot[0].content_hash.is_empty());
}

#[test]
fn dependency_file_snapshot_scans_known_files_below_zone_roots() {
    let zone_root = temp_dir("warder-cli-dependency-scan-nested-zone");
    let nested_root = zone_root.join("workspace").join("crate-a");
    std::fs::create_dir_all(&nested_root).unwrap();
    std::fs::write(
        nested_root.join("Cargo.toml"),
        "[package]\nname = \"nested\"\n",
    )
    .unwrap();

    let snapshot = scan_dependency_files(std::slice::from_ref(&zone_root)).unwrap();

    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].path, nested_root.join("Cargo.toml"));
}

#[test]
fn dependency_file_diff_reports_created_modified_and_removed_files() {
    let before = vec![
        DependencyFileSnapshot {
            path: PathBuf::from("/tmp/Cargo.toml"),
            content_hash: "before".to_string(),
        },
        DependencyFileSnapshot {
            path: PathBuf::from("/tmp/package.json"),
            content_hash: "same".to_string(),
        },
        DependencyFileSnapshot {
            path: PathBuf::from("/tmp/requirements.txt"),
            content_hash: "removed".to_string(),
        },
    ];
    let after = vec![
        DependencyFileSnapshot {
            path: PathBuf::from("/tmp/Cargo.toml"),
            content_hash: "after".to_string(),
        },
        DependencyFileSnapshot {
            path: PathBuf::from("/tmp/package.json"),
            content_hash: "same".to_string(),
        },
        DependencyFileSnapshot {
            path: PathBuf::from("/tmp/pyproject.toml"),
            content_hash: "created".to_string(),
        },
    ];

    let changes = diff_dependency_file_snapshots(&before, &after);

    assert_eq!(changes.len(), 3);
    assert!(changes.iter().any(|change| {
        change.path == Path::new("/tmp/Cargo.toml")
            && change.status == DependencyFileChangeStatus::Modified
    }));
    assert!(changes.iter().any(|change| {
        change.path == Path::new("/tmp/pyproject.toml")
            && change.status == DependencyFileChangeStatus::Created
    }));
    assert!(changes.iter().any(|change| {
        change.path == Path::new("/tmp/requirements.txt")
            && change.status == DependencyFileChangeStatus::Removed
    }));
}

#[test]
fn render_session_receipt_json_is_structured() {
    let session = receipt_test_session();

    let receipt = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();

    assert_eq!(parsed["session_id"], "session-1");
    assert_eq!(parsed["agent"]["id"], "local");
    assert_eq!(parsed["agent"]["profile"], "codex-cli");
    assert_eq!(parsed["status"], "completed");
    assert_eq!(parsed["exit_code"], 0);
    assert_eq!(parsed["command"][0], "sh");
    assert!(parsed["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|limitation| limitation
            .as_str()
            .unwrap()
            .contains("commands run directly outside Warder")));
    assert!(parsed["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|limitation| limitation
            .as_str()
            .unwrap()
            .contains("Protected-path reads are not blocked by default")));
    assert!(parsed["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|limitation| limitation.as_str().unwrap().contains("fd writes")));
    assert_eq!(parsed["enforcement"]["cgroup"]["status"], "tagged");
    assert_eq!(parsed["enforcement"]["landlock"]["status"], "degraded");
    assert_eq!(parsed["enforcement"]["snapshot"]["status"], "not_requested");
    assert_eq!(parsed["dependency_changes"]["status"], "none_detected");
    assert_eq!(parsed["readiness"]["level"], "degraded");
    assert_eq!(
        parsed["readiness"]["blocked_reasons"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        parsed["readiness"]["degraded_reasons"][0],
        "Landlock unavailable"
    );
    assert_eq!(parsed["degraded_coverage"]["total_reasons"], 1);
    assert_eq!(parsed["degraded_reasons"][0], "Landlock unavailable");
    assert_eq!(
        parsed["enforcement"]["cgroup"]["message"],
        serde_json::Value::Null
    );
    assert_eq!(parsed["review_actions"][0]["kind"], "doctor");
    assert_eq!(parsed["review_actions"][0]["command"], "warder doctor");
    assert_eq!(parsed["review_actions"][0]["mutates"], false);
    assert_eq!(
        parsed["review_actions"][0]["reason"],
        "Landlock unavailable"
    );
    assert_eq!(parsed["recovery_actions"][0]["kind"], "doctor");
    assert_eq!(parsed["recovery_actions"][0]["command"], "warder doctor");
    assert_eq!(
        parsed["recovery_actions"][0]["reason"],
        "Landlock unavailable"
    );
}

#[test]
fn render_session_receipt_json_includes_structured_failure_recovery_action() {
    let mut session = receipt_test_session();
    session.status = SessionStatus::Failed;
    session.exit_code = Some(2);
    session.degraded_reasons.clear();

    let receipt = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();

    assert_eq!(parsed["recovery_actions"][0]["kind"], "export_receipt");
    assert_eq!(
        parsed["recovery_actions"][0]["command"],
        "warder receipt --session session-1 --format json"
    );
    assert_eq!(
        parsed["recovery_actions"][0]["reason"],
        "session failed with exit code 2"
    );
}

#[test]
fn render_session_receipt_json_reports_guarded_snapshot_restore() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-ready-snapshot-json");
    write_ready_btrfs_manifest(&snapshot_root, "snap-1");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    let preview_command = format!(
        "warder revert --snapshot snap-1 --snapshot-root {} --preview",
        snapshot_root.display()
    );
    let restore_command = format!(
        "warder revert --snapshot snap-1 --snapshot-root {}",
        snapshot_root.display()
    );

    let actions = parsed["recovery_actions"].as_array().unwrap();
    assert!(actions.iter().any(|action| {
        action["kind"] == "preview_snapshot_restore"
            && action["command"] == preview_command
            && action["command_argv"]
                == serde_json::json!([
                    "warder",
                    "revert",
                    "--snapshot",
                    "snap-1",
                    "--snapshot-root",
                    snapshot_root.display().to_string(),
                    "--preview"
                ])
            && action["mutates"] == false
            && action["reason"]
                == "preview uses the recorded Btrfs snapshot root and makes no changes"
    }));
    assert!(actions.iter().any(|action| {
        action["kind"] == "restore_snapshot_guarded"
            && action["command"] == restore_command
            && action["command_argv"]
                == serde_json::json!([
                    "warder",
                    "revert",
                    "--snapshot",
                    "snap-1",
                    "--snapshot-root",
                    snapshot_root.display().to_string()
                ])
            && action["mutates"] == true
            && action["reason"] == "guarded restore refuses to overwrite existing target paths"
    }));
    assert_eq!(
        parsed["enforcement"]["snapshot"]["path"],
        snapshot_root.display().to_string()
    );
}

#[test]
fn render_session_receipt_json_adds_db_to_guarded_snapshot_restore_action() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-ready-snapshot-db");
    write_ready_btrfs_manifest(&snapshot_root, "snap-1");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt_json_with_activity(
        &session,
        &[],
        &[],
        Some(Path::new("/tmp/warder.sqlite3")),
    )
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();

    let actions = parsed["recovery_actions"].as_array().unwrap();
    assert!(actions.iter().any(|action| {
            action["kind"] == "restore_snapshot_guarded"
                && action["command"]
                    == format!(
                        "warder revert --snapshot snap-1 --snapshot-root {} --db /tmp/warder.sqlite3 --session session-1",
                        snapshot_root.display()
                )
                && action["command_argv"]
                    == serde_json::json!([
                        "warder",
                        "revert",
                        "--snapshot",
                        "snap-1",
                        "--snapshot-root",
                        snapshot_root.display().to_string(),
                        "--db",
                        "/tmp/warder.sqlite3",
                        "--session",
                        "session-1"
                    ])
        }));
}

#[test]
fn receipt_recovery_commands_quote_paths_with_spaces() {
    let snapshot_root = temp_dir("warder cli receipt ready snapshot spaced");
    let db_path = temp_file("warder cli receipt db spaced", "sqlite3");

    assert_eq!(
        guarded_snapshot_restore_preview_command("snap-1", &snapshot_root),
        format!(
            "warder revert --snapshot snap-1 --snapshot-root '{}' --preview",
            snapshot_root.display()
        )
    );
    assert_eq!(
        guarded_snapshot_restore_command_for_receipt(
            "snap-1",
            Some(&snapshot_root),
            Some(&db_path),
            "session 1"
        ),
        format!(
            "warder revert --snapshot snap-1 --snapshot-root '{}' --db '{}' --session 'session 1'",
            snapshot_root.display(),
            db_path.display()
        )
    );
    assert_eq!(
        journal_command(Some(&db_path), "session 1"),
        format!(
            "warder journal --db '{}' --session 'session 1' --file",
            db_path.display()
        )
    );
    assert_eq!(
        receipt_json_command(Some(&db_path), "session 1"),
        format!(
            "warder receipt --db '{}' --session 'session 1' --format json",
            db_path.display()
        )
    );
}

#[test]
fn shell_command_rendering_quotes_apostrophes_and_empty_arguments() {
    assert_eq!(shell_quote(""), "''");
    assert_eq!(
        shell_quote("notes/ben's file.txt"),
        "'notes/ben'\\''s file.txt'"
    );
    assert_eq!(
        shell_command_line(&[
            "sh".to_string(),
            "-c".to_string(),
            "printf '%s\\n' \"hello world\"".to_string(),
            "".to_string(),
        ]),
        "sh -c 'printf '\\''%s\\n'\\'' \"hello world\"' ''"
    );
}

#[test]
fn render_session_receipt_withholds_guarded_snapshot_restore_when_manifest_plan_is_blocked() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-blocked-snapshot");
    write_blocked_btrfs_manifest_with_existing_target(&snapshot_root, "snap-1");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("Restore snapshot with explicit snapshot root"));
    assert!(receipt.contains(&format!(
            "Guarded snapshot restore is withheld because the current restore plan is blocked: blocked: target exists at {}.",
            snapshot_root.join("project").display()
        )));
    assert!(receipt.contains(&format!(
            "Preview guarded snapshot restore: warder revert --snapshot snap-1 --snapshot-root {} --preview",
            snapshot_root.display()
        )));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let actions = parsed["recovery_actions"].as_array().unwrap();
    assert!(actions
        .iter()
        .any(|action| action["kind"] == "preview_snapshot_restore"));
    assert!(!actions
        .iter()
        .any(|action| action["kind"] == "restore_snapshot_guarded"));
    assert!(actions.iter().any(
            |action| action["kind"] == "review_snapshot_restore_withheld"
                && action["reason"]
                    == format!(
                        "Guarded snapshot restore is withheld because the current restore plan is blocked: blocked: target exists at {}.",
                        snapshot_root.join("project").display()
                    )
            ));
}

#[test]
fn render_session_receipt_names_missing_snapshot_path_when_restore_is_withheld() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-missing-snapshot-path");
    write_blocked_btrfs_manifest_with_missing_snapshot_path(&snapshot_root, "snap-1");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Restore snapshot with explicit snapshot root"));
    assert!(receipt.contains(&format!(
            "Guarded snapshot restore is withheld because the current restore plan is blocked: blocked: snapshot path missing at {}.",
            snapshot_root.join("snap-1").join("project").display()
        )));
}

#[test]
fn render_session_receipt_names_missing_target_parent_when_restore_is_withheld() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-missing-target-parent");
    write_blocked_btrfs_manifest_with_missing_target_parent(&snapshot_root, "snap-1");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Restore snapshot with explicit snapshot root"));
    assert!(receipt.contains(&format!(
            "Guarded snapshot restore is withheld because the current restore plan is blocked: blocked: target parent missing at {}.",
            snapshot_root
                .join("missing-parent")
                .join("project")
                .display()
        )));
}

#[test]
fn render_session_receipt_withholds_guarded_snapshot_restore_when_manifest_is_missing() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-missing-manifest");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("Restore snapshot with explicit snapshot root"));
    assert!(receipt.contains(
        "Guarded snapshot restore is withheld: snapshot manifest unavailable for snapshot 'snap-1'"
    ));
    assert!(receipt.contains(&format!(
            "Preview guarded snapshot restore: warder revert --snapshot snap-1 --snapshot-root {} --preview",
            snapshot_root.display()
        )));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let actions = parsed["recovery_actions"].as_array().unwrap();
    assert!(actions
        .iter()
        .any(|action| action["kind"] == "preview_snapshot_restore"));
    assert!(!actions
        .iter()
        .any(|action| action["kind"] == "restore_snapshot_guarded"));
    assert!(actions.iter().any(
        |action| action["kind"] == "review_snapshot_restore_withheld"
            && action["reason"]
                .as_str()
                .unwrap()
                .contains("snapshot manifest unavailable for snapshot 'snap-1'")
    ));
}

#[test]
fn render_session_receipt_withholds_guarded_snapshot_restore_when_manifest_is_empty() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-empty-manifest");
    write_empty_btrfs_manifest(&snapshot_root, "snap-1");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("Restore snapshot with explicit snapshot root"));
    assert!(receipt.contains(
        "Guarded snapshot restore is withheld because the snapshot manifest has no entries."
    ));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let actions = parsed["recovery_actions"].as_array().unwrap();
    assert!(!actions
        .iter()
        .any(|action| action["kind"] == "restore_snapshot_guarded"));
    assert!(actions.iter().any(
            |action| action["kind"] == "review_snapshot_restore_withheld"
                && action["reason"]
                    == "Guarded snapshot restore is withheld because the snapshot manifest has no entries."
        ));
}

#[test]
fn render_session_receipt_withholds_guarded_snapshot_restore_for_active_session() {
    let mut session = receipt_test_session();
    session.status = SessionStatus::Running;
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(PathBuf::from("/tmp/warder-snapshots")),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("warder revert --snapshot snap-1"));
    assert!(receipt.contains("Snapshot restore is withheld while the session is still running"));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "restore_snapshot_guarded"));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |action| action["kind"] == "review_snapshot_restore_withheld"
                && action["command"] == "warder receipt --session session-1 --format json"
                && action["reason"]
                    .as_str()
                    .unwrap()
                    .contains("session is still running")
        ));
    assert!(parsed["recovery_guidance"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item
            .as_str()
            .unwrap()
            .contains("Snapshot restore is withheld while the session is still running")));
}

#[test]
fn render_session_receipt_withholds_guarded_snapshot_restore_without_recorded_root() {
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: None,
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("warder revert --snapshot snap-1"));
    assert!(receipt.contains("does not record a snapshot root"));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "restore_snapshot_guarded"));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |action| action["kind"] == "review_snapshot_restore_withheld"
                && action["mutates"] == false
                && action["reason"]
                    .as_str()
                    .unwrap()
                    .contains("does not record a snapshot root")
        ));
}

#[test]
fn render_session_receipt_withholds_guarded_snapshot_restore_for_non_btrfs_snapshot() {
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::OverlayFs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(PathBuf::from("/tmp/warder-snapshots")),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("warder revert --snapshot snap-1"));
    assert!(receipt.contains("recorded snapshot backend is overlayfs"));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "restore_snapshot_guarded"));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |action| action["kind"] == "review_snapshot_restore_withheld"
                && action["mutates"] == false
                && action["reason"]
                    .as_str()
                    .unwrap()
                    .contains("recorded snapshot backend is overlayfs")
        ));
}

#[test]
fn render_session_receipt_withholds_guarded_snapshot_restore_after_revert() {
    let mut session = receipt_test_session();
    session.status = SessionStatus::Reverted;
    session.snapshot_status = SnapshotStatus::Reverted {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(PathBuf::from("/tmp/warder-snapshots")),
    };

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("warder revert --snapshot snap-1"));
    assert!(receipt.contains(
        "Snapshot restore is already recorded as reverted; no guarded restore action is offered."
    ));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(!parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "restore_snapshot_guarded"));
    assert!(parsed["recovery_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |action| action["kind"] == "review_snapshot_restore_withheld"
                    && action["mutates"] == false
                    && action["reason"]
                        == "Snapshot restore is already recorded as reverted; no guarded restore action is offered."
            ));
}

#[test]
fn render_session_receipt_includes_failed_snapshot_reason_in_withheld_restore() {
    let mut session = receipt_test_session();
    session.snapshot_status = SnapshotStatus::Failed("btrfs unavailable".to_string());

    let receipt = render_session_receipt(&session);

    assert!(!receipt.contains("Guarded snapshot restore is available"));
    assert!(!receipt.contains("warder revert --snapshot"));
    assert!(receipt.contains(
            "Do not rely on snapshot recovery for this session; snapshot creation failed: btrfs unavailable."
        ));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["recovery_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |action| action["kind"] == "review_snapshot_restore_withheld"
                    && action["reason"]
                        == "Do not rely on snapshot recovery for this session; snapshot creation failed: btrfs unavailable."
            ));
}

#[test]
fn render_session_receipt_includes_dependency_change_signal() {
    let mut session = receipt_test_session();
    session.command = vec!["cargo".to_string(), "add".to_string(), "serde".to_string()];

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("dependency changes: possible"));
    assert!(receipt.contains("package manager operation"));
    assert!(receipt.contains("cargo add"));
    assert!(receipt.contains("review guidance:"));
    assert!(receipt.contains("Review dependency file changes before trusting the run output."));
    assert!(receipt.contains("Treat degraded coverage as incomplete protection, not success."));
}

#[test]
fn render_session_receipt_includes_text_review_and_recovery_actions() {
    let session = receipt_test_session();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("review actions:"));
    assert!(
        receipt.contains("- Inspect host readiness: warder doctor (reason: Landlock unavailable)")
    );
    assert!(receipt.contains("recovery actions:"));
    assert!(receipt.contains(
        "- Inspect host readiness before rerun: warder doctor (reason: Landlock unavailable)"
    ));
}

#[test]
fn render_session_receipt_includes_openclaw_review_and_recovery_actions() {
    let mut session = receipt_test_session();
    session.agent_id = "openclaw".to_string();
    session.agent_label = "OpenClaw".to_string();
    session.agent_profile = Some("openclaw-agent".to_string());
    session.command = vec![
        "openclaw".to_string(),
        "agent".to_string(),
        "--message".to_string(),
        "check workspace".to_string(),
    ];
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("- Run OpenClaw security audit: openclaw security audit --deep"));
    assert!(receipt.contains("- Inspect OpenClaw sandbox posture: openclaw sandbox explain --json"));
    assert!(
        receipt.contains("OpenClaw controls app-level gateway, channel, tool, and sandbox policy")
    );
    assert!(receipt.contains(
        "- Export receipt before changing OpenClaw config: warder receipt --session session-1 --format json"
    ));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["review_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "openclaw_security_audit"
            && action["command_argv"][0] == "openclaw"));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "export_openclaw_receipt"));
}

#[test]
fn render_session_receipt_includes_manual_text_review_actions() {
    let mut session = receipt_test_session();
    session.command = vec!["cargo".to_string(), "add".to_string(), "serde".to_string()];
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains(
            "- Review dependency file changes: manual review required (reason: command metadata references a package manager operation)"
        ));
}

#[test]
fn render_session_receipt_json_includes_dependency_change_signal() {
    let mut session = receipt_test_session();
    session.command = vec!["cargo".to_string(), "add".to_string(), "serde".to_string()];

    let receipt = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();

    assert_eq!(parsed["dependency_changes"]["status"], "possible");
    assert_eq!(parsed["dependency_changes"]["evidence"][0], "cargo add");
    assert!(parsed["review_guidance"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item
            .as_str()
            .unwrap()
            .contains("Review dependency file changes")));
    assert!(parsed["review_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "review_dependency_files"
            && action["command"].is_null()
            && action["reason"] == "command metadata references a package manager operation"));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "export_dependency_receipt"
            && action["command"] == "warder receipt --session session-1 --format json"
            && action["mutates"] == false
            && action["reason"] == "command metadata references a package manager operation"));
}

#[test]
fn render_session_receipt_includes_persisted_dependency_file_changes() {
    let mut session = receipt_test_session();
    session.dependency_file_changes = vec![DependencyFileChange {
        path: PathBuf::from("/tmp/Cargo.toml"),
        before_hash: Some("before".to_string()),
        after_hash: Some("after".to_string()),
        status: DependencyFileChangeStatus::Modified,
    }];

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("dependency file changes: 1"));
    assert!(receipt.contains("modified /tmp/Cargo.toml"));
    assert!(receipt.contains(
            "- Review dependency file changes: manual review required (reason: dependency file changes were recorded)"
        ));
}

#[test]
fn render_session_receipt_json_includes_persisted_dependency_file_changes() {
    let mut session = receipt_test_session();
    session.dependency_file_changes = vec![DependencyFileChange {
        path: PathBuf::from("/tmp/Cargo.toml"),
        before_hash: Some("before".to_string()),
        after_hash: Some("after".to_string()),
        status: DependencyFileChangeStatus::Modified,
    }];

    let receipt = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();

    assert_eq!(parsed["dependency_file_changes"][0]["status"], "modified");
    assert_eq!(
        parsed["dependency_file_changes"][0]["path"],
        "/tmp/Cargo.toml"
    );
    assert_eq!(
        parsed["dependency_file_changes"][0]["before_hash"],
        "before"
    );
    assert_eq!(parsed["dependency_file_changes"][0]["after_hash"], "after");
    assert!(parsed["review_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "review_dependency_files"
            && action["reason"] == "dependency file changes were recorded"));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "export_dependency_receipt"
            && action["command"] == "warder receipt --session session-1 --format json"
            && action["mutates"] == false
            && action["reason"] == "dependency file changes were recorded"));
}

#[test]
fn failed_dependency_session_uses_single_receipt_export_recovery_action() {
    let mut session = receipt_test_session();
    session.status = SessionStatus::Failed;
    session.exit_code = Some(2);
    session.command = vec!["cargo".to_string(), "add".to_string(), "serde".to_string()];
    session.degraded_reasons.clear();

    let receipt = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    let receipt_export_actions = parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|action| action["command"] == "warder receipt --session session-1 --format json")
        .count();

    assert_eq!(receipt_export_actions, 1);
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "export_receipt"
            && action["reason"] == "session failed with exit code 2"));
    assert!(!parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "export_dependency_receipt"));
}

#[test]
fn render_session_receipt_from_db_supports_json_format() {
    let db_path = temp_file("warder-cli-receipt-json-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    db.insert_file_journal_event(&warder_journal::FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
        process_id: Some(4242),
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/tmp/notes/todo.md"),
        operation: warder_journal::FileOperation::Write,
        decision: warder_journal::FileDecision::Denied,
        source: warder_journal::JournalSource::Landlock,
        confidence: warder_journal::JournalConfidence::Enforced,
        attribution: warder_journal::JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    })
    .unwrap();

    let receipt = render_session_receipt_from_db_with_format(
        Some(db_path.clone()),
        "session-1",
        ReceiptFormat::Json,
    )
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&receipt).unwrap();

    assert_eq!(parsed["session_id"], "session-1");
    assert_eq!(parsed["agent"]["profile"], "codex-cli");
    assert_eq!(
        parsed["enforcement"]["landlock"]["message"],
        "Landlock unavailable"
    );
    assert_eq!(parsed["file_activity"]["total_events"], 1);
    assert_eq!(parsed["file_activity"]["zones"]["notes"], 1);
    assert_eq!(parsed["file_activity"]["attribution"]["direct-process"], 1);
    assert_eq!(
        parsed["review_actions"][0]["command"],
        format!(
            "warder journal --db {} --session session-1 --file",
            db_path.display()
        )
    );
    assert_eq!(
        parsed["review_actions"][0]["command_argv"],
        serde_json::json!([
            "warder",
            "journal",
            "--db",
            db_path.display().to_string(),
            "--session",
            "session-1",
            "--file"
        ])
    );
    assert_eq!(
        parsed["review_actions"][0]["reason"],
        "protected-zone file activity was recorded"
    );
    assert_eq!(
        parsed["recovery_actions"][0]["command"],
        format!(
            "warder journal --db {} --session session-1 --file",
            db_path.display()
        )
    );
    assert_eq!(
        parsed["recovery_actions"][0]["command_argv"],
        serde_json::json!([
            "warder",
            "journal",
            "--db",
            db_path.display().to_string(),
            "--session",
            "session-1",
            "--file"
        ])
    );
    assert_eq!(
        parsed["recovery_actions"][0]["reason"],
        "protected-zone file activity was recorded"
    );
}

#[test]
fn render_session_receipt_from_db_can_sign_and_verify_text_receipts() {
    let db_path = temp_file("warder-cli-receipt-signing-db", "sqlite3");
    let key_path = temp_file("warder-cli-receipt-signing-key", "key");
    initialize_receipt_signing_key(&key_path, true).unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();

    let signed = render_session_receipt_from_db_with_options(
        Some(db_path.clone()),
        "session-1",
        ReceiptFormat::Text,
        Some(&key_path),
        None,
    )
    .unwrap();
    let signature = signed
        .lines()
        .find_map(|line| line.strip_prefix("- value: "))
        .expect("signature value");
    let verified = render_session_receipt_from_db_with_options(
        Some(db_path.clone()),
        "session-1",
        ReceiptFormat::Text,
        Some(&key_path),
        Some(signature),
    )
    .unwrap();

    assert!(signed.contains("receipt signature:"));
    assert!(verified.contains("signature verification: ok"));

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(key_path);
}

#[test]
fn render_session_receipt_from_db_rejects_bad_signature() {
    let db_path = temp_file("warder-cli-receipt-bad-signing-db", "sqlite3");
    let key_path = temp_file("warder-cli-receipt-bad-signing-key", "key");
    initialize_receipt_signing_key(&key_path, true).unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();

    let error = render_session_receipt_from_db_with_options(
        Some(db_path.clone()),
        "session-1",
        ReceiptFormat::Text,
        Some(&key_path),
        Some("00"),
    )
    .unwrap_err();

    assert_eq!(error.message, "receipt signature verification failed");

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(key_path);
}

#[test]
fn render_receipt_integrity_report_accepts_valid_hash_chain() {
    let db_path = temp_file("warder-cli-receipt-integrity-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();

    let report = render_receipt_integrity_report(Some(db_path.clone())).unwrap();

    assert!(report.contains("receipt integrity: ok"));
    assert!(report.contains("sessions checked: 1"));
    assert!(report.contains("integrity log entries: 1"));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn render_receipt_integrity_report_validates_external_key() {
    let db_path = temp_file("warder-cli-receipt-integrity-external-db", "sqlite3");
    let key_path = temp_file("warder-cli-receipt-integrity-external-key", "key");
    initialize_receipt_signing_key(&key_path, true).unwrap();
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();

    let report =
        render_receipt_integrity_report_with_external_key(Some(db_path.clone()), Some(&key_path))
            .unwrap();

    assert!(report.contains("receipt integrity: ok"));
    assert!(report.contains("external receipt key: ok"));

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(key_path);
}

#[test]
fn strict_receipt_key_validation_requires_external_key() {
    let error = validate_strict_receipt_key(true, None).unwrap_err();

    assert!(error.message.contains("--receipt-key"));
}

#[test]
fn strict_receipt_key_validation_accepts_private_key_file() {
    let key_path = temp_file("warder-cli-strict-receipt-key", "key");
    initialize_receipt_signing_key(&key_path, true).unwrap();

    validate_strict_receipt_key(true, Some(&key_path)).unwrap();

    let _ = std::fs::remove_file(key_path);
}

#[test]
fn initialize_receipt_signing_key_creates_private_key_file() {
    let key_path = temp_file("warder-cli-receipt-init-key", "key");
    let _ = std::fs::remove_file(&key_path);

    let status = initialize_receipt_signing_key(&key_path, false).unwrap();
    let key = read_receipt_signing_key(&key_path).unwrap();

    assert!(status.contains("receipt signing key initialized"));
    assert!(key.len() >= 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let _ = std::fs::remove_file(key_path);
}

#[cfg(unix)]
#[test]
fn receipt_signing_key_rejects_group_readable_file() {
    use std::os::unix::fs::PermissionsExt;

    let key_path = temp_file("warder-cli-receipt-world-readable-key", "key");
    std::fs::write(&key_path, b"0123456789abcdef0123456789abcdef").unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = read_receipt_signing_key(&key_path).unwrap_err();

    assert!(error
        .message
        .contains("must not be readable or writable by group/other"));

    let _ = std::fs::remove_file(key_path);
}

#[test]
fn persist_file_journal_events_records_dropped_event_degraded_reason() {
    let db_path = temp_file("warder-cli-journal-limit-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    let events = (0..(MAX_JOURNAL_EVENTS_PER_DRAIN + 1))
        .map(|index| warder_journal::FileJournalEvent {
            session_id: "session-1".to_string(),
            timestamp: fixed_time() + Duration::from_secs(index as u64),
            process_id: None,
            protected_zone_id: Some("notes".to_string()),
            path: PathBuf::from(format!("/tmp/notes/file-{index}.md")),
            operation: warder_journal::FileOperation::Write,
            decision: warder_journal::FileDecision::Observed,
            source: warder_journal::JournalSource::Inotify,
            confidence: warder_journal::JournalConfidence::Observed,
            attribution: warder_journal::JournalAttribution::SessionWindow,
            message: "file activity observed by inotify".to_string(),
        })
        .collect::<Vec<_>>();

    persist_file_journal_events_with_limit(&db_path, "session-1", events, "inotify").unwrap();

    let stored = db.list_file_journal_events(Some("session-1")).unwrap();
    let session = db.get_session("session-1").unwrap().unwrap();
    assert_eq!(stored.len(), MAX_JOURNAL_EVENTS_PER_DRAIN);
    assert!(session
        .degraded_reasons
        .iter()
        .any(|reason| reason.contains("inotify file journal dropped 1 event")));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn render_session_receipt_from_db_includes_file_activity_rollup() {
    let db_path = temp_file("warder-cli-receipt-file-activity-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    db.insert_file_journal_event(&warder_journal::FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
        process_id: None,
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/tmp/notes/todo.md"),
        operation: warder_journal::FileOperation::Create,
        decision: warder_journal::FileDecision::Observed,
        source: warder_journal::JournalSource::Inotify,
        confidence: warder_journal::JournalConfidence::Observed,
        attribution: warder_journal::JournalAttribution::SessionWindow,
        message: "file activity observed by inotify".to_string(),
    })
    .unwrap();

    let receipt = render_session_receipt_from_db(Some(db_path.clone()), "session-1").unwrap();

    assert!(receipt.contains("file activity: 1 event(s)"));
    assert!(receipt.contains("file activity zones: notes=1"));
    assert!(receipt.contains("file activity attribution: session-window=1"));
    assert!(receipt.contains(
            "Inspect file activity rollups and raw journal events for unexpected protected-zone changes."
        ));
    assert!(receipt.contains(
            "Inotify session-window events are observational and are not PID-attributed enforcement evidence."
        ));
    assert!(receipt.contains("recovery guidance:"));
    assert!(receipt.contains(&format!(
            "Run `warder journal --db {} --session session-1 --file` to inspect protected-zone file activity.",
            db_path.display()
        )));
    assert!(receipt.contains(&format!(
            "- Inspect protected-zone file activity: warder journal --db {} --session session-1 --file (reason: protected-zone file activity was recorded)",
            db_path.display()
        )));

    let json =
        render_session_receipt_from_db_with_format(Some(db_path), "session-1", ReceiptFormat::Json)
            .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["review_guidance"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item
            .as_str()
            .unwrap()
            .contains("not PID-attributed enforcement evidence")));
}

#[test]
fn render_session_receipt_from_db_includes_network_activity_rollup() {
    let db_path = temp_file("warder-cli-receipt-network-activity-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    db.insert_network_journal_event(&warder_journal::NetworkJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
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
    .unwrap();

    let receipt = render_session_receipt_from_db(Some(db_path.clone()), "session-1").unwrap();

    assert!(receipt.contains("network activity: 1 event(s)"));
    assert!(receipt.contains("network activity destinations: 203.0.113.10:443=1"));
    assert!(receipt.contains("network activity protocols: tcp=1"));
    assert!(receipt.contains("network activity sources: eBPF=1"));
    assert!(receipt.contains("network activity attribution: direct-process=1"));
    assert!(receipt.contains(
        "Inspect network activity rollups and raw network journal events for unexpected egress."
    ));
    assert!(receipt.contains("Network journal visibility is limited to observed TCP connect(2)"));
    assert!(receipt.contains("socket send(2)"));
    assert!(receipt.contains("not complete socket forensics or enforcement"));
    assert!(receipt.contains(&format!(
            "Run `warder journal --db {} --session session-1 --network` to inspect recorded network egress activity.",
            db_path.display()
        )));
    assert!(receipt.contains(&format!(
            "- Inspect network egress activity: warder journal --db {} --session session-1 --network (reason: network egress activity was recorded)",
            db_path.display()
        )));

    let json =
        render_session_receipt_from_db_with_format(Some(db_path), "session-1", ReceiptFormat::Json)
            .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["network_activity"]["total_events"], 1);
    assert_eq!(
        parsed["network_activity"]["destinations"]["203.0.113.10:443"],
        1
    );
    assert_eq!(parsed["network_activity"]["protocols"]["tcp"], 1);
    assert_eq!(parsed["network_activity"]["sources"]["eBPF"], 1);
    assert_eq!(
        parsed["network_activity"]["attribution"]["direct-process"],
        1
    );
    assert!(parsed["review_guidance"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item
            .as_str()
            .unwrap()
            .contains("not complete socket forensics or enforcement")));
    assert!(parsed["review_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "inspect_network_journal"
            && action["command"].as_str().unwrap().contains("--network")
            && action["reason"] == "network egress activity was recorded"));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "inspect_network_journal"
            && action["command_argv"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg == "--network")
            && action["mutates"] == false));
}

#[test]
fn render_session_receipt_from_db_combines_file_and_network_journal_actions() {
    let db_path = temp_file("warder-cli-receipt-all-activity-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    db.insert_file_journal_event(&warder_journal::FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
        process_id: Some(123),
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/tmp/notes/todo.md"),
        operation: warder_journal::FileOperation::Write,
        decision: warder_journal::FileDecision::Denied,
        source: warder_journal::JournalSource::Landlock,
        confidence: warder_journal::JournalConfidence::Enforced,
        attribution: warder_journal::JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    })
    .unwrap();
    db.insert_network_journal_event(&warder_journal::NetworkJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
        process_id: Some(123),
        destination: "203.0.113.10".to_string(),
        destination_port: Some(443),
        protocol: warder_journal::NetworkProtocol::Tcp,
        decision: warder_journal::NetworkDecision::Observed,
        source: warder_journal::JournalSource::Ebpf,
        confidence: warder_journal::JournalConfidence::Observed,
        attribution: warder_journal::JournalAttribution::DirectProcess,
        message: "network egress observed by eBPF".to_string(),
    })
    .unwrap();

    let receipt = render_session_receipt_from_db(Some(db_path.clone()), "session-1").unwrap();

    assert!(receipt.contains(&format!(
            "Run `warder journal --db {} --session session-1 --all` to inspect recorded file and network activity together.",
            db_path.display()
        )));
    assert!(receipt.contains(&format!(
            "- Inspect all recorded journal activity: warder journal --db {} --session session-1 --all (reason: file and network activity were recorded)",
            db_path.display()
        )));

    let json =
        render_session_receipt_from_db_with_format(Some(db_path), "session-1", ReceiptFormat::Json)
            .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed["review_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "inspect_all_journals"
            && action["command_argv"]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg == "--all")
            && action["mutates"] == false));
    assert!(parsed["recovery_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["kind"] == "inspect_all_journals"
            && action["reason"] == "file and network activity were recorded"));
}

#[test]
fn render_failed_session_receipt_from_db_includes_db_in_export_command() {
    let db_path = temp_file("warder-cli-failed-receipt-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    let mut session = receipt_test_session();
    session.status = SessionStatus::Failed;
    session.degraded_reasons.clear();
    db.create_session(&session).unwrap();

    let receipt = render_session_receipt_from_db(Some(db_path.clone()), "session-1").unwrap();

    assert!(receipt.contains(&format!(
            "Run `warder receipt --db {} --session session-1 --format json` to preserve structured failure details before rerunning.",
            db_path.display()
        )));

    let json = render_session_receipt_from_db_with_format(
        Some(db_path.clone()),
        "session-1",
        ReceiptFormat::Json,
    )
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["recovery_actions"][0]["command"],
        format!(
            "warder receipt --db {} --session session-1 --format json",
            db_path.display()
        )
    );
}

#[test]
fn render_session_receipt_includes_recovery_guidance_for_degraded_coverage() {
    let session = receipt_test_session();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("recovery guidance:"));
    assert!(receipt.contains(
        "Rerun after addressing degraded coverage if this session needed strong protection."
    ));
    assert!(receipt.contains(
            "Run `warder doctor` to inspect host readiness before rerunning a session that needed strong protection."
        ));
}

#[test]
fn render_session_receipt_warns_when_file_journal_coverage_is_degraded() {
    let mut session = receipt_test_session();
    session.degraded_reasons =
        vec!["eBPF file journaling unavailable: live attach is not implemented yet".to_string()];

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("file activity: 0 event(s)"));
    assert!(receipt.contains(
            "File activity may be incomplete because journal coverage degraded; do not treat a quiet journal as proof that protected zones were untouched."
        ));
    assert!(receipt.contains("- Review degraded journal coverage: manual review required"));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["review_guidance"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("quiet journal")));
    assert!(parsed["review_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |action| action["kind"] == "review_degraded_journal_coverage"
                && action["command"].is_null()
        ));
}

#[test]
fn render_session_receipt_warns_when_network_journal_coverage_is_degraded() {
    let mut session = receipt_test_session();
    session.degraded_reasons =
        vec!["eBPF network journaling unavailable: live attach is not implemented yet".to_string()];

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("network activity: 0 event(s)"));
    assert!(receipt.contains(
            "Network activity may be incomplete because live network journal coverage degraded; do not treat quiet egress as proof that no network access happened."
        ));
    assert!(receipt.contains("- Review degraded network journal coverage: manual review required"));

    let json = render_session_receipt_json(&session).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["review_guidance"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("quiet egress")));
    assert!(parsed["review_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |action| action["kind"] == "review_degraded_network_journal_coverage"
                && action["command"].is_null()
        ));
}

#[test]
fn render_session_receipt_includes_recovery_guidance_for_created_snapshot() {
    let mut session = receipt_test_session();
    let snapshot_root = temp_dir("warder-cli-receipt-ready-snapshot-text");
    write_ready_btrfs_manifest(&snapshot_root, "snap-1");
    session.snapshot_status = SnapshotStatus::Created {
        backend: warder_core::SnapshotBackend::Btrfs,
        snapshot_id: "snap-1".to_string(),
        snapshot_root: Some(snapshot_root.clone()),
    };

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("Guarded snapshot restore is available"));
    assert!(receipt.contains(&format!(
            "Preview guarded snapshot restore: warder revert --snapshot snap-1 --snapshot-root {} --preview",
            snapshot_root.display()
        )));
    assert!(receipt.contains(&format!(
            "Restore snapshot with explicit snapshot root (mutates): warder revert --snapshot snap-1 --snapshot-root {}",
            snapshot_root.display()
        )));
}

#[test]
fn render_session_receipt_includes_recovery_guidance_for_failed_session() {
    let mut session = receipt_test_session();
    session.status = SessionStatus::Failed;
    session.exit_code = Some(2);
    session.degraded_reasons.clear();

    let receipt = render_session_receipt(&session);

    assert!(receipt.contains("exit code: 2"));
    assert!(receipt.contains(
        "Inspect the command exit status and rerun only after correcting the failed agent command."
    ));
    assert!(receipt.contains(
            "Run `warder receipt --session session-1 --format json` to preserve structured failure details before rerunning."
        ));
}

#[test]
fn render_file_journal_from_db_reads_persisted_events() {
    let db_path = temp_file("warder-cli-file-journal-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    db.insert_file_journal_event(&warder_journal::FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
        process_id: Some(4242),
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/tmp/notes/todo.md"),
        operation: warder_journal::FileOperation::Write,
        decision: warder_journal::FileDecision::Denied,
        source: warder_journal::JournalSource::Landlock,
        confidence: warder_journal::JournalConfidence::Enforced,
        attribution: warder_journal::JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    })
    .unwrap();

    let journal = render_file_journal_from_db(Some(db_path), Some("session-1")).unwrap();

    assert!(journal.contains("session-1"));
    assert!(journal.contains("write denied"));
    assert!(journal.contains("/tmp/notes/todo.md"));
    assert!(journal.contains("attribution=direct-process"));
}

#[test]
fn render_network_journal_from_db_reads_persisted_events() {
    let db_path = temp_file("warder-cli-network-journal-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    db.insert_network_journal_event(&warder_journal::NetworkJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
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
    .unwrap();

    let journal = render_network_journal_from_db(Some(db_path), Some("session-1")).unwrap();

    assert!(journal.contains("network journal: 1 event(s)"));
    assert!(journal.contains("203.0.113.10:443"));
    assert!(journal.contains("tcp observed"));
    assert!(journal.contains("attribution=direct-process"));
}

#[test]
fn render_journal_from_db_rejects_missing_session_filter() {
    let db_path = temp_file("warder-cli-missing-journal-session-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();

    let error = render_file_journal_from_db(Some(db_path), Some("missing-session")).unwrap_err();

    assert_eq!(error.message, "session 'missing-session' was not found");
}

#[test]
fn render_all_journals_from_db_reads_file_and_network_events() {
    let db_path = temp_file("warder-cli-all-journals-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    db.insert_file_journal_event(&warder_journal::FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
        process_id: Some(123),
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/tmp/notes/todo.md"),
        operation: warder_journal::FileOperation::Write,
        decision: warder_journal::FileDecision::Denied,
        source: warder_journal::JournalSource::Landlock,
        confidence: warder_journal::JournalConfidence::Enforced,
        attribution: warder_journal::JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    })
    .unwrap();
    db.insert_network_journal_event(&warder_journal::NetworkJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: fixed_time(),
        process_id: Some(123),
        destination: "203.0.113.10".to_string(),
        destination_port: Some(443),
        protocol: warder_journal::NetworkProtocol::Tcp,
        decision: warder_journal::NetworkDecision::Observed,
        source: warder_journal::JournalSource::Ebpf,
        confidence: warder_journal::JournalConfidence::Observed,
        attribution: warder_journal::JournalAttribution::DirectProcess,
        message: "network egress observed by eBPF".to_string(),
    })
    .unwrap();

    let journal = render_all_journals_from_db(Some(db_path), Some("session-1")).unwrap();

    assert!(journal.contains("file journal: 1 event(s)"));
    assert!(journal.contains("/tmp/notes/todo.md"));
    assert!(journal.contains("network journal: 1 event(s)"));
    assert!(journal.contains("203.0.113.10:443"));
}

#[test]
fn render_policy_explain_from_config_summarizes_policy_and_degraded_support() {
    let config_path = temp_file("warder-cli-explain-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("best-effort", "best-effort"),
    )
    .unwrap();
    let environment = EnvironmentSupport {
        landlock: false,
        cgroups: true,
        ebpf: false,
        snapshot_backends: Vec::new(),
    };

    let explanation = render_policy_explain_from_config(Some(config_path), &environment).unwrap();

    assert!(explanation.contains("policy explanation"));
    assert!(explanation.contains("protected zones: 1"));
    assert!(explanation.contains("agent: local"));
    assert!(explanation.contains("Landlock unavailable"));
    assert!(explanation.contains("snapshot backend unavailable"));
    assert!(explanation.contains("network journal: degraded"));
    assert!(explanation
        .contains("cgroup tagging: required (--cgroup-root must be provided for launch)"));
}

#[test]
fn render_policy_explain_from_config_loads_yaml_config() {
    let config_path = temp_file("warder-cli-explain-config", "yaml");
    std::fs::write(
        &config_path,
        r#"
enforcement:
  landlock: disabled
  cgroups: disabled
network:
  journal: false
zones:
  - id: notes
    name: Notes
    paths:
      - /tmp/warder-notes
    write-policy: deny
    snapshot: disabled
agents:
  - id: local
    label: Local Agent
    command: agent-command
"#,
    )
    .unwrap();
    let environment = supported_environment();

    let explanation = render_policy_explain_from_config(Some(config_path), &environment).unwrap();

    assert!(explanation.contains("policy explanation"));
    assert!(explanation.contains("agent: local"));
    assert!(explanation.contains("zone: notes"));
    assert!(explanation.contains("validation: ok"));
}

#[test]
fn render_policy_explain_from_config_loads_yml_config() {
    let config_path = temp_file("warder-cli-explain-config", "yml");
    std::fs::write(
        &config_path,
        r#"
enforcement:
  landlock: disabled
  cgroups: disabled
network:
  journal: false
zones:
  - id: notes
    name: Notes
    paths:
      - /tmp/warder-notes
    snapshot: disabled
agents:
  - id: local
    label: Local Agent
    command: agent-command
"#,
    )
    .unwrap();

    let explanation =
        render_policy_explain_from_config(Some(config_path), &supported_environment()).unwrap();

    assert!(explanation.contains("agent: local"));
    assert!(explanation.contains("zone: notes"));
    assert!(explanation.contains("validation: ok"));
}

#[test]
fn render_policy_explain_reports_network_journal_degraded_until_ebpf_attach_is_wired() {
    let config_path = temp_file("warder-cli-explain-ebpf-attach-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let environment = EnvironmentSupport {
        landlock: true,
        cgroups: true,
        ebpf: true,
        snapshot_backends: Vec::new(),
    };

    let explanation = render_policy_explain_from_config(Some(config_path), &environment).unwrap();

    assert!(explanation.contains(
            "network journal: degraded: eBPF network journaling unavailable: live attach is not implemented yet"
        ));
    assert!(explanation.contains(
        "warning: eBPF network journaling unavailable: live attach is not implemented yet"
    ));
    assert!(!explanation.contains("validation: ok"));
}

#[test]
fn render_policy_explain_warns_allowed_destinations_are_not_enforced() {
    let config_path = temp_file("warder-cli-explain-network-allowlist-config", "toml");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "disabled"

                [network]
                journal = false
                allowed-destinations = ["example.com:443"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/warder-notes"]
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();

    let explanation =
        render_policy_explain_from_config(Some(config_path), &supported_environment()).unwrap();

    assert!(explanation.contains("network.allowed_destinations is configured"));
    assert!(explanation.contains("does not enforce destination allowlists yet"));
    assert!(!explanation.contains("validation: ok"));
}

#[test]
fn dry_run_warns_allowed_destinations_are_not_enforced() {
    let config_path = temp_file("warder-cli-dry-run-network-allowlist-config", "toml");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "disabled"

                [network]
                journal = false
                allowed-destinations = ["example.com:443"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/warder-notes"]
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
    )
    .unwrap();

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "local",
        &["sh".to_string(), "-c".to_string(), "true".to_string()],
        &supported_environment(),
    )
    .unwrap();

    assert!(dry_run.contains("network.allowed_destinations is configured"));
    assert!(dry_run.contains("observation-only"));
}

#[test]
fn render_agent_profile_summary_explains_known_profile() {
    let summary = render_agent_profile_summary(Some("codex-cli"), "codex");

    assert!(summary.contains("profile: codex-cli"));
    assert!(summary.contains("known local CLI agent"));
    assert!(summary.contains("transparent preset"));
    assert!(summary.contains("declared command: codex"));
    assert!(summary.contains("profile preflight:"));
    assert!(summary.contains("Codex workspace and approval settings"));
}

#[test]
fn render_agent_profile_catalog_lists_transparent_presets() {
    let catalog = render_agent_profile_catalog();

    assert!(catalog.contains("transparent profiles"));
    assert!(catalog.contains("profile: codex-cli"));
    assert!(catalog.contains("profile: claude-code"));
    assert!(catalog.contains("profile: goose-cli"));
    assert!(catalog.contains("profile: openclaw-cli"));
    assert!(catalog.contains("profile: openclaw-gateway"));
    assert!(catalog.contains("profile: openclaw-agent"));
    assert!(catalog.contains("profile: local-script"));
    assert!(catalog.contains("profile: generic-cli"));
    assert!(catalog.contains("profile effect: transparent preset only"));
    assert!(catalog.contains("Codex workspace and approval settings"));
    assert!(catalog.contains("Goose extension and tool permissions"));
    assert!(catalog.contains("OpenClaw security audit"));
    assert!(catalog.contains("- OpenClaw state: $HOME/.openclaw read=true write=false"));
    assert!(catalog.contains("template network journal: enabled"));
    assert!(catalog.contains("template snapshot: best-effort"));
    assert!(catalog.contains("template protected paths:"));
    assert!(catalog.contains("- SSH keys: $HOME/.ssh read=true write=true"));
    assert!(catalog.contains("- NPM token: $HOME/.npmrc read=true write=true"));
    assert!(catalog.contains("- Password store: $HOME/.password-store read=true write=true"));
    assert!(catalog.contains("- Firefox profiles: $HOME/.mozilla/firefox read=true write=true"));
    assert!(catalog.contains("template writable roots: $PWD"));
}

#[test]
fn render_agent_profile_catalog_json_is_structured() {
    let catalog = render_agent_profile_catalog_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&catalog).unwrap();
    let profiles = value["profiles"].as_array().unwrap();

    assert_eq!(profiles[0]["id"], "codex-cli");
    assert_eq!(profiles[0]["declared_command"], "codex");
    assert_eq!(
        profiles[0]["effect"],
        "transparent preset only; policy still comes from config and host support"
    );
    assert!(profiles.iter().any(|profile| {
        profile["id"] == "goose-cli"
            && profile["preflight"]
                .as_str()
                .unwrap()
                .contains("Goose extension")
    }));
    assert!(profiles.iter().any(|profile| {
        profile["id"] == "openclaw-agent"
            && profile["declared_command"] == "openclaw agent"
            && profile["template"]["network_journal"] == true
    }));
}

#[test]
fn render_agent_profile_catalog_json_includes_setup_templates() {
    let catalog = render_agent_profile_catalog_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&catalog).unwrap();
    let profiles = value["profiles"].as_array().unwrap();
    let codex = profiles
        .iter()
        .find(|profile| profile["id"] == "codex-cli")
        .unwrap();

    assert_eq!(codex["template"]["network_journal"], true);
    assert_eq!(codex["template"]["snapshot"], "best-effort");
    assert!(codex["template"]["recommended_protected_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path["path"] == "$HOME/.ssh" && path["read"] == true && path["write"] == true));
    assert!(codex["template"]["recommended_protected_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path["path"] == "$HOME/.npmrc"
            && path["read"] == true
            && path["write"] == true));
    assert!(codex["template"]["writable_roots"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path == "$PWD"));
}

#[test]
fn secret_zone_suggestions_warn_for_existing_uncovered_profile_paths() {
    let home = PathBuf::from("/tmp/warder-home");
    let config = WarderConfig::from_toml(
        r#"
            [enforcement]
            landlock = "disabled"
            cgroups = "disabled"

            [[zones]]
            id = "ssh"
            name = "SSH"
            paths = ["/tmp/warder-home/.ssh"]
            snapshot = "disabled"

            [[agents]]
            id = "codex"
            label = "Codex"
            command = "codex"
            profile = "codex-cli"
        "#,
    )
    .unwrap();

    let suggestions = secret_zone_suggestions(&config, Some(&home), |path| {
        matches!(
            path.to_str().unwrap(),
            "/tmp/warder-home/.ssh" | "/tmp/warder-home/.npmrc" | "/tmp/warder-home/.config/gh"
        )
    });

    assert!(!suggestions
        .iter()
        .any(|diagnostic| diagnostic.message.contains("SSH keys")));
    assert!(suggestions
        .iter()
        .any(|diagnostic| diagnostic.message.contains("NPM token")));
    assert!(suggestions
        .iter()
        .any(|diagnostic| diagnostic.message.contains("GitHub CLI credentials")));
}

#[test]
fn render_agent_profile_summary_explains_claude_preflight() {
    let summary = render_agent_profile_summary(Some("claude-code"), "claude");

    assert!(summary.contains("profile: claude-code"));
    assert!(summary.contains("profile preflight:"));
    assert!(summary.contains("Claude Code tool permissions"));
}

#[test]
fn render_agent_profile_summary_explains_goose_preflight() {
    let summary = render_agent_profile_summary(Some("goose-cli"), "goose");

    assert!(summary.contains("profile: goose-cli"));
    assert!(summary.contains("known local CLI agent"));
    assert!(summary.contains("Goose extension and tool permissions"));
}

#[test]
fn render_agent_profile_summary_falls_back_for_unknown_profile() {
    let summary = render_agent_profile_summary(Some("custom-agent"), "custom-agent");

    assert!(summary.contains("profile: custom-agent"));
    assert!(summary.contains("unknown profile"));
    assert!(summary.contains("generic CLI handling"));
}

#[test]
fn effective_agent_profile_prefers_explicit_config_over_command_inference() {
    assert_eq!(
        effective_agent_profile(Some("local-script"), "/usr/bin/codex").as_deref(),
        Some("local-script")
    );
}

#[test]
fn effective_agent_profile_infers_from_declared_command_basename() {
    assert_eq!(
        effective_agent_profile(None, "/usr/local/bin/claude").as_deref(),
        Some("claude-code")
    );
    assert_eq!(
        effective_agent_profile(None, "/home/alex/go/bin/goose").as_deref(),
        Some("goose-cli")
    );
    assert_eq!(
        effective_agent_profile(None, "/usr/local/bin/openclaw").as_deref(),
        Some("openclaw-cli")
    );
}

#[test]
fn effective_agent_profile_infers_openclaw_subcommands_from_run_command() {
    assert_eq!(
        effective_agent_profile_for_run(
            None,
            "openclaw",
            &["openclaw".to_string(), "gateway".to_string()]
        )
        .as_deref(),
        Some("openclaw-gateway")
    );
    assert_eq!(
        effective_agent_profile_for_run(
            None,
            "openclaw",
            &[
                "openclaw".to_string(),
                "agent".to_string(),
                "--message".to_string(),
                "hello".to_string()
            ]
        )
        .as_deref(),
        Some("openclaw-agent")
    );
    assert_eq!(
        effective_agent_profile_for_run(
            None,
            "openclaw",
            &[
                "openclaw".to_string(),
                "message".to_string(),
                "send".to_string()
            ]
        )
        .as_deref(),
        Some("openclaw-cli")
    );
}

#[test]
fn render_dry_run_from_config_summarizes_command_and_policy_without_launching() {
    let config_path = temp_file("warder-cli-dry-run-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("best-effort", "best-effort"),
    )
    .unwrap();
    let environment = EnvironmentSupport {
        landlock: false,
        cgroups: true,
        ebpf: false,
        snapshot_backends: Vec::new(),
    };

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "local",
        &["sh".to_string(), "-c".to_string(), "true".to_string()],
        &environment,
    )
    .unwrap();

    assert!(dry_run.contains("dry run"));
    assert!(dry_run.contains("agent: local"));
    assert!(dry_run.contains("command: sh -c true"));
    assert!(dry_run.contains("launch: no command was run"));
    assert!(dry_run.contains("host readiness: blocked"));
    assert!(dry_run.contains("policy explanation"));
    assert!(dry_run.contains("Landlock unavailable"));
    assert!(dry_run.contains("snapshot backend unavailable"));
    assert!(dry_run.contains("network journal: degraded"));
    assert!(
        dry_run.contains("cgroup tagging: required (--cgroup-root must be provided for launch)")
    );
}

#[test]
fn render_pre_launch_readiness_uses_shared_labels() {
    let readiness = render_pre_launch_readiness(&EnvironmentSupport {
        landlock: true,
        cgroups: true,
        ebpf: false,
        snapshot_backends: Vec::new(),
    });

    assert!(readiness.contains("host readiness: degraded"));
    assert!(readiness.contains("Btrfs snapshots unavailable"));
    assert!(readiness.contains("live eBPF journals unavailable"));
}

#[test]
fn render_dry_run_quotes_command_arguments_with_spaces() {
    let config_path = temp_file("warder-cli-dry-run-spaced-command-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();
    let environment = EnvironmentSupport {
        landlock: true,
        cgroups: true,
        ebpf: false,
        snapshot_backends: Vec::new(),
    };

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "local",
        &[
            "sh".to_string(),
            "-c".to_string(),
            "echo hello > /tmp/warder out.txt".to_string(),
        ],
        &environment,
    )
    .unwrap();

    assert!(dry_run.contains("command: sh -c 'echo hello > /tmp/warder out.txt'"));
}

#[test]
fn render_dry_run_from_config_includes_declared_agent_profile() {
    let config_path = temp_file("warder-cli-dry-run-profile-config", "toml");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "required"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                snapshot = "disabled"

                [[agents]]
                id = "codex"
                label = "Codex CLI"
                command = "codex"
                profile = "codex-cli"
            "#,
    )
    .unwrap();

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "codex",
        &[
            "codex".to_string(),
            "--dangerously-bypass-approvals-and-sandbox".to_string(),
        ],
        &supported_environment(),
    )
    .unwrap();

    assert!(dry_run.contains("profile: codex-cli"));
    assert!(dry_run.contains("declared command: codex"));
    assert!(dry_run.contains("transparent preset only"));
}

#[test]
fn render_dry_run_from_config_infers_known_agent_profile() {
    let config_path = temp_file("warder-cli-dry-run-inferred-profile-config", "toml");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "required"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                snapshot = "disabled"

                [[agents]]
                id = "codex"
                label = "Codex CLI"
                command = "codex"
            "#,
    )
    .unwrap();

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "codex",
        &["codex".to_string()],
        &supported_environment(),
    )
    .unwrap();

    assert!(dry_run.contains("profile: codex-cli"));
    assert!(dry_run.contains("known local CLI agent"));
}

#[test]
fn render_dry_run_from_config_infers_openclaw_and_reports_preflight() {
    let config_path = temp_file("warder-cli-dry-run-openclaw-profile-config", "toml");
    std::fs::write(
        &config_path,
        r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "disabled"

                [network]
                journal = false

                [[zones]]
                id = "workspace"
                name = "Workspace"
                paths = ["/tmp/workspace"]
                snapshot = "disabled"

                [[agents]]
                id = "openclaw"
                label = "OpenClaw"
                command = "openclaw"
            "#,
    )
    .unwrap();

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "openclaw",
        &[
            "openclaw".to_string(),
            "agent".to_string(),
            "--message".to_string(),
            "hi".to_string(),
        ],
        &supported_environment(),
    )
    .unwrap();

    assert!(dry_run.contains("profile: openclaw-agent"));
    assert!(dry_run.contains("OpenClaw agent run"));
    assert!(dry_run.contains("openclaw preflight:"));
    assert!(dry_run.contains("security audit:"));
    assert!(dry_run.contains("sandbox explain:"));
}

#[test]
fn render_starter_config_supports_openclaw_agent_profile() {
    let config = render_starter_config(
        "openclaw-agent",
        &[PathBuf::from("/tmp/warder-openclaw-workspace")],
        Some("openclaw"),
    )
    .unwrap();

    assert!(config.contains("id = \"openclaw-agent\""));
    assert!(config.contains("command = \"openclaw\""));
    assert!(config.contains("profile = \"openclaw-agent\""));
}

#[test]
fn openclaw_audit_warnings_maps_high_risk_checks() {
    let value: serde_json::Value = serde_json::json!({
        "findings": [
            {"checkId": "gateway.bind_no_auth", "severity": "critical"},
            {"checkId": "sandbox.dangerous_bind_mount", "severity": "critical"},
            {"checkId": "models.legacy", "severity": "warn"}
        ]
    });

    let warnings = openclaw_audit_warnings(&value);

    assert!(warnings
        .iter()
        .any(|warning| warning.contains("Gateway auth or bind exposure")));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("sandbox configuration weakens isolation")));
    assert!(!warnings
        .iter()
        .any(|warning| warning.contains("models.legacy")));
}

#[test]
fn openclaw_sandbox_warnings_mark_remote_or_containerized_coverage_degraded() {
    let value: serde_json::Value = serde_json::json!({
        "sandbox": {
            "mode": "all",
            "backend": "docker",
            "scope": "session",
            "docker": {
                "network": "host",
                "binds": ["/var/run/docker.sock:/var/run/docker.sock"]
            }
        }
    });

    let status = openclaw_sandbox_status(&value);
    let warnings = openclaw_sandbox_warnings("openclaw-agent", &value);

    assert_eq!(status, "parsed: mode=all, backend=docker, scope=session");
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("Warder coverage inside that sandbox is degraded")));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("Docker socket")));
    assert!(warnings
        .iter()
        .any(|warning| warning.contains("host network mode")));
}

#[test]
fn openclaw_sandbox_status_matches_current_explain_shape_without_backend() {
    let value: serde_json::Value = serde_json::json!({
        "sandbox": {
            "mode": "all",
            "scope": "agent",
            "workspaceAccess": "none",
            "sessionIsSandboxed": true,
            "tools": {
                "allow": [],
                "deny": [],
                "sources": []
            }
        },
        "elevated": {
            "enabled": false
        }
    });

    let status = openclaw_sandbox_status(&value);
    let warnings = openclaw_sandbox_warnings("openclaw-agent", &value);

    assert_eq!(status, "parsed: mode=all, scope=agent");
    assert!(warnings.is_empty());
}

#[test]
fn demo_config_supports_cli_first_dry_run() {
    let config_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/prototype/local-demo.toml");

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "local-shell",
        &["sh".to_string(), "-c".to_string(), "true".to_string()],
        &EnvironmentSupport {
            landlock: false,
            cgroups: true,
            ebpf: false,
            snapshot_backends: Vec::new(),
        },
    )
    .unwrap();

    assert!(dry_run.contains("agent: local-shell"));
    assert!(dry_run.contains("profile: local-script"));
    assert!(dry_run.contains("snapshot: not requested"));
    assert!(dry_run.contains("launch: no command was run"));
}

#[test]
fn quickstart_yaml_config_supports_cli_first_dry_run() {
    let config_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/prototype/quickstart.yaml");

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "local-shell",
        &["sh".to_string(), "-c".to_string(), "true".to_string()],
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: false,
            snapshot_backends: Vec::new(),
        },
    )
    .unwrap();

    assert!(dry_run.contains("agent: local-shell"));
    assert!(dry_run.contains("profile: local-script"));
    assert!(dry_run.contains("network journal: disabled"));
    assert!(dry_run.contains("snapshot: not requested"));
}

#[test]
fn landlock_demo_config_preflights_required_write_denial() {
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/prototype/landlock-demo.toml");

    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "local-shell",
        &["sh".to_string(), "-c".to_string(), "true".to_string()],
        &supported_environment(),
    )
    .unwrap();

    assert!(dry_run.contains("agent: local-shell"));
    assert!(dry_run.contains("landlock: will apply"));
    assert!(dry_run.contains("snapshot: not requested"));
    assert!(dry_run.contains("launch: no command was run"));
}

#[test]
fn quickstart_demo_config_allows_no_cgroup_root_launch_with_degraded_tagging() {
    let config_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/prototype/quickstart.toml");
    let db_path = temp_file("warder-cli-quickstart-demo-db", "sqlite3");
    let protected_root = PathBuf::from("/tmp/warder-quickstart/protected");
    let _ = std::fs::remove_dir_all("/tmp/warder-quickstart");
    std::fs::create_dir_all(&protected_root).unwrap();
    let command = CliCommand::Run {
        config: Some(config_path.clone()),
        db: Some(db_path.clone()),
        cgroup_root: None,
        snapshot_root: None,
        launch: true,
        require_enforcement: false,
        receipt_key: None,
        accept_degraded: true,

        agent: "local-shell".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "printf hello > {}",
                protected_root.join("hello.txt").display()
            ),
        ],
    };
    let dry_run = render_dry_run_from_config(
        Some(config_path),
        "local-shell",
        &[
            "sh".to_string(),
            "-c".to_string(),
            format!(
                "printf hello > {}",
                protected_root.join("hello.txt").display()
            ),
        ],
        &EnvironmentSupport {
            landlock: false,
            cgroups: true,
            ebpf: false,
            snapshot_backends: Vec::new(),
        },
    )
    .unwrap();

    assert!(dry_run.contains("network journal: disabled"));
    assert!(
        dry_run.contains("cgroup tagging: best-effort (--cgroup-root enables tagging at launch)")
    );

    let outcome = launch_supervised_run(&command, &supported_environment(), fixed_time()).unwrap();

    assert_eq!(outcome.exit_code, Some(0));
    assert!(outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("--cgroup-root")));
    assert!(!outcome
        .validation_warnings
        .iter()
        .any(|warning| warning.contains("eBPF")));
    let receipt = render_session_receipt_from_db(Some(db_path), &outcome.session_id).unwrap();
    assert!(receipt.contains("status: completed"));
    assert!(receipt.contains("cgroup: degraded: cgroup tagging skipped"));
}

#[test]
fn render_daemon_status_from_runtime_reads_runtime_file() {
    let runtime_path = temp_file("warder-cli-daemon-runtime", "state");
    let store = warder_daemon::DaemonRuntimeFile::new(&runtime_path);
    let pid = std::process::id();
    store
        .write_status(&warder_daemon::DaemonRuntimeReport {
            status: warder_daemon::DaemonRuntimeStatus::Running,
            pid: Some(pid),
            socket_path: Some(PathBuf::from("/run/user/1000/warder.sock")),
            message: format!("daemon running with pid {pid}"),
        })
        .unwrap();

    let status = render_daemon_status_from_runtime(Some(runtime_path)).unwrap();

    assert!(status.contains("daemon: running"));
    assert!(status.contains(&format!("pid: {pid}")));
}

#[test]
fn start_daemon_runtime_with_launcher_writes_verified_runtime_state() {
    let runtime_path = temp_file("warder-cli-daemon-start-launcher-runtime", "state");
    let pid = std::process::id();
    let launcher = FakeDaemonLauncher {
        pid,
        alive: true,
        runtime_path: Some(runtime_path.clone()),
    };

    let status = start_daemon_runtime_with_launcher(Some(runtime_path.clone()), &launcher).unwrap();

    assert!(status.contains("daemon: running"));
    assert!(status.contains(&format!("pid: {pid}")));
    let loaded = warder_daemon::DaemonRuntimeFile::new(runtime_path)
        .read_status()
        .unwrap();
    assert_eq!(loaded.pid, Some(pid));
}

#[test]
fn start_daemon_runtime_with_launcher_refuses_unverified_process() {
    let runtime_path = temp_file("warder-cli-daemon-start-unverified-runtime", "state");
    let launcher = FakeDaemonLauncher {
        pid: 4242,
        alive: false,
        runtime_path: None,
    };

    let error =
        start_daemon_runtime_with_launcher(Some(runtime_path.clone()), &launcher).unwrap_err();

    assert!(error.message.contains("failed to verify"));
    assert!(!runtime_path.exists());
}

#[test]
fn start_daemon_runtime_with_config_rejects_invalid_config_before_launch() {
    let runtime_path = temp_file("warder-cli-daemon-start-invalid-config-runtime", "state");
    let config_path = temp_file("warder-cli-daemon-start-invalid-config", "toml");
    std::fs::write(&config_path, "").unwrap();
    let launcher = FakeDaemonLauncher {
        pid: 4242,
        alive: true,
        runtime_path: Some(runtime_path.clone()),
    };

    let error = start_daemon_runtime_with_launcher_and_config(
        Some(runtime_path.clone()),
        Some(config_path),
        &launcher,
    )
    .unwrap_err();

    assert!(error.message.contains("config validation failed"));
    assert!(!runtime_path.exists());
}

#[test]
fn daemon_start_config_validation_returns_degraded_warnings() {
    let config_path = temp_file("warder-cli-daemon-start-warning-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("best-effort", "disabled"),
    )
    .unwrap();

    let warnings = validate_daemon_start_config_with_environment(
        Some(&config_path),
        &EnvironmentSupport {
            landlock: false,
            cgroups: true,
            ebpf: false,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
    )
    .unwrap();

    assert!(warnings.iter().any(|warning| warning.contains("Landlock")));
    assert!(warnings.iter().any(|warning| warning.contains("eBPF")));
}

#[test]
fn daemon_start_config_validation_reports_unwired_ebpf_attach() {
    let config_path = temp_file("warder-cli-daemon-start-ebpf-attach-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "disabled"),
    )
    .unwrap();

    let warnings = validate_daemon_start_config_with_environment(
        Some(&config_path),
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
        },
    )
    .unwrap();

    assert!(warnings
        .iter()
        .any(|warning| warning.contains("live attach is not implemented yet")));
}

#[test]
fn daemon_start_config_validation_rejects_required_overlayfs_snapshot_driver() {
    let config_path = temp_file("warder-cli-daemon-start-overlay-required-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "required"),
    )
    .unwrap();

    let error = validate_daemon_start_config_with_environment(
        Some(&config_path),
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::OverlayFs],
        },
    )
    .unwrap_err();

    assert!(error.message.contains(
        "snapshot required, but overlayfs snapshot backend driver is not implemented yet"
    ));
}

#[test]
fn daemon_start_config_validation_warns_on_best_effort_overlayfs_snapshot_driver() {
    let config_path = temp_file("warder-cli-daemon-start-overlay-best-effort-config", "toml");
    std::fs::write(
        &config_path,
        valid_config_with_landlock("disabled", "best-effort"),
    )
    .unwrap();

    let warnings = validate_daemon_start_config_with_environment(
        Some(&config_path),
        &EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![ConfigSnapshotBackend::OverlayFs],
        },
    )
    .unwrap();

    assert!(warnings.iter().any(|warning| {
        warning.contains("overlayfs snapshot backend driver is not implemented yet")
    }));
}

#[test]
fn command_daemon_launcher_reports_spawn_failure() {
    let launcher = CommandDaemonLauncher {
        executable: PathBuf::from("/definitely/missing/warder-daemon"),
        runtime_path: PathBuf::from("/run/user/1000/warder.state"),
        socket_path: PathBuf::from("/run/user/1000/warder.sock"),
        config_path: None,
    };

    let error = launcher.launch().unwrap_err();

    assert!(error.message.contains("failed to launch daemon"));
}

#[test]
fn stop_daemon_runtime_clears_stale_runtime_file() {
    let runtime_path = temp_file("warder-cli-daemon-stop-runtime", "state");
    let store = warder_daemon::DaemonRuntimeFile::new(&runtime_path);
    store
        .write_status(&warder_daemon::DaemonRuntimeReport {
            status: warder_daemon::DaemonRuntimeStatus::Stopped,
            pid: None,
            socket_path: None,
            message: "stale stopped runtime state".to_string(),
        })
        .unwrap();

    let stopped = stop_daemon_runtime(Some(runtime_path.clone())).unwrap();

    assert!(stopped.contains("daemon: stopped"));
    assert!(!runtime_path.exists());
}

#[test]
fn stop_daemon_runtime_with_terminator_terminates_recorded_pid_before_clear() {
    let runtime_path = temp_file("warder-cli-daemon-stop-terminator-runtime", "state");
    let pid = std::process::id();
    warder_daemon::DaemonRuntimeFile::new(&runtime_path)
        .write_status(&warder_daemon::DaemonRuntimeReport {
            status: warder_daemon::DaemonRuntimeStatus::Running,
            pid: Some(pid),
            socket_path: Some(PathBuf::from("/tmp/warder.sock")),
            message: format!("daemon running with pid {pid}"),
        })
        .unwrap();
    let terminator = RecordingTerminator::default();

    let stopped =
        stop_daemon_runtime_with_terminator(Some(runtime_path.clone()), &terminator).unwrap();

    assert_eq!(terminator.terminated_pids(), vec![pid]);
    assert!(stopped.contains(&format!("daemon pid {pid} terminated")));
    assert!(!runtime_path.exists());
}

#[test]
fn parses_internal_daemon_run_command_separately_from_public_args() {
    assert!(is_internal_daemon_run_command([
        "warder",
        "__warder-daemon-run"
    ]));
    assert!(!is_internal_daemon_run_command(["warder", "start"]));
}

#[test]
fn parses_internal_daemon_run_options() {
    let options = parse_internal_daemon_run_options([
        "warder",
        "__warder-daemon-run",
        "--runtime",
        "/tmp/warder.state",
        "--socket",
        "/tmp/warder.sock",
    ])
    .unwrap();

    assert_eq!(options.runtime_path, PathBuf::from("/tmp/warder.state"));
    assert_eq!(options.socket_path, PathBuf::from("/tmp/warder.sock"));
    assert_eq!(options.config_path, None);
}

#[test]
fn command_daemon_launcher_passes_internal_runtime_arguments() {
    let args = internal_daemon_run_args(
        &PathBuf::from("/tmp/warder.state"),
        &PathBuf::from("/tmp/warder.sock"),
        Some(&PathBuf::from("/tmp/warder.toml")),
    );

    assert_eq!(
        args,
        vec![
            "__warder-daemon-run",
            "--runtime",
            "/tmp/warder.state",
            "--socket",
            "/tmp/warder.sock",
            "--config",
            "/tmp/warder.toml"
        ]
    );
}

#[test]
fn internal_daemon_run_writes_own_runtime_state() {
    let runtime_path = temp_file("warder-cli-internal-daemon-runtime", "state");
    let options = InternalDaemonRunOptions {
        runtime_path: runtime_path.clone(),
        socket_path: PathBuf::from("/tmp/warder.sock"),
        config_path: None,
    };

    let pid = std::process::id();
    let report = write_internal_daemon_runtime_state(&options, pid).unwrap();

    assert_eq!(report.pid, Some(pid));
    let loaded = warder_daemon::DaemonRuntimeFile::new(runtime_path)
        .read_status()
        .unwrap();
    assert_eq!(loaded.status, warder_daemon::DaemonRuntimeStatus::Running);
    assert_eq!(loaded.pid, Some(pid));
    assert_eq!(loaded.socket_path, Some(PathBuf::from("/tmp/warder.sock")));
}

#[test]
fn internal_daemon_run_starts_coordinator_with_runtime_identity() {
    let runtime_path = temp_file("warder-cli-internal-daemon-coordinator", "state");
    let config_path = temp_file("warder-cli-internal-daemon-config", "toml");
    std::fs::write(&config_path, valid_config("disabled")).unwrap();
    let options = InternalDaemonRunOptions {
        runtime_path: runtime_path.clone(),
        socket_path: PathBuf::from("/tmp/warder.sock"),
        config_path: Some(config_path),
    };

    let pid = std::process::id();
    let mut coordinator = start_internal_daemon_coordinator(&options, pid).unwrap();
    let tick = coordinator.tick(warder_daemon::CapabilityProbe {
        landlock: warder_daemon::CapabilityState::Available,
        cgroups: warder_daemon::CapabilityState::Available,
        btrfs: warder_daemon::CapabilityState::Unavailable("not btrfs".to_string()),
        overlayfs: warder_daemon::CapabilityState::Unavailable("not overlayfs".to_string()),
        ebpf: warder_daemon::CapabilityState::Available,
    });

    assert_eq!(tick.tick_count, 1);
    let loaded = warder_daemon::DaemonRuntimeFile::new(runtime_path)
        .read_status()
        .unwrap();
    assert_eq!(loaded.pid, Some(pid));
    assert!(loaded.message.contains("1 protected zone"));
}

#[test]
fn persist_ebpf_file_journal_events_stores_collector_events() {
    let db_path = temp_file("warder-cli-ebpf-journal-db", "sqlite3");
    let mut collector = warder_journal::EbpfFileJournalCollector::new(
        FakeEbpfReader {
            events: vec![warder_journal::EbpfFileAccessEvent {
                process_id: Some(4242),
                cgroup_id: None,
                path: PathBuf::from("/tmp/notes/todo.md"),
                operation: warder_journal::FileOperation::Write,
                denied: true,
                timestamp: fixed_time(),
            }],
        },
        vec![warder_journal::ProtectedJournalZone {
            id: "notes".to_string(),
            root_paths: vec![PathBuf::from("/tmp/notes")],
        }],
    );

    persist_ebpf_file_journal_events(&db_path, "session-1", Some(&mut collector)).unwrap();

    let db = WarderDb::open(db_path).unwrap();
    db.migrate().unwrap();
    let events = db.list_file_journal_events(Some("session-1")).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].source, warder_journal::JournalSource::Ebpf);
    assert_eq!(events[0].decision, warder_journal::FileDecision::Denied);
}

#[test]
fn wait_for_child_polls_ebpf_file_journal_collector() {
    let db_path = temp_file("warder-cli-ebpf-wait-journal-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    let mut child = std::process::Command::new("sh")
        .args(["-c", "sleep 0.05"])
        .spawn()
        .unwrap();
    let mut collector = warder_journal::EbpfFileJournalCollector::new(
        FakeEbpfReader {
            events: vec![warder_journal::EbpfFileAccessEvent {
                process_id: Some(4242),
                cgroup_id: None,
                path: PathBuf::from("/tmp/notes/live.md"),
                operation: warder_journal::FileOperation::Read,
                denied: false,
                timestamp: fixed_time(),
            }],
        },
        vec![warder_journal::ProtectedJournalZone {
            id: "notes".to_string(),
            root_paths: vec![PathBuf::from("/tmp/notes")],
        }],
    );

    wait_for_child_with_file_journals(
        &db_path,
        "session-1",
        &mut child,
        None,
        Some(&mut collector),
        None::<
            &mut warder_journal::EbpfNetworkJournalCollector<
                warder_journal::RawEbpfNetworkEgressReader<std::io::Cursor<Vec<u8>>>,
            >,
        >,
        None,
    )
    .unwrap();

    let events = db.list_file_journal_events(Some("session-1")).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].source, warder_journal::JournalSource::Ebpf);
    assert_eq!(events[0].path, PathBuf::from("/tmp/notes/live.md"));
}

#[cfg(target_os = "linux")]
#[test]
fn persist_procfs_network_journal_events_records_connected_socket_snapshot() {
    let db_path = temp_file("warder-cli-procfs-network-journal-db", "sqlite3");
    let db = WarderDb::open(&db_path).unwrap();
    db.migrate().unwrap();
    db.create_session(&receipt_test_session()).unwrap();
    let proc_root = temp_dir("warder-cli-procfs-network");
    let pid = 4242_u32;
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let net_dir = proc_root.join(pid.to_string()).join("net");
    std::fs::create_dir_all(&fd_dir).unwrap();
    std::fs::create_dir_all(&net_dir).unwrap();
    std::os::unix::fs::symlink("socket:[12345]", fd_dir.join("3")).unwrap();
    std::fs::write(
        net_dir.join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B2 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000\n",
    )
    .unwrap();

    let mut reader =
        warder_journal::ProcfsNetworkSocketReader::with_proc_root(proc_root.clone(), pid);
    persist_procfs_network_journal_events(&db_path, "session-1", Some(&mut reader)).unwrap();
    persist_procfs_network_journal_events(&db_path, "session-1", Some(&mut reader)).unwrap();

    let events = db.list_network_journal_events(Some("session-1")).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].source, warder_journal::JournalSource::Procfs);
    assert_eq!(events[0].destination, "ipv4:7f000001");
    assert_eq!(events[0].destination_port, Some(443));
    assert!(events[0].message.contains("inode=12345"));

    let _ = std::fs::remove_dir_all(proc_root);
}

#[derive(Debug)]
struct FakeEbpfReader {
    events: Vec<warder_journal::EbpfFileAccessEvent>,
}

#[derive(Debug)]
struct FakeDaemonLauncher {
    pid: u32,
    alive: bool,
    runtime_path: Option<PathBuf>,
}

#[derive(Debug, Default)]
struct RecordingTerminator {
    pids: std::sync::Mutex<Vec<u32>>,
}

impl RecordingTerminator {
    fn terminated_pids(&self) -> Vec<u32> {
        self.pids.lock().unwrap().clone()
    }
}

impl DaemonTerminator for RecordingTerminator {
    fn terminate(&self, pid: u32) -> Result<(), CliError> {
        self.pids.lock().unwrap().push(pid);
        Ok(())
    }
}

impl DaemonLauncher for FakeDaemonLauncher {
    fn launch(&self) -> Result<LaunchedDaemon, CliError> {
        if let Some(runtime_path) = &self.runtime_path {
            warder_daemon::DaemonRuntimeFile::new(runtime_path)
                .write_status(&warder_daemon::DaemonRuntimeReport {
                    status: warder_daemon::DaemonRuntimeStatus::Running,
                    pid: Some(self.pid),
                    socket_path: Some(PathBuf::from("/run/user/1000/warder.sock")),
                    message: format!("daemon running with pid {}", self.pid),
                })
                .unwrap();
        }
        Ok(LaunchedDaemon {
            pid: self.pid,
            socket_path: PathBuf::from("/run/user/1000/warder.sock"),
        })
    }

    fn is_alive(&self, _pid: u32) -> bool {
        self.alive
    }
}

impl warder_journal::EbpfFileAccessReader for FakeEbpfReader {
    fn read_available_events(
        &mut self,
    ) -> Result<Vec<warder_journal::EbpfFileAccessEvent>, warder_journal::FileJournalWatchError>
    {
        Ok(std::mem::take(&mut self.events))
    }
}

fn fixed_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn assert_valid_random_session_id(session_id: &str) {
    assert!(session_id.starts_with("session-"));
    assert_eq!(session_id.len(), "session-".len() + 32);
    assert!(session_id["session-".len()..]
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn generate_session_id_returns_unique_random_style_ids() {
    let first = generate_session_id();
    let second = generate_session_id();

    assert_valid_random_session_id(&first);
    assert_valid_random_session_id(&second);
    assert_ne!(first, second);
}

#[test]
fn xdg_path_helpers_use_user_scoped_defaults() {
    assert_eq!(
        xdg_data_home(None, Some(PathBuf::from("/home/alice"))),
        PathBuf::from("/home/alice/.local/share")
    );
    assert_eq!(
        xdg_state_home(None, Some(PathBuf::from("/home/alice"))),
        PathBuf::from("/home/alice/.local/state")
    );
    assert_eq!(
        xdg_data_home(
            Some(PathBuf::from("/tmp/data")),
            Some(PathBuf::from("/home/alice"))
        ),
        PathBuf::from("/tmp/data")
    );
    assert_eq!(
        xdg_state_home(
            Some(PathBuf::from("/tmp/state")),
            Some(PathBuf::from("/home/alice"))
        ),
        PathBuf::from("/tmp/state")
    );
    assert_eq!(
        xdg_data_home(
            Some(PathBuf::from("relative-data")),
            Some(PathBuf::from("/home/alice"))
        ),
        PathBuf::from("/home/alice/.local/share")
    );
    assert_eq!(
        xdg_state_home(
            Some(PathBuf::from("relative-state")),
            Some(PathBuf::from("/home/alice"))
        ),
        PathBuf::from("/home/alice/.local/state")
    );
}

fn receipt_test_session() -> SessionRecord {
    SessionRecord {
        id: "session-1".to_string(),
        agent_id: "local".to_string(),
        agent_label: "Local Agent".to_string(),
        agent_profile: Some("codex-cli".to_string()),
        command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        protected_zone_ids: vec!["notes".to_string()],
        status: SessionStatus::Completed,
        exit_code: Some(0),
        started_at: fixed_time(),
        ended_at: Some(fixed_time() + Duration::from_secs(1)),
        root_pid: Some(4242),
        cgroup_path: Some(PathBuf::from("/sys/fs/cgroup/warder/session-1")),
        cgroup_status: CgroupStatus::Tagged,
        landlock_status: warder_core::LandlockStatus::Degraded("Landlock unavailable".to_string()),
        snapshot_status: SnapshotStatus::NotRequested,
        dependency_file_changes: Vec::new(),
        degraded_reasons: vec!["Landlock unavailable".to_string()],
    }
}

fn supported_environment() -> EnvironmentSupport {
    EnvironmentSupport {
        landlock: true,
        cgroups: true,
        ebpf: true,
        snapshot_backends: vec![ConfigSnapshotBackend::Btrfs],
    }
}

fn valid_config(snapshot: &str) -> String {
    valid_config_with_landlock("required", snapshot)
}

fn valid_config_with_landlock(landlock: &str, snapshot: &str) -> String {
    format!(
        r#"
                [enforcement]
                landlock = "{landlock}"
                cgroups = "required"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                snapshot = "{snapshot}"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#
    )
}

fn valid_config_with_writable_roots(landlock: &str, snapshot: &str) -> String {
    format!(
        r#"
                [enforcement]
                landlock = "{landlock}"
                cgroups = "required"
                writable-roots = ["/tmp"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]
                snapshot = "{snapshot}"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#
    )
}

fn config_with_zone_root(zone_root: &std::path::Path, landlock: &str, snapshot: &str) -> String {
    config_with_zone_root_and_cgroups(zone_root, landlock, "required", snapshot)
}

fn config_with_zone_root_and_cgroups(
    zone_root: &std::path::Path,
    landlock: &str,
    cgroups: &str,
    snapshot: &str,
) -> String {
    format!(
        r#"
                [enforcement]
                landlock = "{landlock}"
                cgroups = "{cgroups}"
                writable-roots = ["/tmp"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["{}"]
                write-policy = "allow"
                snapshot = "{snapshot}"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
        zone_root.display()
    )
}

fn temp_file(name: &str, extension: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.{extension}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn write_ready_btrfs_manifest(snapshot_root: &Path, snapshot_id: &str) {
    let snapshot_dir = snapshot_root.join(snapshot_id);
    let snapshot_path = snapshot_dir.join("project");
    let restore_parent = snapshot_root.join("restore-target");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(&restore_parent).unwrap();
    write_test_snapshot_manifest(
        &snapshot_dir,
        warder_snapshot::SnapshotManifest {
            snapshot_id: snapshot_id.to_string(),
            backend: "btrfs".to_string(),
            entries: vec![warder_snapshot::SnapshotManifestEntry {
                source_root: restore_parent.join("project").display().to_string(),
                snapshot_path: snapshot_path.display().to_string(),
            }],
        },
    );
}

fn write_blocked_btrfs_manifest_with_existing_target(snapshot_root: &Path, snapshot_id: &str) {
    let snapshot_dir = snapshot_root.join(snapshot_id);
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("project");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    std::fs::create_dir_all(&source_root).unwrap();
    write_test_snapshot_manifest(
        &snapshot_dir,
        warder_snapshot::SnapshotManifest {
            snapshot_id: snapshot_id.to_string(),
            backend: "btrfs".to_string(),
            entries: vec![warder_snapshot::SnapshotManifestEntry {
                source_root: source_root.display().to_string(),
                snapshot_path: snapshot_path.display().to_string(),
            }],
        },
    );
}

fn write_blocked_btrfs_manifest_with_missing_snapshot_path(
    snapshot_root: &Path,
    snapshot_id: &str,
) {
    let snapshot_dir = snapshot_root.join(snapshot_id);
    let snapshot_path = snapshot_dir.join("project");
    let restore_parent = snapshot_root.join("restore-target");
    std::fs::create_dir_all(&restore_parent).unwrap();
    write_test_snapshot_manifest(
        &snapshot_dir,
        warder_snapshot::SnapshotManifest {
            snapshot_id: snapshot_id.to_string(),
            backend: "btrfs".to_string(),
            entries: vec![warder_snapshot::SnapshotManifestEntry {
                source_root: restore_parent.join("project").display().to_string(),
                snapshot_path: snapshot_path.display().to_string(),
            }],
        },
    );
}

fn write_blocked_btrfs_manifest_with_missing_target_parent(
    snapshot_root: &Path,
    snapshot_id: &str,
) {
    let snapshot_dir = snapshot_root.join(snapshot_id);
    let snapshot_path = snapshot_dir.join("project");
    let source_root = snapshot_root.join("missing-parent").join("project");
    std::fs::create_dir_all(&snapshot_path).unwrap();
    write_test_snapshot_manifest(
        &snapshot_dir,
        warder_snapshot::SnapshotManifest {
            snapshot_id: snapshot_id.to_string(),
            backend: "btrfs".to_string(),
            entries: vec![warder_snapshot::SnapshotManifestEntry {
                source_root: source_root.display().to_string(),
                snapshot_path: snapshot_path.display().to_string(),
            }],
        },
    );
}

fn write_empty_btrfs_manifest(snapshot_root: &Path, snapshot_id: &str) {
    let snapshot_dir = snapshot_root.join(snapshot_id);
    write_test_snapshot_manifest(
        &snapshot_dir,
        warder_snapshot::SnapshotManifest {
            snapshot_id: snapshot_id.to_string(),
            backend: "btrfs".to_string(),
            entries: Vec::new(),
        },
    );
}

fn write_test_snapshot_manifest(snapshot_dir: &Path, manifest: warder_snapshot::SnapshotManifest) {
    std::fs::create_dir_all(snapshot_dir).unwrap();
    std::fs::write(
        snapshot_dir.join("manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();
}
