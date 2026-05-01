use crate::config::{render_gui_config_toml, GuiAgentConfig, GuiConfigDraft, GuiProtectedPath};
use crate::defaults::{
    recommended_protections_with_checker, ProtectionAccess, RecommendedProtectionKind,
};

#[test]
fn sensitive_user_paths_default_to_read_and_write_when_present() {
    let protections = recommended_protections_with_checker("/home/alex", |path| {
        matches!(path, "/home/alex/.ssh" | "/home/alex/.gnupg")
    });

    let ssh = protections
        .iter()
        .find(|item| item.path == "/home/alex/.ssh")
        .expect("ssh recommendation");
    assert_eq!(ssh.kind, RecommendedProtectionKind::SensitiveUser);
    assert_eq!(ssh.access, ProtectionAccess::ReadWrite);
    assert!(ssh.exists);
    assert!(ssh.enabled_by_default);

    let missing_aws = protections
        .iter()
        .find(|item| item.path == "/home/alex/.aws")
        .expect("aws recommendation");
    assert!(!missing_aws.exists);
    assert!(!missing_aws.enabled_by_default);
}

#[test]
fn system_paths_default_to_write_only() {
    let protections =
        recommended_protections_with_checker("/home/alex", |path| matches!(path, "/etc" | "/usr"));

    let etc = protections
        .iter()
        .find(|item| item.path == "/etc")
        .expect("etc recommendation");
    assert_eq!(etc.kind, RecommendedProtectionKind::VitalSystem);
    assert_eq!(etc.access, ProtectionAccess::WriteOnly);
    assert!(etc.enabled_by_default);
}

#[test]
fn renders_gui_config_with_selected_paths_and_agent() {
    let draft = GuiConfigDraft {
        agent: GuiAgentConfig {
            id: "codex".to_string(),
            label: "Codex".to_string(),
            command: "codex".to_string(),
            profile: Some("codex-cli".to_string()),
        },
        protected_paths: vec![
            GuiProtectedPath {
                id: "ssh".to_string(),
                label: "SSH keys".to_string(),
                path: "/home/alex/.ssh".to_string(),
                read_protected: true,
                write_protected: true,
                snapshot: false,
            },
            GuiProtectedPath {
                id: "etc".to_string(),
                label: "System path /etc".to_string(),
                path: "/etc".to_string(),
                read_protected: false,
                write_protected: true,
                snapshot: false,
            },
        ],
        network_journal: false,
    };

    let toml = render_gui_config_toml(&draft).expect("rendered config");
    assert!(toml.contains("landlock = \"best-effort\""));
    assert!(toml.contains("cgroups = \"best-effort\""));
    assert!(toml.contains("id = \"ssh\""));
    assert!(toml.contains("paths = [\"/home/alex/.ssh\"]"));
    assert!(toml.contains("write-policy = \"deny\""));
    assert!(toml.contains("command = \"codex\""));
    assert!(toml.contains("profile = \"codex-cli\""));

    let parsed = warder_config::WarderConfig::from_toml(&toml).expect("valid Warder config");
    assert_eq!(parsed.zones.len(), 2);
    assert_eq!(parsed.agents[0].id, "codex");
    assert_eq!(parsed.agents[0].profile.as_deref(), Some("codex-cli"));
}

#[test]
fn rejects_paths_without_write_or_read_protection() {
    let draft = GuiConfigDraft {
        agent: GuiAgentConfig {
            id: "agent".to_string(),
            label: "Agent".to_string(),
            command: "agent".to_string(),
            profile: None,
        },
        protected_paths: vec![GuiProtectedPath {
            id: "noop".to_string(),
            label: "No protection".to_string(),
            path: "/tmp/noop".to_string(),
            read_protected: false,
            write_protected: false,
            snapshot: false,
        }],
        network_journal: false,
    };

    let error = render_gui_config_toml(&draft).unwrap_err();
    assert!(error.contains("must enable read or write protection"));
}
