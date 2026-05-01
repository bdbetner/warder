use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendedProtectionKind {
    SensitiveUser,
    VitalSystem,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionAccess {
    ReadWrite,
    WriteOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecommendedProtection {
    pub id: String,
    pub label: String,
    pub path: String,
    pub kind: RecommendedProtectionKind,
    pub access: ProtectionAccess,
    pub reason: String,
    pub exists: bool,
    pub enabled_by_default: bool,
}

pub fn recommended_protections(home_dir: impl AsRef<Path>) -> Vec<RecommendedProtection> {
    recommended_protections_with_checker(home_dir, |path| Path::new(path).exists())
}

pub fn recommended_protections_with_checker<F>(
    home_dir: impl AsRef<Path>,
    exists: F,
) -> Vec<RecommendedProtection>
where
    F: Fn(&str) -> bool,
{
    let home = home_dir
        .as_ref()
        .to_string_lossy()
        .trim_end_matches('/')
        .to_string();
    let sensitive = [
        (".ssh", "SSH keys"),
        (".gnupg", "GnuPG keys"),
        (".config/gh", "GitHub CLI credentials"),
        (".config/op", "1Password CLI state"),
        (".config/1Password", "1Password desktop state"),
        (".config/keepassxc", "KeePassXC state"),
        (".aws", "AWS credentials"),
        (".azure", "Azure credentials"),
        (".kube", "Kubernetes credentials"),
        (".docker", "Docker credentials"),
        (".npmrc", "NPM token"),
        (".pypirc", "Python package token"),
        (".netrc", "Netrc credentials"),
        (".gem/credentials", "RubyGems credentials"),
        (".password-store", "Password store"),
        (".local/share/keyrings", "Local keyrings"),
        (".mozilla/firefox", "Firefox profiles"),
        (".config/google-chrome", "Chrome profiles"),
        (".config/chromium", "Chromium profiles"),
        (".config/BraveSoftware", "Brave profiles"),
        (".config/vivaldi", "Vivaldi profiles"),
        (".config/microsoft-edge", "Microsoft Edge profiles"),
        (".config/librewolf", "LibreWolf profiles"),
    ];
    let system = ["/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64"];

    let mut protections = Vec::new();

    for (relative, label) in sensitive {
        let path = format!("{home}/{relative}");
        let present = exists(&path);
        protections.push(RecommendedProtection {
            id: slug(&format!("user-{relative}")),
            label: label.to_string(),
            path,
            kind: RecommendedProtectionKind::SensitiveUser,
            access: ProtectionAccess::ReadWrite,
            reason: "Contains credentials, keys, or account state that local agent sessions should not read or modify unless explicitly allowed.".to_string(),
            exists: present,
            enabled_by_default: present,
        });
    }

    for path in system {
        let present = exists(path);
        protections.push(RecommendedProtection {
            id: slug(&format!("system-{path}")),
            label: format!("System path {path}"),
            path: path.to_string(),
            kind: RecommendedProtectionKind::VitalSystem,
            access: ProtectionAccess::WriteOnly,
            reason: "Vital OS path. Warder should block writes from supervised sessions while still allowing normal reads needed to start commands.".to_string(),
            exists: present,
            enabled_by_default: present,
        });
    }

    protections
}

fn slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
