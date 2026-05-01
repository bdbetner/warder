use std::path::{Component, Path, PathBuf};
use warder_core::{AgentIdentity, Capability, PolicyEffect, PolicyRule, ProtectedZone};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    Ask,
}

pub fn evaluate_policy(
    agent: &AgentIdentity,
    protected_zone: &ProtectedZone,
    capability: Capability,
    target_path: impl AsRef<Path>,
) -> PolicyDecision {
    evaluate_policy_with_rules(agent, protected_zone, &[], capability, target_path)
}

pub fn evaluate_policy_with_rules(
    agent: &AgentIdentity,
    protected_zone: &ProtectedZone,
    rules: &[PolicyRule],
    capability: Capability,
    target_path: impl AsRef<Path>,
) -> PolicyDecision {
    if agent.disabled {
        return PolicyDecision::Deny;
    }

    if is_always_denied_capability(capability) {
        return PolicyDecision::Deny;
    }

    if is_file_capability(capability)
        && (!is_path_allowed_in_protected_zone(protected_zone, target_path.as_ref())
            || is_builtin_denied_path(target_path.as_ref()))
    {
        return PolicyDecision::Deny;
    }

    if is_risky_capability(capability) {
        return matching_rule_decision(
            agent,
            protected_zone,
            rules,
            capability,
            target_path.as_ref(),
        )
        .unwrap_or(PolicyDecision::Ask);
    }

    matching_rule_decision(
        agent,
        protected_zone,
        rules,
        capability,
        target_path.as_ref(),
    )
    .unwrap_or(match capability {
        Capability::ReadFile => PolicyDecision::Allow,
        _ => PolicyDecision::Deny,
    })
}

pub fn is_path_allowed_in_protected_zone(
    protected_zone: &ProtectedZone,
    target_path: &Path,
) -> bool {
    if has_parent_traversal(target_path) {
        return false;
    }

    let Some(target) = normalized_existing_or_lexical(target_path) else {
        return false;
    };

    protected_zone
        .root_paths
        .iter()
        .filter_map(|root| normalized_existing_or_lexical(root))
        .any(|root| target == root || target.starts_with(root))
}

pub fn is_builtin_denied_path(path: &Path) -> bool {
    let lowered = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_lowercase())
        .collect::<Vec<_>>();
    let lowered_path = path_to_slash_string(path).to_lowercase();

    lowered.iter().any(|part| {
        matches!(
            part.as_str(),
            ".ssh"
                | ".gnupg"
                | ".aws"
                | ".azure"
                | ".docker"
                | ".gem"
                | ".kube"
                | ".git"
                | ".password-store"
                | "node_modules"
                | "firefox"
                | "google-chrome"
                | "chromium"
                | "bravesoftware"
                | "librewolf"
                | "microsoft-edge"
                | "opera"
                | "vivaldi"
        )
    }) || [
        "/.config/1password/",
        "/.config/gh/",
        "/.config/keepassxc/",
        "/.docker/config.json",
        "/.gem/credentials",
    ]
    .iter()
    .any(|needle| lowered_path.contains(needle))
        || lowered_path.ends_with("/.config/1password")
        || lowered_path.ends_with("/.config/gh")
        || lowered_path.ends_with("/.config/keepassxc")
        || lowered
            .last()
            .map(|name| {
                name == ".env"
                    || name.starts_with(".env.")
                    || name == ".netrc"
                    || name == ".npmrc"
                    || name == ".pypirc"
                    || name == "credentials"
                    || name.ends_with(".pem")
                    || name.ends_with(".key")
                    || name.ends_with(".p12")
                    || name.ends_with(".pfx")
                    || name.starts_with("wallet")
            })
            .unwrap_or(false)
}

fn matching_rule_decision(
    agent: &AgentIdentity,
    protected_zone: &ProtectedZone,
    rules: &[PolicyRule],
    capability: Capability,
    target_path: &Path,
) -> Option<PolicyDecision> {
    rules
        .iter()
        .find(|rule| {
            rule.protected_zone_id == protected_zone.id
                && rule.agent_id == agent.id
                && rule.capability == capability
                && rule_path_matches(rule, target_path)
        })
        .map(|rule| match rule.effect {
            PolicyEffect::Allow => PolicyDecision::Allow,
            PolicyEffect::Deny => PolicyDecision::Deny,
            PolicyEffect::Ask => PolicyDecision::Ask,
        })
}

fn rule_path_matches(rule: &PolicyRule, target_path: &Path) -> bool {
    let path_scope_matches = rule
        .path_scope
        .as_ref()
        .map(|scope| target_path.starts_with(scope))
        .unwrap_or(true);

    path_scope_matches && globs_match(&rule.file_globs, target_path)
}

fn globs_match(globs: &[String], target_path: &Path) -> bool {
    if globs.is_empty() {
        return true;
    }

    let filename = target_path.file_name().and_then(|name| name.to_str());
    let full_path = path_to_slash_string(target_path);
    let trimmed_path = full_path.trim_start_matches('/');

    globs.iter().any(|glob| {
        if glob.contains('/') {
            simple_glob_match(glob, &full_path) || simple_glob_match(glob, trimmed_path)
        } else {
            filename
                .map(|name| simple_glob_match(glob, name))
                .unwrap_or(false)
        }
    })
}

fn simple_glob_match(glob: &str, name: &str) -> bool {
    if glob == "*" {
        return true;
    }

    if !glob.contains('*') {
        return glob == name;
    }

    let anchored_start = !glob.starts_with('*');
    let anchored_end = !glob.ends_with('*');
    let parts = glob.split('*').collect::<Vec<_>>();
    let mut remainder = name;

    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if index == 0 && anchored_start {
            let Some(next) = remainder.strip_prefix(part) else {
                return false;
            };
            remainder = next;
            continue;
        }

        let Some(position) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[position + part.len()..];
    }

    if anchored_end {
        match parts.iter().rev().find(|part| !part.is_empty()) {
            Some(last) => name.ends_with(last),
            None => true,
        }
    } else {
        true
    }
}

fn path_to_slash_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn is_risky_capability(capability: Capability) -> bool {
    matches!(
        capability,
        Capability::WriteFile | Capability::MoveFile | Capability::DeleteFile
    )
}

fn is_file_capability(capability: Capability) -> bool {
    matches!(
        capability,
        Capability::ReadFile
            | Capability::WriteFile
            | Capability::MoveFile
            | Capability::DeleteFile
    )
}

fn is_always_denied_capability(capability: Capability) -> bool {
    matches!(capability, Capability::RunShellCommand)
}

fn has_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn normalized_existing_or_lexical(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }

    if !path.is_absolute() {
        return None;
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => return None,
            Component::Normal(part) => normalized.push(part),
        }
    }

    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::SystemTime;
    use warder_core::{AgentKind, PolicyEffect};

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("warder-policy-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn agent() -> AgentIdentity {
        AgentIdentity {
            id: "agent-1".to_string(),
            name: "Test Agent".to_string(),
            kind: AgentKind::LocalScript,
            token_hash: "hash".to_string(),
            created_at: SystemTime::now(),
            expires_at: None,
            disabled: false,
        }
    }

    fn protected_zone(root: PathBuf) -> ProtectedZone {
        ProtectedZone {
            id: "protected_zone-1".to_string(),
            name: "Test ProtectedZone".to_string(),
            description: "A test protected_zone".to_string(),
            root_paths: vec![root],
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
        }
    }

    #[test]
    fn policy_allow_rule_allows_read_inside_protected_zone() {
        let root = temp_root("allow");
        let file = root.join("note.md");
        fs::write(&file, "hello").unwrap();
        let agent = agent();
        let protected_zone = protected_zone(root.clone());
        let rules = vec![PolicyRule {
            id: "rule-1".to_string(),
            protected_zone_id: protected_zone.id.clone(),
            agent_id: agent.id.clone(),
            capability: Capability::ReadFile,
            effect: PolicyEffect::Allow,
            path_scope: Some(root),
            file_globs: vec!["*.md".to_string()],
            expires_at: None,
        }];

        assert_eq!(
            evaluate_policy_with_rules(&agent, &protected_zone, &rules, Capability::ReadFile, file),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn policy_deny_rule_denies_read_inside_protected_zone() {
        let root = temp_root("deny");
        let file = root.join("note.md");
        fs::write(&file, "hello").unwrap();
        let agent = agent();
        let protected_zone = protected_zone(root.clone());
        let rules = vec![PolicyRule {
            id: "rule-1".to_string(),
            protected_zone_id: protected_zone.id.clone(),
            agent_id: agent.id.clone(),
            capability: Capability::ReadFile,
            effect: PolicyEffect::Deny,
            path_scope: Some(root),
            file_globs: vec!["*.md".to_string()],
            expires_at: None,
        }];

        assert_eq!(
            evaluate_policy_with_rules(&agent, &protected_zone, &rules, Capability::ReadFile, file),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn policy_ask_rule_returns_ask() {
        let root = temp_root("ask");
        let file = root.join("proposal.md");
        fs::write(&file, "hello").unwrap();
        let agent = agent();
        let protected_zone = protected_zone(root.clone());
        let rules = vec![PolicyRule {
            id: "rule-1".to_string(),
            protected_zone_id: protected_zone.id.clone(),
            agent_id: agent.id.clone(),
            capability: Capability::WriteFile,
            effect: PolicyEffect::Ask,
            path_scope: Some(root),
            file_globs: vec!["*.md".to_string()],
            expires_at: None,
        }];

        assert_eq!(
            evaluate_policy_with_rules(
                &agent,
                &protected_zone,
                &rules,
                Capability::WriteFile,
                file
            ),
            PolicyDecision::Ask
        );
    }

    #[test]
    fn allowed_read_inside_protected_zone() {
        let root = temp_root("inside");
        let file = root.join("notes.txt");
        fs::write(&file, "hello").unwrap();

        assert_eq!(
            evaluate_policy(&agent(), &protected_zone(root), Capability::ReadFile, file),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn denied_read_outside_protected_zone() {
        let root = temp_root("outside-root");
        let outside = temp_root("outside-file").join("notes.txt");
        fs::write(&outside, "hello").unwrap();

        assert_eq!(
            evaluate_policy(
                &agent(),
                &protected_zone(root),
                Capability::ReadFile,
                outside
            ),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn path_traversal_is_denied() {
        let root = temp_root("traversal");
        let target = root.join("../secret.txt");

        assert_eq!(
            evaluate_policy(
                &agent(),
                &protected_zone(root),
                Capability::ReadFile,
                target
            ),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denied_env_file() {
        let root = temp_root("env");
        let file = root.join(".env");
        fs::write(&file, "TOKEN=secret").unwrap();

        assert_eq!(
            evaluate_policy(&agent(), &protected_zone(root), Capability::ReadFile, file),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denied_ssh_path() {
        let root = temp_root("ssh");
        let dir = root.join(".ssh");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("id_rsa");
        fs::write(&file, "secret").unwrap();

        assert_eq!(
            evaluate_policy(&agent(), &protected_zone(root), Capability::ReadFile, file),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denied_browser_profile_path() {
        let root = temp_root("browser");
        let dir = root.join(".config").join("google-chrome").join("Default");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("Cookies");
        fs::write(&file, "secret").unwrap();

        assert_eq!(
            evaluate_policy(&agent(), &protected_zone(root), Capability::ReadFile, file),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn denied_expanded_secret_paths() {
        let root = temp_root("expanded-secrets");
        let paths = [
            root.join(".npmrc"),
            root.join(".pypirc"),
            root.join(".netrc"),
            root.join(".password-store").join("example.gpg"),
            root.join(".docker").join("config.json"),
            root.join(".config").join("gh").join("hosts.yml"),
            root.join(".config").join("1Password").join("settings.json"),
            root.join(".config").join("keepassxc").join("keepassxc.ini"),
            root.join(".gem").join("credentials"),
            root.join(".config")
                .join("vivaldi")
                .join("Default")
                .join("Cookies"),
            root.join(".config").join("microsoft-edge").join("Default"),
            root.join(".config").join("librewolf").join("profiles.ini"),
        ];

        for path in paths {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, "secret").unwrap();

            assert_eq!(
                evaluate_policy(
                    &agent(),
                    &protected_zone(root.clone()),
                    Capability::ReadFile,
                    path
                ),
                PolicyDecision::Deny
            );
        }
    }

    #[test]
    fn write_file_returns_ask() {
        let root = temp_root("write");
        let file = root.join("notes.txt");

        assert_eq!(
            evaluate_policy(&agent(), &protected_zone(root), Capability::WriteFile, file),
            PolicyDecision::Ask
        );
    }

    #[test]
    fn delete_file_returns_ask_or_deny() {
        let root = temp_root("delete");
        let file = root.join("notes.txt");

        assert!(matches!(
            evaluate_policy(
                &agent(),
                &protected_zone(root),
                Capability::DeleteFile,
                file
            ),
            PolicyDecision::Ask | PolicyDecision::Deny
        ));
    }

    #[test]
    fn write_file_outside_protected_zone_is_denied() {
        let root = temp_root("write-outside-root");
        let outside = temp_root("write-outside-file").join("notes.txt");

        assert_eq!(
            evaluate_policy(
                &agent(),
                &protected_zone(root),
                Capability::WriteFile,
                outside
            ),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn write_file_to_secret_path_is_denied() {
        let root = temp_root("write-secret");
        let file = root.join(".env.local");

        assert_eq!(
            evaluate_policy(&agent(), &protected_zone(root), Capability::WriteFile, file),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn run_shell_command_returns_deny() {
        let root = temp_root("shell");

        assert_eq!(
            evaluate_policy(
                &agent(),
                &protected_zone(root.clone()),
                Capability::RunShellCommand,
                root.join("ignored")
            ),
            PolicyDecision::Deny
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_denied_by_canonicalization() {
        use std::os::unix::fs::symlink;

        let root = temp_root("symlink-root");
        let outside = temp_root("symlink-outside");
        let outside_file = outside.join("secret.txt");
        fs::write(&outside_file, "secret").unwrap();
        let link = root.join("linked-secret.txt");
        symlink(&outside_file, &link).unwrap();

        assert_eq!(
            evaluate_policy(&agent(), &protected_zone(root), Capability::ReadFile, link),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn path_aware_globs_match_full_paths() {
        let root = temp_root("path-globs");
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let src_file = src_dir.join("main.rs");
        let docs_file = root.join("docs").join("main.rs");
        fs::create_dir_all(docs_file.parent().unwrap()).unwrap();
        fs::write(&src_file, "fn main() {}").unwrap();
        fs::write(&docs_file, "not source").unwrap();
        let agent = agent();
        let protected_zone = protected_zone(root.clone());
        let rules = vec![PolicyRule {
            id: "rule-1".to_string(),
            protected_zone_id: protected_zone.id.clone(),
            agent_id: agent.id.clone(),
            capability: Capability::WriteFile,
            effect: PolicyEffect::Allow,
            path_scope: Some(root),
            file_globs: vec!["*/src/*.rs".to_string()],
            expires_at: None,
        }];

        assert_eq!(
            evaluate_policy_with_rules(
                &agent,
                &protected_zone,
                &rules,
                Capability::WriteFile,
                src_file
            ),
            PolicyDecision::Allow
        );
        assert_eq!(
            evaluate_policy_with_rules(
                &agent,
                &protected_zone,
                &rules,
                Capability::WriteFile,
                docs_file
            ),
            PolicyDecision::Ask
        );
    }
}
