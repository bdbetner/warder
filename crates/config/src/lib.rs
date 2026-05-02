use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct WarderConfig {
    #[serde(default)]
    pub enforcement: EnforcementConfig,
    #[serde(default)]
    pub zones: Vec<ProtectedZoneConfig>,
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    #[serde(default)]
    pub network: NetworkPolicyConfig,
}

impl WarderConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigParseError> {
        toml::from_str(input).map_err(ConfigParseError::Toml)
    }

    pub fn from_yaml(input: &str) -> Result<Self, ConfigParseError> {
        serde_yaml::from_str(input).map_err(ConfigParseError::Yaml)
    }

    pub fn validate(&self, environment: &EnvironmentSupport) -> ConfigValidationReport {
        let mut report = ConfigValidationReport::default();

        if self.zones.is_empty() {
            report.error("at least one protected zone is required");
        }

        if self.agents.is_empty() {
            report.error("at least one agent is required");
        }

        if self.enforcement.landlock == EnforcementRequirement::Required && !environment.landlock {
            report.error("Landlock unavailable, but config requires Landlock enforcement");
        } else if self.enforcement.landlock == EnforcementRequirement::BestEffort
            && !environment.landlock
        {
            report.warning("Landlock unavailable; filesystem enforcement is degraded");
        }

        if self.enforcement.cgroups == EnforcementRequirement::Required && !environment.cgroups {
            report.error("cgroups unavailable, but config requires cgroup session tagging");
        } else if self.enforcement.cgroups == EnforcementRequirement::BestEffort
            && !environment.cgroups
        {
            report.warning("cgroups unavailable; session tagging is degraded");
        }

        if self.network.journal && !environment.ebpf {
            report.warning("eBPF unavailable; network journaling is degraded");
        }

        if !self.network.allowed_destinations.is_empty() {
            report.warning(
                "network.allowed_destinations is non-enforcing metadata in this release; Warder journals network activity but does not block destinations",
            );
        }

        let mut writable_roots = HashSet::new();
        for path in &self.enforcement.writable_roots {
            validate_writable_root_path(&mut report, path);
            if !writable_roots.insert(path.clone()) {
                report.warning(format!(
                    "Landlock writable root '{}' is declared more than once",
                    path.display()
                ));
            }
        }

        let mut zone_ids = HashSet::new();
        for zone in &self.zones {
            validate_identifier(&mut report, "protected zone", &zone.id);
            let normalized_zone_id = zone.id.trim().to_string();
            if !normalized_zone_id.is_empty() && !zone_ids.insert(normalized_zone_id.clone()) {
                report.error(format!(
                    "duplicate protected zone id '{}'",
                    normalized_zone_id
                ));
            }

            if zone.paths.is_empty() {
                report.error(format!(
                    "protected zone '{}' must declare at least one path",
                    zone.id
                ));
            }

            let mut zone_paths = HashSet::new();
            for path in &zone.paths {
                validate_zone_path(&mut report, &zone.id, path);
                if !zone_paths.insert(path.clone()) {
                    report.warning(format!(
                        "protected zone '{}' path '{}' is declared more than once",
                        zone.id,
                        path.display()
                    ));
                }
            }

            if zone.snapshot == SnapshotPolicy::Required && environment.snapshot_backends.is_empty()
            {
                report.error(format!(
                    "snapshot required for protected zone '{}', but no snapshot backend is available",
                    zone.id
                ));
            } else if zone.snapshot == SnapshotPolicy::BestEffort
                && environment.snapshot_backends.is_empty()
            {
                report.warning(format!(
                    "snapshot backend unavailable for protected zone '{}'; session will be unsnapshotted",
                    zone.id
                ));
            }

            if zone.write_policy == WritePolicy::Allow {
                report.warning(format!(
                    "protected zone '{}' has write_policy = \"allow\"; Warder will not deny writes to this zone",
                    zone.id
                ));
            }
        }

        for left in 0..self.zones.len() {
            for right in (left + 1)..self.zones.len() {
                warn_if_zones_overlap(&mut report, &self.zones[left], &self.zones[right]);
            }
        }
        validate_writable_roots_against_zones(
            &mut report,
            self.enforcement.landlock,
            &self.enforcement.writable_roots,
            &self.zones,
        );

        let mut agent_ids = HashSet::new();
        for agent in &self.agents {
            validate_identifier(&mut report, "agent", &agent.id);
            let normalized_agent_id = agent.id.trim().to_string();
            if !normalized_agent_id.is_empty() && !agent_ids.insert(normalized_agent_id.clone()) {
                report.error(format!("duplicate agent id '{}'", normalized_agent_id));
            }

            if agent.command.trim().is_empty() {
                report.error(format!("agent '{}' must declare a command", agent.id));
            }

            if let Some(profile) = &agent.profile {
                validate_identifier(&mut report, "agent profile", profile);
            }
        }

        report
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct EnforcementConfig {
    #[serde(default = "default_required")]
    pub landlock: EnforcementRequirement,
    #[serde(default = "default_required")]
    pub cgroups: EnforcementRequirement,
    #[serde(default)]
    pub writable_roots: Vec<PathBuf>,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            landlock: EnforcementRequirement::Required,
            cgroups: EnforcementRequirement::Required,
            writable_roots: Vec::new(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementRequirement {
    Required,
    BestEffort,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ProtectedZoneConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    #[serde(default = "default_write_policy", alias = "write_policy")]
    pub write_policy: WritePolicy,
    #[serde(default = "default_snapshot_policy")]
    pub snapshot: SnapshotPolicy,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WritePolicy {
    Deny,
    Allow,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotPolicy {
    Required,
    BestEffort,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    pub label: String,
    pub command: String,
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NetworkPolicyConfig {
    #[serde(default = "default_network_journal")]
    pub journal: bool,
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
}

impl Default for NetworkPolicyConfig {
    fn default() -> Self {
        Self {
            journal: true,
            allowed_destinations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentSupport {
    pub landlock: bool,
    pub cgroups: bool,
    pub ebpf: bool,
    pub snapshot_backends: Vec<SnapshotBackend>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SnapshotBackend {
    Btrfs,
    OverlayFs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigIssue {
    pub severity: ConfigIssueSeverity,
    pub message: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigIssueSeverity {
    Error,
    Warning,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigValidationReport {
    pub issues: Vec<ConfigIssue>,
}

impl ConfigValidationReport {
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Error)
    }

    fn error(&mut self, message: impl Into<String>) {
        self.issues.push(ConfigIssue {
            severity: ConfigIssueSeverity::Error,
            message: message.into(),
        });
    }

    fn warning(&mut self, message: impl Into<String>) {
        self.issues.push(ConfigIssue {
            severity: ConfigIssueSeverity::Warning,
            message: message.into(),
        });
    }
}

#[derive(Debug)]
pub enum ConfigParseError {
    Toml(toml::de::Error),
    Yaml(serde_yaml::Error),
}

fn validate_zone_path(report: &mut ConfigValidationReport, zone_id: &str, path: &Path) {
    if !path.is_absolute() {
        report.error(format!(
            "protected zone '{}' path '{}' must be an absolute path",
            zone_id,
            path.display()
        ));
        return;
    }

    if path.parent().is_none() {
        report.error(format!(
            "protected zone '{}' path '{}' must not be the filesystem root",
            zone_id,
            path.display()
        ));
    }

    if is_whole_home_path(path) {
        report.warning(format!(
            "protected zone '{}' uses whole-home protection; prefer explicit subpaths",
            zone_id
        ));
    }

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        report.error(format!(
            "protected zone '{}' path '{}' must not contain parent traversal",
            zone_id,
            path.display()
        ));
    }
}

fn validate_writable_root_path(report: &mut ConfigValidationReport, path: &Path) {
    if !path.is_absolute() {
        report.error(format!(
            "Landlock writable root '{}' must be an absolute path",
            path.display()
        ));
        return;
    }

    if path.parent().is_none() {
        report.error(format!(
            "Landlock writable root '{}' must not be the filesystem root",
            path.display()
        ));
    }

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        report.error(format!(
            "Landlock writable root '{}' must not contain parent traversal",
            path.display()
        ));
    }
}

fn validate_identifier(report: &mut ConfigValidationReport, label: &str, value: &str) {
    if value.trim().is_empty() {
        report.error(format!("{label} id cannot be empty"));
        return;
    }

    if value.trim() != value {
        report.error(format!(
            "{label} id '{}' must not have surrounding whitespace",
            value
        ));
    }

    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        report.error(format!(
            "{label} id '{}' may only contain ASCII letters, numbers, '.', '_', or '-'",
            value
        ));
    }
}

fn warn_if_zones_overlap(
    report: &mut ConfigValidationReport,
    left: &ProtectedZoneConfig,
    right: &ProtectedZoneConfig,
) {
    for left_path in &left.paths {
        for right_path in &right.paths {
            if !left_path.is_absolute() || !right_path.is_absolute() {
                continue;
            }

            if paths_overlap(left_path, right_path) {
                report.warning(format!(
                    "protected zones '{}' and '{}' have overlapping paths",
                    left.id, right.id
                ));
                return;
            }
        }
    }
}

fn validate_writable_roots_against_zones(
    report: &mut ConfigValidationReport,
    landlock: EnforcementRequirement,
    writable_roots: &[PathBuf],
    zones: &[ProtectedZoneConfig],
) {
    if landlock == EnforcementRequirement::Disabled {
        for writable_root in writable_roots {
            if writable_root.is_absolute() {
                report.warning(format!(
                    "Landlock writable root '{}' is ignored because Landlock enforcement is disabled",
                    writable_root.display()
                ));
            }
        }
        return;
    }

    for writable_root in writable_roots {
        if !writable_root.is_absolute() {
            continue;
        }
        for zone in zones {
            if zone.write_policy != WritePolicy::Deny {
                continue;
            }
            for zone_path in &zone.paths {
                if !zone_path.is_absolute() {
                    continue;
                }
                if paths_overlap(writable_root, zone_path) {
                    report.error(format!(
                        "Landlock writable root '{}' must not overlap write-denied protected zone '{}' path '{}'",
                        writable_root.display(),
                        zone.id,
                        zone_path.display()
                    ));
                }
            }
        }
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn is_whole_home_path(path: &Path) -> bool {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    is_whole_home_path_with_home(path, home.as_deref())
}

fn is_whole_home_path_with_home(path: &Path, home: Option<&Path>) -> bool {
    if home
        .filter(|home| home.is_absolute() && path == *home)
        .is_some()
    {
        return true;
    }

    if path == Path::new("/root") {
        return true;
    }

    let components = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>();

    components.len() == 3 && components[0] == "/" && components[1] == "home"
}

fn default_required() -> EnforcementRequirement {
    EnforcementRequirement::Required
}

fn default_write_policy() -> WritePolicy {
    WritePolicy::Deny
}

fn default_snapshot_policy() -> SnapshotPolicy {
    SnapshotPolicy::BestEffort
}

fn default_network_journal() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn supported_environment() -> EnvironmentSupport {
        EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![SnapshotBackend::Btrfs],
        }
    }

    #[test]
    fn parses_minimal_toml_config() {
        let config = WarderConfig::from_toml(
            r#"
                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]
                write_policy = "deny"
                snapshot = "required"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
        )
        .unwrap();

        assert_eq!(config.zones[0].id, "notes");
        assert_eq!(
            config.zones[0].paths,
            vec![PathBuf::from("/home/user/notes")]
        );
        assert_eq!(config.zones[0].snapshot, SnapshotPolicy::Required);
        assert_eq!(config.agents[0].id, "local");
    }

    #[test]
    fn parses_minimal_yaml_config() {
        let config = WarderConfig::from_yaml(
            r#"
zones:
  - id: notes
    name: Notes
    paths:
      - /home/user/notes
    write-policy: deny
    snapshot: required
agents:
  - id: local
    label: Local Agent
    command: agent-command
"#,
        )
        .unwrap();

        assert_eq!(config.zones[0].id, "notes");
        assert_eq!(
            config.zones[0].paths,
            vec![PathBuf::from("/home/user/notes")]
        );
        assert_eq!(config.zones[0].snapshot, SnapshotPolicy::Required);
        assert_eq!(config.agents[0].id, "local");
    }

    #[test]
    fn parses_optional_agent_profile() {
        let config = WarderConfig::from_toml(
            r#"
                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]

                [[agents]]
                id = "codex"
                label = "Codex CLI"
                command = "codex"
                profile = "codex-cli"
            "#,
        )
        .unwrap();

        assert_eq!(config.agents[0].profile.as_deref(), Some("codex-cli"));
    }

    #[test]
    fn rejects_unknown_nested_config_keys() {
        let error = WarderConfig::from_toml(
            r#"
                [enforcement]
                landlock = "disabled"
                cgroups = "best-effort"
                network = "disabled"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes"]
                write_policy = "deny"
                snapshot = "disabled"

                [[agents]]
                id = "local"
                label = "Local Agent"
                command = "agent-command"
            "#,
        )
        .unwrap_err();

        assert!(
            matches!(error, ConfigParseError::Toml(error) if error.message().contains("unknown field `network`"))
        );
    }

    #[test]
    fn rejects_relative_protected_paths() {
        let config = WarderConfig::from_toml(
            r#"
                [[zones]]
                id = "repo"
                name = "Repo"
                paths = ["projects/warder"]
                write_policy = "deny"
                snapshot = "best-effort"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Error
                && issue.message.contains("absolute path")));
    }

    #[test]
    fn warns_about_whole_home_protection() {
        let config = WarderConfig::from_toml(
            r#"
                [[zones]]
                id = "home"
                name = "Home"
                paths = ["/home/user"]
                write_policy = "deny"
                snapshot = "best-effort"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(!report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Warning
                && issue.message.contains("whole-home")));
    }

    #[test]
    fn whole_home_detection_covers_root_and_custom_home() {
        assert!(is_whole_home_path_with_home(Path::new("/root"), None));
        assert!(is_whole_home_path_with_home(
            Path::new("/srv/users/ben"),
            Some(Path::new("/srv/users/ben"))
        ));
        assert!(is_whole_home_path_with_home(Path::new("/home/user"), None));
        assert!(!is_whole_home_path_with_home(
            Path::new("/srv/users/ben/projects"),
            Some(Path::new("/srv/users/ben"))
        ));
    }

    #[test]
    fn reports_required_snapshot_without_backend_as_error() {
        let config = WarderConfig::from_toml(
            r#"
                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]
                write_policy = "deny"
                snapshot = "required"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![],
        });

        assert!(report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.message.contains("snapshot required")));
    }

    #[test]
    fn reports_landlock_degraded_mode_plainly() {
        let config = WarderConfig::from_toml(
            r#"
                [enforcement]
                landlock = "required"
                cgroups = "required"

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]
                write_policy = "deny"
                snapshot = "best-effort"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&EnvironmentSupport {
            landlock: false,
            cgroups: true,
            ebpf: true,
            snapshot_backends: vec![SnapshotBackend::Btrfs],
        });

        assert!(report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.message.contains("Landlock unavailable")));
    }

    #[test]
    fn reports_ebpf_journal_degraded_mode_plainly() {
        let config = WarderConfig::from_toml(
            r#"
                [network]
                journal = true

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]
                write_policy = "deny"
                snapshot = "best-effort"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&EnvironmentSupport {
            landlock: true,
            cgroups: true,
            ebpf: false,
            snapshot_backends: vec![SnapshotBackend::Btrfs],
        });

        assert!(!report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Warning
                && issue.message.contains("eBPF")));
    }

    #[test]
    fn warns_about_non_enforcing_network_allowlists() {
        let config = WarderConfig::from_toml(
            r#"
                [network]
                journal = true
                allowed-destinations = ["api.example.com:443"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(!report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Warning
                && issue
                    .message
                    .contains("network.allowed_destinations is non-enforcing")));
    }

    #[test]
    fn warns_about_observation_only_write_allowed_zones() {
        let config = WarderConfig::from_toml(
            r#"
                [[zones]]
                id = "workspace"
                name = "Workspace"
                paths = ["/home/user/project"]
                write-policy = "allow"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(!report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Warning
                && issue.message.contains("will not deny writes to this zone")));
    }

    #[test]
    fn rejects_relative_writable_roots() {
        let config = WarderConfig::from_toml(
            r#"
                [enforcement]
                writable-roots = ["tmp/work"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/home/user/notes"]
                write_policy = "deny"
                snapshot = "best-effort"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.message.contains("writable root")
                && issue.message.contains("absolute path")));
    }

    #[test]
    fn rejects_unsafe_identifiers_and_normalizes_duplicate_checks() {
        let config = WarderConfig::from_toml(
            r#"
                [[zones]]
                id = " notes "
                name = "Notes"
                paths = ["/tmp/notes"]

                [[zones]]
                id = "notes"
                name = "Notes Duplicate"
                paths = ["/tmp/notes-duplicate"]

                [[agents]]
                id = "local/script"
                label = "Local"
                command = "sh"
                profile = " codex-cli "

                [[agents]]
                id = "local/script"
                label = "Local Duplicate"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(report.has_errors());
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("protected zone id ' notes ' must not have surrounding whitespace")));
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("duplicate protected zone id 'notes'")));
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("agent id 'local/script' may only contain ASCII")));
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.message.contains("duplicate agent id 'local/script'")));
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("agent profile id ' codex-cli ' must not have surrounding whitespace")));
    }

    #[test]
    fn rejects_filesystem_root_as_protected_path_or_writable_root() {
        let config = WarderConfig::from_toml(
            r#"
                [enforcement]
                writable-roots = ["/"]

                [[zones]]
                id = "root-zone"
                name = "Root"
                paths = ["/"]

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(report.has_errors());
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("protected zone 'root-zone' path '/' must not be the filesystem root")));
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("Landlock writable root '/' must not be the filesystem root")));
    }

    #[test]
    fn warns_about_duplicate_paths_and_writable_roots() {
        let config = WarderConfig::from_toml(
            r#"
                [enforcement]
                writable-roots = ["/tmp/work", "/tmp/work"]

                [[zones]]
                id = "notes"
                name = "Notes"
                paths = ["/tmp/notes", "/tmp/notes"]

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(!report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Warning
                && issue
                    .message
                    .contains("Landlock writable root '/tmp/work' is declared more than once")));
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Warning
                && issue.message.contains(
                    "protected zone 'notes' path '/tmp/notes' is declared more than once"
                )));
    }

    #[test]
    fn rejects_writable_roots_that_overlap_write_denied_zones() {
        let config = WarderConfig::from_toml(
            r#"
                [enforcement]
                writable-roots = ["/tmp/work", "/tmp/secrets/cache"]

                [[zones]]
                id = "secrets"
                name = "Secrets"
                paths = ["/tmp/work/secrets", "/tmp/secrets"]
                write-policy = "deny"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(report.has_errors());
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("Landlock writable root '/tmp/work' must not overlap write-denied protected zone 'secrets' path '/tmp/work/secrets'")));
        assert!(report.issues.iter().any(|issue| issue
            .message
            .contains("Landlock writable root '/tmp/secrets/cache' must not overlap write-denied protected zone 'secrets' path '/tmp/secrets'")));
    }

    #[test]
    fn warns_when_writable_roots_are_ignored_with_landlock_disabled() {
        let config = WarderConfig::from_toml(
            r#"
                [enforcement]
                landlock = "disabled"
                writable-roots = ["/tmp/work"]

                [[zones]]
                id = "workspace"
                name = "Workspace"
                paths = ["/tmp/work"]
                write-policy = "allow"

                [[agents]]
                id = "local"
                label = "Local"
                command = "sh"
            "#,
        )
        .unwrap();

        let report = config.validate(&supported_environment());

        assert!(!report.has_errors());
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.severity == ConfigIssueSeverity::Warning
                && issue.message.contains(
                    "Landlock writable root '/tmp/work' is ignored because Landlock enforcement is disabled"
                )));
    }
}
