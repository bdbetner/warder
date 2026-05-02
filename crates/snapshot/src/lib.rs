use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotBackend {
    Btrfs,
    OverlayFs,
    Unsupported,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SnapshotRequirement {
    Required,
    BestEffort,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotPlan {
    Create { backend: SnapshotBackend },
    Skip(String),
    Block(String),
    NotRequested,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotCreateRequest {
    pub session_id: String,
    pub roots: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRestoreRequest {
    pub snapshot_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotCreateOutcome {
    pub backend: SnapshotBackend,
    pub snapshot_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRestoreOutcome {
    pub backend: SnapshotBackend,
    pub snapshot_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub snapshot_id: String,
    pub backend: String,
    pub entries: Vec<SnapshotManifestEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifestEntry {
    pub source_root: String,
    pub snapshot_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotError {
    pub message: String,
}

pub trait SnapshotBackendDriver {
    fn backend(&self) -> SnapshotBackend;

    fn create_snapshot(
        &self,
        request: &SnapshotCreateRequest,
    ) -> Result<SnapshotCreateOutcome, SnapshotError>;

    fn restore_snapshot(
        &self,
        request: &SnapshotRestoreRequest,
    ) -> Result<SnapshotRestoreOutcome, SnapshotError>;
}

pub trait SnapshotCommandRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<(), SnapshotError>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemSnapshotCommandRunner;

impl SnapshotCommandRunner for SystemSnapshotCommandRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<(), SnapshotError> {
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .map_err(|error| SnapshotError {
                message: format!("failed to run {program}: {error}"),
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(SnapshotError {
                message: format!("{program} exited with {status}"),
            })
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtrfsSnapshotDriver<R> {
    snapshot_root: PathBuf,
    runner: R,
}

impl<R> BtrfsSnapshotDriver<R> {
    pub fn new(snapshot_root: impl Into<PathBuf>, runner: R) -> Self {
        Self {
            snapshot_root: snapshot_root.into(),
            runner,
        }
    }
}

impl<R> SnapshotBackendDriver for BtrfsSnapshotDriver<R>
where
    R: SnapshotCommandRunner,
{
    fn backend(&self) -> SnapshotBackend {
        SnapshotBackend::Btrfs
    }

    fn create_snapshot(
        &self,
        request: &SnapshotCreateRequest,
    ) -> Result<SnapshotCreateOutcome, SnapshotError> {
        if request.roots.is_empty() {
            return Err(SnapshotError {
                message: format!(
                    "btrfs snapshot creation failed for session '{}': no roots requested",
                    request.session_id
                ),
            });
        }
        let snapshot_id = format!("{}-btrfs", request.session_id);
        validate_snapshot_id(&snapshot_id).map_err(|error| SnapshotError {
            message: format!(
                "btrfs snapshot creation failed for session '{}': {}",
                request.session_id, error.message
            ),
        })?;
        let session_snapshot_root = self.snapshot_root.join(&snapshot_id);
        std::fs::create_dir_all(&session_snapshot_root).map_err(|error| SnapshotError {
            message: format!(
                "btrfs snapshot creation failed for session '{}': failed to create snapshot root '{}': {error}",
                request.session_id,
                session_snapshot_root.display()
            ),
        })?;
        let mut manifest = SnapshotManifest {
            snapshot_id: snapshot_id.clone(),
            backend: snapshot_backend_label(&SnapshotBackend::Btrfs).to_string(),
            entries: Vec::new(),
        };
        let target_names = snapshot_target_names(&request.roots);
        for (root, target_name) in request.roots.iter().zip(target_names.iter()) {
            let target = session_snapshot_root.join(target_name);
            let args = vec![
                "subvolume".to_string(),
                "snapshot".to_string(),
                "-r".to_string(),
                root.display().to_string(),
                target.display().to_string(),
            ];
            self.runner
                .run("btrfs", &args)
                .map_err(|error| SnapshotError {
                    message: format!(
                        "btrfs snapshot creation failed for session '{}': {}",
                        request.session_id, error.message
                    ),
                })?;
            manifest.entries.push(SnapshotManifestEntry {
                source_root: root.display().to_string(),
                snapshot_path: target.display().to_string(),
            });
        }
        write_snapshot_manifest(&session_snapshot_root, &manifest)?;
        Ok(SnapshotCreateOutcome {
            backend: SnapshotBackend::Btrfs,
            snapshot_id,
        })
    }

    fn restore_snapshot(
        &self,
        request: &SnapshotRestoreRequest,
    ) -> Result<SnapshotRestoreOutcome, SnapshotError> {
        let manifest = load_snapshot_manifest(&self.snapshot_root, &request.snapshot_id)?;
        if manifest.backend != snapshot_backend_label(&SnapshotBackend::Btrfs) {
            return Err(SnapshotError {
                message: format!(
                    "btrfs snapshot restore refused for snapshot '{}': manifest backend is '{}'",
                    request.snapshot_id, manifest.backend
                ),
            });
        }
        if manifest.entries.is_empty() {
            return Err(SnapshotError {
                message: format!(
                    "btrfs snapshot restore refused for snapshot '{}': manifest has no entries",
                    request.snapshot_id
                ),
            });
        }
        let entries = manifest
            .entries
            .iter()
            .map(|entry| {
                (
                    PathBuf::from(&entry.snapshot_path),
                    PathBuf::from(&entry.source_root),
                )
            })
            .collect::<Vec<_>>();
        for (snapshot_path, source_root) in &entries {
            if !snapshot_path.exists() {
                return Err(SnapshotError {
                    message: format!(
                        "btrfs snapshot restore refused for snapshot '{}': snapshot path '{}' is missing",
                        request.snapshot_id,
                        snapshot_path.display()
                    ),
                });
            }
            if source_root.exists() {
                return Err(SnapshotError {
                    message: format!(
                        "btrfs snapshot restore refused for snapshot '{}': refusing to restore over existing path '{}'",
                        request.snapshot_id,
                        source_root.display()
                    ),
                });
            }
            let Some(parent) = source_root.parent() else {
                return Err(SnapshotError {
                    message: format!(
                        "btrfs snapshot restore refused for snapshot '{}': source root '{}' has no parent",
                        request.snapshot_id,
                        source_root.display()
                    ),
                });
            };
            if !parent.exists() {
                return Err(SnapshotError {
                    message: format!(
                        "btrfs snapshot restore refused for snapshot '{}': parent path '{}' is missing",
                        request.snapshot_id,
                        parent.display()
                    ),
                });
            }
        }
        for (snapshot_path, source_root) in entries {
            let args = vec![
                "subvolume".to_string(),
                "snapshot".to_string(),
                snapshot_path.display().to_string(),
                source_root.display().to_string(),
            ];
            self.runner
                .run("btrfs", &args)
                .map_err(|error| SnapshotError {
                    message: format!(
                        "btrfs snapshot restore failed for snapshot '{}': {}",
                        request.snapshot_id, error.message
                    ),
                })?;
        }
        Ok(SnapshotRestoreOutcome {
            backend: SnapshotBackend::Btrfs,
            snapshot_id: request.snapshot_id.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedSnapshotDriver {
    backend: SnapshotBackend,
    reason: String,
}

impl UnsupportedSnapshotDriver {
    pub fn new(backend: SnapshotBackend, reason: impl Into<String>) -> Self {
        Self {
            backend,
            reason: reason.into(),
        }
    }
}

impl SnapshotBackendDriver for UnsupportedSnapshotDriver {
    fn backend(&self) -> SnapshotBackend {
        self.backend.clone()
    }

    fn create_snapshot(
        &self,
        request: &SnapshotCreateRequest,
    ) -> Result<SnapshotCreateOutcome, SnapshotError> {
        Err(SnapshotError {
            message: format!(
                "{} snapshot creation is unavailable for session '{}': {}",
                snapshot_backend_label(&self.backend),
                request.session_id,
                self.reason
            ),
        })
    }

    fn restore_snapshot(
        &self,
        request: &SnapshotRestoreRequest,
    ) -> Result<SnapshotRestoreOutcome, SnapshotError> {
        Err(SnapshotError {
            message: format!(
                "{} snapshot restore is unavailable for snapshot '{}': {}",
                snapshot_backend_label(&self.backend),
                request.snapshot_id,
                self.reason
            ),
        })
    }
}

pub fn plan_snapshot(
    requirement: SnapshotRequirement,
    available_backends: &[SnapshotBackend],
) -> SnapshotPlan {
    match requirement {
        SnapshotRequirement::Disabled => SnapshotPlan::NotRequested,
        SnapshotRequirement::Required => match first_supported_backend(available_backends) {
            Some(backend) => SnapshotPlan::Create { backend },
            None => SnapshotPlan::Block(
                "snapshot required, but no supported snapshot backend is available".to_string(),
            ),
        },
        SnapshotRequirement::BestEffort => match first_supported_backend(available_backends) {
            Some(backend) => SnapshotPlan::Create { backend },
            None => {
                SnapshotPlan::Skip("snapshot backend unavailable; skipping snapshot".to_string())
            }
        },
    }
}

fn first_supported_backend(available_backends: &[SnapshotBackend]) -> Option<SnapshotBackend> {
    available_backends
        .iter()
        .find(|backend| **backend != SnapshotBackend::Unsupported)
        .cloned()
}

fn snapshot_target_names(roots: &[PathBuf]) -> Vec<String> {
    let mut counts = std::collections::BTreeMap::new();
    roots
        .iter()
        .map(|root| {
            let base = snapshot_target_name(root);
            let count = counts.entry(base.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                base
            } else {
                format!("{base}-{count}")
            }
        })
        .collect()
}

fn snapshot_target_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("root")
        .to_string()
}

fn write_snapshot_manifest(
    session_snapshot_root: &Path,
    manifest: &SnapshotManifest,
) -> Result<(), SnapshotError> {
    let json = serde_json::to_string(manifest).map_err(|error| SnapshotError {
        message: format!("failed to encode snapshot manifest: {error}"),
    })?;
    std::fs::write(session_snapshot_root.join("manifest.json"), json).map_err(|error| {
        SnapshotError {
            message: format!("failed to write snapshot manifest: {error}"),
        }
    })
}

pub fn load_snapshot_manifest(
    snapshot_root: impl AsRef<Path>,
    snapshot_id: &str,
) -> Result<SnapshotManifest, SnapshotError> {
    validate_snapshot_id(snapshot_id)?;
    let manifest_path = snapshot_root
        .as_ref()
        .join(snapshot_id)
        .join("manifest.json");
    let json = std::fs::read_to_string(&manifest_path).map_err(|error| SnapshotError {
        message: format!(
            "snapshot manifest unavailable for snapshot '{}': failed to read '{}': {error}",
            snapshot_id,
            manifest_path.display()
        ),
    })?;
    let manifest: SnapshotManifest =
        serde_json::from_str(&json).map_err(|error| SnapshotError {
            message: format!(
                "snapshot manifest unavailable for snapshot '{}': failed to parse '{}': {error}",
                snapshot_id,
                manifest_path.display()
            ),
        })?;
    validate_snapshot_manifest(snapshot_id, &manifest)?;
    Ok(manifest)
}

pub fn validate_snapshot_id(snapshot_id: &str) -> Result<(), SnapshotError> {
    if snapshot_id.is_empty() {
        return Err(SnapshotError {
            message: "invalid snapshot id: snapshot id must not be empty".to_string(),
        });
    }
    if !snapshot_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(SnapshotError {
            message: format!(
                "invalid snapshot id '{snapshot_id}': only ASCII letters, digits, '-' and '_' are allowed"
            ),
        });
    }
    Ok(())
}

fn validate_snapshot_manifest(
    requested_snapshot_id: &str,
    manifest: &SnapshotManifest,
) -> Result<(), SnapshotError> {
    if manifest.snapshot_id != requested_snapshot_id {
        return Err(SnapshotError {
            message: format!(
                "snapshot manifest invalid for snapshot '{}': manifest declares snapshot id '{}'",
                requested_snapshot_id, manifest.snapshot_id
            ),
        });
    }

    for entry in &manifest.entries {
        validate_manifest_path(requested_snapshot_id, "source_root", &entry.source_root)?;
        validate_manifest_path(requested_snapshot_id, "snapshot_path", &entry.snapshot_path)?;
    }
    Ok(())
}

fn validate_manifest_path(
    requested_snapshot_id: &str,
    field: &'static str,
    value: &str,
) -> Result<(), SnapshotError> {
    if value.as_bytes().contains(&0) {
        return Err(SnapshotError {
            message: format!(
                "snapshot manifest invalid for snapshot '{requested_snapshot_id}': {field} must not contain NUL bytes"
            ),
        });
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(SnapshotError {
            message: format!(
                "snapshot manifest invalid for snapshot '{requested_snapshot_id}': {field} '{value}' must be absolute"
            ),
        });
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SnapshotError {
            message: format!(
                "snapshot manifest invalid for snapshot '{requested_snapshot_id}': {field} '{value}' must not contain parent traversal"
            ),
        });
    }
    Ok(())
}

fn snapshot_backend_label(backend: &SnapshotBackend) -> &'static str {
    match backend {
        SnapshotBackend::Btrfs => "btrfs",
        SnapshotBackend::OverlayFs => "overlayfs",
        SnapshotBackend::Unsupported => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_snapshot_uses_available_backend() {
        let plan = plan_snapshot(SnapshotRequirement::Required, &[SnapshotBackend::Btrfs]);

        assert_eq!(
            plan,
            SnapshotPlan::Create {
                backend: SnapshotBackend::Btrfs
            }
        );
    }

    #[test]
    fn required_snapshot_fails_closed_without_backend() {
        let plan = plan_snapshot(SnapshotRequirement::Required, &[]);

        assert!(matches!(
            plan,
            SnapshotPlan::Block(message) if message.contains("snapshot required")
        ));
    }

    #[test]
    fn best_effort_snapshot_skips_plainly_without_backend() {
        let plan = plan_snapshot(SnapshotRequirement::BestEffort, &[]);

        assert!(matches!(
            plan,
            SnapshotPlan::Skip(message) if message.contains("unavailable")
        ));
    }

    #[test]
    fn disabled_snapshot_is_not_requested() {
        let plan = plan_snapshot(SnapshotRequirement::Disabled, &[SnapshotBackend::Btrfs]);

        assert_eq!(plan, SnapshotPlan::NotRequested);
    }

    #[test]
    fn unsupported_snapshot_driver_reports_create_without_claiming_snapshot() {
        let driver = UnsupportedSnapshotDriver::new(
            SnapshotBackend::Btrfs,
            "btrfs subvolume creation is not wired yet",
        );
        let request = SnapshotCreateRequest {
            session_id: "session-1".to_string(),
            roots: vec![std::path::PathBuf::from("/tmp/project")],
        };

        let error = driver.create_snapshot(&request).unwrap_err();

        assert!(error.message.contains("btrfs"));
        assert!(error.message.contains("not wired yet"));
    }

    #[test]
    fn unsupported_snapshot_driver_reports_restore_without_claiming_revert() {
        let driver = UnsupportedSnapshotDriver::new(
            SnapshotBackend::OverlayFs,
            "overlayfs restore is not wired yet",
        );
        let request = SnapshotRestoreRequest {
            snapshot_id: "snap-1".to_string(),
        };

        let error = driver.restore_snapshot(&request).unwrap_err();

        assert!(error.message.contains("overlayfs"));
        assert!(error.message.contains("not wired yet"));
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingCommandRunner {
        commands: RecordedCommands,
        fail_with: Option<String>,
    }

    type RecordedCommands = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>;

    impl RecordingCommandRunner {
        fn commands(&self) -> Vec<(String, Vec<String>)> {
            self.commands.lock().unwrap().clone()
        }
    }

    impl SnapshotCommandRunner for RecordingCommandRunner {
        fn run(&self, program: &str, args: &[String]) -> Result<(), SnapshotError> {
            self.commands
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            match &self.fail_with {
                Some(message) => Err(SnapshotError {
                    message: message.clone(),
                }),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn btrfs_snapshot_driver_creates_readonly_snapshots_for_each_root() {
        let runner = RecordingCommandRunner::default();
        let driver = BtrfsSnapshotDriver::new("/tmp/warder-snapshots", runner.clone());
        let request = SnapshotCreateRequest {
            session_id: "session-1".to_string(),
            roots: vec![
                std::path::PathBuf::from("/tmp/project"),
                std::path::PathBuf::from("/tmp/notes"),
            ],
        };

        let outcome = driver.create_snapshot(&request).unwrap();

        assert_eq!(outcome.backend, SnapshotBackend::Btrfs);
        assert_eq!(outcome.snapshot_id, "session-1-btrfs");
        assert_eq!(
            runner.commands(),
            vec![
                (
                    "btrfs".to_string(),
                    vec![
                        "subvolume".to_string(),
                        "snapshot".to_string(),
                        "-r".to_string(),
                        "/tmp/project".to_string(),
                        "/tmp/warder-snapshots/session-1-btrfs/project".to_string(),
                    ],
                ),
                (
                    "btrfs".to_string(),
                    vec![
                        "subvolume".to_string(),
                        "snapshot".to_string(),
                        "-r".to_string(),
                        "/tmp/notes".to_string(),
                        "/tmp/warder-snapshots/session-1-btrfs/notes".to_string(),
                    ],
                ),
            ]
        );
    }

    #[test]
    fn btrfs_snapshot_driver_disambiguates_duplicate_root_names() {
        let runner = RecordingCommandRunner::default();
        let driver = BtrfsSnapshotDriver::new("/tmp/warder-snapshots", runner.clone());
        let request = SnapshotCreateRequest {
            session_id: "session-1".to_string(),
            roots: vec![
                std::path::PathBuf::from("/tmp/one/project"),
                std::path::PathBuf::from("/tmp/two/project"),
            ],
        };

        driver.create_snapshot(&request).unwrap();

        let commands = runner.commands();
        assert_eq!(
            commands[0].1[4],
            "/tmp/warder-snapshots/session-1-btrfs/project"
        );
        assert_eq!(
            commands[1].1[4],
            "/tmp/warder-snapshots/session-1-btrfs/project-2"
        );
    }

    #[test]
    fn btrfs_snapshot_driver_fails_plainly_without_claiming_snapshot() {
        let runner = RecordingCommandRunner {
            fail_with: Some("btrfs command failed".to_string()),
            ..RecordingCommandRunner::default()
        };
        let driver = BtrfsSnapshotDriver::new("/tmp/warder-snapshots", runner);
        let request = SnapshotCreateRequest {
            session_id: "session-1".to_string(),
            roots: vec![std::path::PathBuf::from("/tmp/project")],
        };

        let error = driver.create_snapshot(&request).unwrap_err();

        assert!(error.message.contains("btrfs snapshot creation failed"));
        assert!(error.message.contains("btrfs command failed"));
    }

    #[test]
    fn btrfs_snapshot_driver_rejects_malicious_session_ids_before_path_join() {
        let snapshot_root = temp_snapshot_root("create-invalid-session-id");
        let driver = BtrfsSnapshotDriver::new(&snapshot_root, RecordingCommandRunner::default());
        let request = SnapshotCreateRequest {
            session_id: "../escape".to_string(),
            roots: vec![std::path::PathBuf::from("/tmp/project")],
        };

        let error = driver.create_snapshot(&request).unwrap_err();

        assert!(error.message.contains("invalid snapshot id"));
        assert!(!snapshot_root.join("../escape-btrfs").exists());
    }

    #[test]
    fn btrfs_snapshot_driver_writes_restore_manifest() {
        let snapshot_root = temp_snapshot_root("manifest");
        let runner = RecordingCommandRunner::default();
        let driver = BtrfsSnapshotDriver::new(&snapshot_root, runner);
        let request = SnapshotCreateRequest {
            session_id: "session-1".to_string(),
            roots: vec![std::path::PathBuf::from("/tmp/project")],
        };

        let outcome = driver.create_snapshot(&request).unwrap();

        let manifest = std::fs::read_to_string(
            snapshot_root
                .join(&outcome.snapshot_id)
                .join("manifest.json"),
        )
        .unwrap();
        assert!(manifest.contains("\"snapshot_id\":\"session-1-btrfs\""));
        assert!(manifest.contains("\"source_root\":\"/tmp/project\""));
        let expected_snapshot_path = format!(
            "\"snapshot_path\":\"{}\"",
            snapshot_root
                .join("session-1-btrfs")
                .join("project")
                .display()
        );
        assert!(manifest.contains(&expected_snapshot_path));
    }

    #[test]
    fn load_snapshot_manifest_reads_persisted_manifest() {
        let snapshot_root = temp_snapshot_root("load-manifest");
        let runner = RecordingCommandRunner::default();
        let driver = BtrfsSnapshotDriver::new(&snapshot_root, runner);
        let request = SnapshotCreateRequest {
            session_id: "session-1".to_string(),
            roots: vec![std::path::PathBuf::from("/tmp/project")],
        };
        driver.create_snapshot(&request).unwrap();

        let manifest = load_snapshot_manifest(&snapshot_root, "session-1-btrfs").unwrap();

        assert_eq!(manifest.snapshot_id, "session-1-btrfs");
        assert_eq!(manifest.backend, "btrfs");
        assert_eq!(manifest.entries[0].source_root, "/tmp/project");
    }

    #[test]
    fn load_snapshot_manifest_reports_missing_snapshot_plainly() {
        let snapshot_root = temp_snapshot_root("missing-manifest");

        let error = load_snapshot_manifest(&snapshot_root, "missing").unwrap_err();

        assert!(error.message.contains("snapshot manifest unavailable"));
        assert!(error.message.contains("missing"));
    }

    #[test]
    fn load_snapshot_manifest_rejects_mismatched_manifest_id() {
        let snapshot_root = temp_snapshot_root("mismatched-manifest-id");
        let snapshot_dir = snapshot_root.join("snap-1");
        let snapshot_path = snapshot_dir.join("project");
        let source_root = snapshot_root.join("restore").join("project");
        std::fs::create_dir_all(&snapshot_path).unwrap();
        std::fs::create_dir_all(source_root.parent().unwrap()).unwrap();
        std::fs::write(
            snapshot_dir.join("manifest.json"),
            format!(
                r#"{{"snapshot_id":"snap-2","backend":"btrfs","entries":[{{"source_root":"{}","snapshot_path":"{}"}}]}}"#,
                source_root.display(),
                snapshot_path.display()
            ),
        )
        .unwrap();

        let error = load_snapshot_manifest(&snapshot_root, "snap-1").unwrap_err();

        assert!(error
            .message
            .contains("manifest declares snapshot id 'snap-2'"));
    }

    #[test]
    fn load_snapshot_manifest_rejects_relative_or_traversing_entries() {
        for (name, source_root, snapshot_path, expected) in [
            (
                "relative-source",
                "restore/project",
                "/tmp/snapshot/project",
                "source_root 'restore/project' must be absolute",
            ),
            (
                "relative-snapshot",
                "/tmp/restore/project",
                "snapshots/project",
                "snapshot_path 'snapshots/project' must be absolute",
            ),
            (
                "traversing-source",
                "/tmp/restore/../project",
                "/tmp/snapshot/project",
                "source_root '/tmp/restore/../project' must not contain parent traversal",
            ),
            (
                "traversing-snapshot",
                "/tmp/restore/project",
                "/tmp/snapshot/../project",
                "snapshot_path '/tmp/snapshot/../project' must not contain parent traversal",
            ),
            (
                "nul-source",
                "/tmp/restore/\\u0000project",
                "/tmp/snapshot/project",
                "source_root must not contain NUL bytes",
            ),
            (
                "nul-snapshot",
                "/tmp/restore/project",
                "/tmp/snapshot/\\u0000project",
                "snapshot_path must not contain NUL bytes",
            ),
        ] {
            let snapshot_root = temp_snapshot_root(name);
            let snapshot_dir = snapshot_root.join("snap-1");
            std::fs::create_dir_all(&snapshot_dir).unwrap();
            std::fs::write(
                snapshot_dir.join("manifest.json"),
                format!(
                    r#"{{"snapshot_id":"snap-1","backend":"btrfs","entries":[{{"source_root":"{source_root}","snapshot_path":"{snapshot_path}"}}]}}"#
                ),
            )
            .unwrap();

            let error = load_snapshot_manifest(&snapshot_root, "snap-1").unwrap_err();

            assert!(
                error.message.contains(expected),
                "expected {expected:?}, got {:?}",
                error.message
            );
        }
    }

    #[test]
    fn load_snapshot_manifest_rejects_invalid_snapshot_ids_before_path_join() {
        let snapshot_root = temp_snapshot_root("invalid-snapshot-id");
        for snapshot_id in ["", "../escape", "nested/snap", "/tmp/snap", "snap.1"] {
            let error = load_snapshot_manifest(&snapshot_root, snapshot_id).unwrap_err();

            assert!(error.message.contains("invalid snapshot id"));
        }
    }

    #[test]
    fn btrfs_snapshot_driver_rejects_invalid_snapshot_ids_before_restore() {
        let snapshot_root = temp_snapshot_root("restore-invalid-snapshot-id");
        let driver = BtrfsSnapshotDriver::new(snapshot_root, RecordingCommandRunner::default());

        let error = driver
            .restore_snapshot(&SnapshotRestoreRequest {
                snapshot_id: "../escape".to_string(),
            })
            .unwrap_err();

        assert!(error.message.contains("invalid snapshot id"));
    }

    #[test]
    fn btrfs_snapshot_driver_restores_missing_roots_from_manifest() {
        let snapshot_root = temp_snapshot_root("restore-missing");
        let snapshot_dir = snapshot_root.join("snap-1");
        let snapshot_path = snapshot_dir.join("project");
        std::fs::create_dir_all(&snapshot_path).unwrap();
        let source_root = snapshot_root.join("restored").join("project");
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
        let runner = RecordingCommandRunner::default();
        let driver = BtrfsSnapshotDriver::new(&snapshot_root, runner.clone());

        let outcome = driver
            .restore_snapshot(&SnapshotRestoreRequest {
                snapshot_id: "snap-1".to_string(),
            })
            .unwrap();

        assert_eq!(outcome.backend, SnapshotBackend::Btrfs);
        assert_eq!(outcome.snapshot_id, "snap-1");
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
    fn btrfs_snapshot_driver_refuses_to_restore_over_existing_root() {
        let snapshot_root = temp_snapshot_root("restore-existing");
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
        let runner = RecordingCommandRunner::default();
        let driver = BtrfsSnapshotDriver::new(&snapshot_root, runner.clone());

        let error = driver
            .restore_snapshot(&SnapshotRestoreRequest {
                snapshot_id: "snap-1".to_string(),
            })
            .unwrap_err();

        assert!(error
            .message
            .contains("refusing to restore over existing path"));
        assert!(runner.commands().is_empty());
    }

    fn temp_snapshot_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "warder-snapshot-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }
}
