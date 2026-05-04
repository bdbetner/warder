use std::path::{Path, PathBuf};
use warder_core::SnapshotBackend;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityState {
    Available,
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityProbe {
    pub landlock: CapabilityState,
    pub cgroups: CapabilityState,
    pub btrfs: CapabilityState,
    pub overlayfs: CapabilityState,
    pub ebpf: CapabilityState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProbePaths {
    pub landlock_abi: PathBuf,
    pub cgroup_procs: PathBuf,
    pub mounts: PathBuf,
    pub bpf_fs: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonCapabilityReport {
    pub enforcement_ready: bool,
    pub snapshot_backends: Vec<SnapshotBackend>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonStartRequest {
    pub pid: u32,
    pub socket_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonRuntimeReport {
    pub status: DaemonRuntimeStatus,
    pub pid: Option<u32>,
    pub socket_path: Option<PathBuf>,
    pub message: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DaemonRuntimeStatus {
    Running,
    Stopped,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DaemonRunner {
    running: Option<DaemonStartRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonCoordinator {
    start_request: DaemonStartRequest,
    policy: Option<DaemonPolicySnapshot>,
    tick_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonPolicySnapshot {
    pub zone_count: usize,
    pub agent_count: usize,
    pub network_journal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonCoordinatorTick {
    pub tick_count: u64,
    pub enforcement_ready: bool,
    pub degraded_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonRuntimeFile {
    path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonRuntimeFileError {
    pub message: String,
}

impl DaemonCapabilityReport {
    pub fn from_probe(probe: CapabilityProbe) -> Self {
        let mut degraded_reasons = Vec::new();
        push_unavailable("Landlock", &probe.landlock, &mut degraded_reasons);
        push_unavailable("cgroups", &probe.cgroups, &mut degraded_reasons);
        push_unavailable("eBPF", &probe.ebpf, &mut degraded_reasons);

        let mut snapshot_backends = Vec::new();
        if probe.btrfs == CapabilityState::Available {
            snapshot_backends.push(SnapshotBackend::Btrfs);
        }
        if snapshot_backends.is_empty() {
            push_unavailable("Btrfs snapshots", &probe.btrfs, &mut degraded_reasons);
            match &probe.overlayfs {
                CapabilityState::Available => degraded_reasons
                    .push("OverlayFS snapshot backend driver is not implemented yet".to_string()),
                CapabilityState::Unavailable(_) => {
                    push_unavailable(
                        "OverlayFS snapshots",
                        &probe.overlayfs,
                        &mut degraded_reasons,
                    );
                }
            }
        }

        Self {
            enforcement_ready: probe.landlock == CapabilityState::Available
                && probe.cgroups == CapabilityState::Available,
            snapshot_backends,
            degraded_reasons,
        }
    }
}

impl DaemonRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn start(&mut self, request: DaemonStartRequest) -> DaemonRuntimeReport {
        if let Some(current) = &self.running {
            return DaemonRuntimeReport {
                status: DaemonRuntimeStatus::Running,
                pid: Some(current.pid),
                socket_path: Some(current.socket_path.clone()),
                message: format!("daemon already running with pid {}", current.pid),
            };
        }

        let report = DaemonRuntimeReport {
            status: DaemonRuntimeStatus::Running,
            pid: Some(request.pid),
            socket_path: Some(request.socket_path.clone()),
            message: format!("daemon started with pid {}", request.pid),
        };
        self.running = Some(request);
        report
    }

    pub fn stop(&mut self) -> DaemonRuntimeReport {
        let Some(current) = self.running.take() else {
            return DaemonRuntimeReport {
                status: DaemonRuntimeStatus::Stopped,
                pid: None,
                socket_path: None,
                message: "daemon is not running".to_string(),
            };
        };

        DaemonRuntimeReport {
            status: DaemonRuntimeStatus::Stopped,
            pid: Some(current.pid),
            socket_path: Some(current.socket_path),
            message: format!("daemon stopped from pid {}", current.pid),
        }
    }

    pub fn status(&self) -> DaemonRuntimeReport {
        match &self.running {
            Some(current) => DaemonRuntimeReport {
                status: DaemonRuntimeStatus::Running,
                pid: Some(current.pid),
                socket_path: Some(current.socket_path.clone()),
                message: format!("daemon running with pid {}", current.pid),
            },
            None => DaemonRuntimeReport {
                status: DaemonRuntimeStatus::Stopped,
                pid: None,
                socket_path: None,
                message: "daemon is not running".to_string(),
            },
        }
    }
}

impl DaemonCoordinator {
    pub fn new(start_request: DaemonStartRequest, policy: Option<DaemonPolicySnapshot>) -> Self {
        Self {
            start_request,
            policy,
            tick_count: 0,
        }
    }

    pub fn runtime_report(&self) -> DaemonRuntimeReport {
        DaemonRuntimeReport {
            status: DaemonRuntimeStatus::Running,
            pid: Some(self.start_request.pid),
            socket_path: Some(self.start_request.socket_path.clone()),
            message: self.runtime_message(),
        }
    }

    pub fn tick(&mut self, probe: CapabilityProbe) -> DaemonCoordinatorTick {
        self.tick_count += 1;
        let report = DaemonCapabilityReport::from_probe(probe);
        DaemonCoordinatorTick {
            tick_count: self.tick_count,
            enforcement_ready: report.enforcement_ready,
            degraded_reasons: report.degraded_reasons,
        }
    }

    fn runtime_message(&self) -> String {
        let base = format!("daemon running with pid {}", self.start_request.pid);
        match &self.policy {
            Some(policy) => format!(
                "{base}; loaded {} protected zone(s), {} agent(s), network journal {}",
                policy.zone_count,
                policy.agent_count,
                if policy.network_journal {
                    "requested"
                } else {
                    "not requested"
                }
            ),
            None => format!("{base}; no policy config loaded"),
        }
    }
}

impl DaemonRuntimeFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn read_status(&self) -> Result<DaemonRuntimeReport, DaemonRuntimeFileError> {
        let contents = match std::fs::read_to_string(&self.path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DaemonRuntimeReport {
                    status: DaemonRuntimeStatus::Stopped,
                    pid: None,
                    socket_path: None,
                    message: "daemon is not running".to_string(),
                });
            }
            Err(error) => {
                return Err(runtime_file_error(format!(
                    "failed to read daemon runtime file '{}': {error}",
                    self.path.display()
                )));
            }
        };

        let report = parse_runtime_file(&contents)?;
        if matches!(report.status, DaemonRuntimeStatus::Running)
            && report
                .pid
                .map(|pid| !process_is_alive(pid))
                .unwrap_or(false)
        {
            let _ = self.clear();
            return Ok(DaemonRuntimeReport {
                status: DaemonRuntimeStatus::Stopped,
                pid: None,
                socket_path: None,
                message: "daemon is not running; removed stale runtime file".to_string(),
            });
        }
        Ok(report)
    }

    pub fn write_status(&self, report: &DaemonRuntimeReport) -> Result<(), DaemonRuntimeFileError> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                runtime_file_error(format!(
                    "failed to create daemon runtime directory '{}': {error}",
                    parent.display()
                ))
            })?;
        }
        let temp_path = self.path.with_extension(format!(
            "{}.tmp-{}",
            self.path
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or("state"),
            std::process::id()
        ));
        std::fs::write(&temp_path, render_runtime_file(report)).map_err(|error| {
            runtime_file_error(format!(
                "failed to write daemon runtime file '{}': {error}",
                temp_path.display()
            ))
        })?;
        std::fs::rename(&temp_path, &self.path).map_err(|error| {
            runtime_file_error(format!(
                "failed to write daemon runtime file '{}': {error}",
                self.path.display()
            ))
        })
    }

    pub fn clear(&self) -> Result<(), DaemonRuntimeFileError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(runtime_file_error(format!(
                "failed to remove daemon runtime file '{}': {error}",
                self.path.display()
            ))),
        }
    }
}

pub fn render_status(report: &DaemonCapabilityReport) -> String {
    let enforcement = if report.enforcement_ready {
        "ready"
    } else {
        "degraded"
    };
    let snapshots = if report.snapshot_backends.is_empty() {
        "none".to_string()
    } else {
        report
            .snapshot_backends
            .iter()
            .map(snapshot_backend_label)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut lines = vec![
        format!("enforcement: {enforcement}"),
        format!("snapshot backends: {snapshots}"),
    ];
    if report.degraded_reasons.is_empty() {
        lines.push("degraded reasons: none".to_string());
    } else {
        lines.push("degraded reasons:".to_string());
        lines.extend(
            report
                .degraded_reasons
                .iter()
                .map(|reason| format!("- {reason}")),
        );
    }
    lines.join("\n")
}

pub fn render_daemon_runtime_report(report: &DaemonRuntimeReport) -> String {
    let status = match report.status {
        DaemonRuntimeStatus::Running => "running",
        DaemonRuntimeStatus::Stopped => "stopped",
    };
    let mut lines = vec![
        format!("daemon: {status}"),
        format!(
            "pid: {}",
            report
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        format!(
            "socket: {}",
            report
                .socket_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
    ];
    if !report.message.is_empty() {
        lines.push(format!("message: {}", report.message));
    }
    lines.join("\n")
}

pub fn probe_current_host() -> CapabilityProbe {
    probe_host_paths(&HostProbePaths {
        landlock_abi: PathBuf::from("/sys/kernel/security/landlock/abi"),
        cgroup_procs: PathBuf::from("/sys/fs/cgroup/cgroup.procs"),
        mounts: PathBuf::from("/proc/mounts"),
        bpf_fs: PathBuf::from("/sys/fs/bpf"),
    })
}

pub fn probe_host_paths(paths: &HostProbePaths) -> CapabilityProbe {
    let mounts = std::fs::read_to_string(&paths.mounts).unwrap_or_default();
    CapabilityProbe {
        landlock: probe_landlock_abi(&paths.landlock_abi),
        cgroups: path_available(&paths.cgroup_procs, "cgroup v2 root is unavailable"),
        btrfs: filesystem_available(&mounts, "btrfs", "Btrfs filesystem is unavailable"),
        overlayfs: filesystem_available(&mounts, "overlay", "OverlayFS filesystem is unavailable"),
        ebpf: probe_bpffs_access(&paths.bpf_fs),
    }
}

fn snapshot_backend_label(backend: &SnapshotBackend) -> &'static str {
    match backend {
        SnapshotBackend::Btrfs => "btrfs",
        SnapshotBackend::OverlayFs => "overlayfs",
    }
}

fn push_unavailable(label: &str, state: &CapabilityState, degraded_reasons: &mut Vec<String>) {
    if let CapabilityState::Unavailable(reason) = state {
        degraded_reasons.push(format!("{label} unavailable: {reason}"));
    }
}

fn probe_landlock_abi(path: &Path) -> CapabilityState {
    probe_landlock_abi_with_syscall(path, query_landlock_abi_version)
}

fn probe_landlock_abi_with_syscall<F>(path: &Path, syscall_probe: F) -> CapabilityState
where
    F: FnOnce() -> Result<u32, String>,
{
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.trim().parse::<u32>().unwrap_or(0) > 0 => {
            CapabilityState::Available
        }
        Ok(_) => CapabilityState::Unavailable("Landlock ABI is not enabled".to_string()),
        Err(path_error) => match syscall_probe() {
            Ok(version) if version > 0 => CapabilityState::Available,
            Ok(_) => CapabilityState::Unavailable("Landlock ABI is not enabled".to_string()),
            Err(syscall_error) => CapabilityState::Unavailable(format!(
                "Landlock ABI path is unavailable ({path_error}); syscall version probe failed: {syscall_error}"
            )),
        },
    }
}

#[cfg(target_os = "linux")]
fn query_landlock_abi_version() -> Result<u32, String> {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if result > 0 {
        Ok(result as u32)
    } else if result == 0 {
        Ok(0)
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(not(target_os = "linux"))]
fn query_landlock_abi_version() -> Result<u32, String> {
    Err("Landlock is Linux-only".to_string())
}

fn filesystem_available(mounts: &str, filesystem: &str, reason: &str) -> CapabilityState {
    if mounts
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .any(|kind| kind == filesystem)
    {
        CapabilityState::Available
    } else {
        CapabilityState::Unavailable(reason.to_string())
    }
}

fn path_available(path: &Path, reason: &str) -> CapabilityState {
    if path.exists() {
        CapabilityState::Available
    } else {
        CapabilityState::Unavailable(reason.to_string())
    }
}

fn probe_bpffs_access(path: &Path) -> CapabilityState {
    if !path.exists() {
        return CapabilityState::Unavailable("bpffs is unavailable".to_string());
    }
    if !path.is_dir() {
        return CapabilityState::Unavailable(format!(
            "bpffs path '{}' is not a directory",
            path.display()
        ));
    }
    if let Err(error) = std::fs::read_dir(path) {
        return CapabilityState::Unavailable(format!(
            "bpffs path '{}' is not readable: {error}",
            path.display()
        ));
    }

    CapabilityState::Available
}

fn render_runtime_file(report: &DaemonRuntimeReport) -> String {
    let status = match report.status {
        DaemonRuntimeStatus::Running => "running",
        DaemonRuntimeStatus::Stopped => "stopped",
    };
    format!(
        "status={status}\npid={}\nsocket={}\nmessage={}\n",
        report.pid.map(|pid| pid.to_string()).unwrap_or_default(),
        report
            .socket_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        report.message.replace('\n', " ")
    )
}

fn parse_runtime_file(contents: &str) -> Result<DaemonRuntimeReport, DaemonRuntimeFileError> {
    let mut status = None;
    let mut pid = None;
    let mut socket_path = None;
    let mut message = None;

    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "status" => {
                status = Some(match value {
                    "running" => DaemonRuntimeStatus::Running,
                    "stopped" => DaemonRuntimeStatus::Stopped,
                    unknown => {
                        return Err(runtime_file_error(format!(
                            "invalid daemon runtime status '{unknown}'"
                        )));
                    }
                });
            }
            "pid" if !value.is_empty() => {
                pid = Some(value.parse::<u32>().map_err(|_| {
                    runtime_file_error(format!("invalid daemon runtime pid '{value}'"))
                })?);
            }
            "socket" if !value.is_empty() => socket_path = Some(PathBuf::from(value)),
            "message" => message = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(DaemonRuntimeReport {
        status: status.unwrap_or(DaemonRuntimeStatus::Stopped),
        pid,
        socket_path,
        message: message.unwrap_or_else(|| "daemon is not running".to_string()),
    })
}

#[cfg(target_os = "linux")]
fn process_is_alive(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

#[cfg(not(target_os = "linux"))]
fn process_is_alive(_pid: u32) -> bool {
    true
}

fn runtime_file_error(message: impl Into<String>) -> DaemonRuntimeFileError {
    DaemonRuntimeFileError {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_report_lists_degraded_required_features() {
        let report = DaemonCapabilityReport::from_probe(CapabilityProbe {
            landlock: CapabilityState::Unavailable("kernel does not expose Landlock".to_string()),
            cgroups: CapabilityState::Available,
            btrfs: CapabilityState::Unavailable("path is not on Btrfs".to_string()),
            overlayfs: CapabilityState::Unavailable("overlayfs not mounted".to_string()),
            ebpf: CapabilityState::Unavailable("missing CAP_BPF".to_string()),
        });

        assert!(!report.enforcement_ready);
        assert!(report
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("Landlock")));
        assert_eq!(report.snapshot_backends, Vec::<SnapshotBackend>::new());
    }

    #[test]
    fn capability_report_discovers_supported_snapshot_backends() {
        let report = DaemonCapabilityReport::from_probe(CapabilityProbe {
            landlock: CapabilityState::Available,
            cgroups: CapabilityState::Available,
            btrfs: CapabilityState::Available,
            overlayfs: CapabilityState::Unavailable("overlayfs not mounted".to_string()),
            ebpf: CapabilityState::Available,
        });

        assert!(report.enforcement_ready);
        assert_eq!(report.snapshot_backends, vec![SnapshotBackend::Btrfs]);
        assert!(report.degraded_reasons.is_empty());
    }

    #[test]
    fn capability_report_does_not_claim_overlayfs_snapshot_driver_support() {
        let report = DaemonCapabilityReport::from_probe(CapabilityProbe {
            landlock: CapabilityState::Available,
            cgroups: CapabilityState::Available,
            btrfs: CapabilityState::Unavailable("not btrfs".to_string()),
            overlayfs: CapabilityState::Available,
            ebpf: CapabilityState::Available,
        });

        assert!(report.enforcement_ready);
        assert_eq!(report.snapshot_backends, Vec::<SnapshotBackend>::new());
        assert!(report
            .degraded_reasons
            .iter()
            .any(|reason| reason
                .contains("OverlayFS snapshot backend driver is not implemented yet")));

        let status = render_status(&report);
        assert!(status.contains("snapshot backends: none"));
        assert!(status.contains("OverlayFS snapshot backend driver is not implemented yet"));
    }

    #[test]
    fn renders_readable_degraded_status() {
        let report = DaemonCapabilityReport::from_probe(CapabilityProbe {
            landlock: CapabilityState::Unavailable("missing".to_string()),
            cgroups: CapabilityState::Available,
            btrfs: CapabilityState::Unavailable("not btrfs".to_string()),
            overlayfs: CapabilityState::Unavailable("not overlayfs".to_string()),
            ebpf: CapabilityState::Unavailable("missing bpffs".to_string()),
        });

        let status = render_status(&report);

        assert!(status.contains("enforcement: degraded"));
        assert!(status.contains("snapshot backends: none"));
        assert!(status.contains("Landlock unavailable"));
    }

    #[test]
    fn probe_host_paths_detects_available_landlock_cgroups_btrfs_and_bpf() {
        let root = temp_dir("available");
        std::fs::create_dir_all(root.join("landlock")).unwrap();
        std::fs::write(root.join("landlock/abi"), "3\n").unwrap();
        std::fs::create_dir_all(root.join("cgroup")).unwrap();
        std::fs::write(root.join("cgroup/cgroup.procs"), "").unwrap();
        std::fs::write(
            root.join("mounts"),
            "none /sys/fs/bpf bpf rw 0 0\n/dev/sda /home btrfs rw 0 0\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("bpf")).unwrap();

        let probe = probe_host_paths(&HostProbePaths {
            landlock_abi: root.join("landlock/abi"),
            cgroup_procs: root.join("cgroup/cgroup.procs"),
            mounts: root.join("mounts"),
            bpf_fs: root.join("bpf"),
        });

        assert_eq!(probe.landlock, CapabilityState::Available);
        assert_eq!(probe.cgroups, CapabilityState::Available);
        assert_eq!(probe.btrfs, CapabilityState::Available);
        assert_eq!(probe.ebpf, CapabilityState::Available);
    }

    #[test]
    fn landlock_probe_falls_back_to_syscall_version_when_abi_file_is_absent() {
        let root = temp_dir("landlock-syscall-fallback");

        let state = probe_landlock_abi_with_syscall(&root.join("missing-abi"), || Ok(8));

        assert_eq!(state, CapabilityState::Available);
    }

    #[test]
    fn landlock_probe_reports_both_path_and_syscall_failures() {
        let root = temp_dir("landlock-syscall-failure");

        let state =
            probe_landlock_abi_with_syscall(
                &root.join("missing-abi"),
                || Err("ENOSYS".to_string()),
            );

        assert!(
            matches!(state, CapabilityState::Unavailable(message) if message.contains("path is unavailable") && message.contains("ENOSYS"))
        );
    }

    #[test]
    fn probe_host_paths_reports_degraded_reasons_for_missing_support() {
        let root = temp_dir("missing");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("mounts"), "tmpfs /tmp tmpfs rw 0 0\n").unwrap();

        let probe = probe_host_paths(&HostProbePaths {
            landlock_abi: root.join("missing-landlock-abi"),
            cgroup_procs: root.join("missing-cgroup.procs"),
            mounts: root.join("mounts"),
            bpf_fs: root.join("missing-bpf"),
        });

        if let CapabilityState::Unavailable(message) = probe.landlock {
            assert!(message.contains("Landlock"));
        }
        assert!(
            matches!(probe.cgroups, CapabilityState::Unavailable(message) if message.contains("cgroup"))
        );
        assert!(
            matches!(probe.btrfs, CapabilityState::Unavailable(message) if message.contains("Btrfs"))
        );
        assert!(
            matches!(probe.overlayfs, CapabilityState::Unavailable(message) if message.contains("OverlayFS"))
        );
        assert!(
            matches!(probe.ebpf, CapabilityState::Unavailable(message) if message.contains("bpffs"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_host_paths_reports_unreadable_bpffs_plainly() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("unreadable-bpf");
        std::fs::create_dir_all(root.join("landlock")).unwrap();
        std::fs::write(root.join("landlock/abi"), "3\n").unwrap();
        std::fs::create_dir_all(root.join("cgroup")).unwrap();
        std::fs::write(root.join("cgroup/cgroup.procs"), "").unwrap();
        std::fs::write(root.join("mounts"), "tmpfs /tmp tmpfs rw 0 0\n").unwrap();
        let bpf = root.join("bpf");
        std::fs::create_dir_all(&bpf).unwrap();
        let original_permissions = std::fs::metadata(&bpf).unwrap().permissions();
        std::fs::set_permissions(&bpf, std::fs::Permissions::from_mode(0o000)).unwrap();

        let probe = probe_host_paths(&HostProbePaths {
            landlock_abi: root.join("landlock/abi"),
            cgroup_procs: root.join("cgroup/cgroup.procs"),
            mounts: root.join("mounts"),
            bpf_fs: bpf.clone(),
        });

        std::fs::set_permissions(&bpf, original_permissions).unwrap();

        assert!(
            matches!(probe.ebpf, CapabilityState::Unavailable(message) if message.contains("not readable"))
        );
    }

    #[test]
    fn daemon_runner_start_status_stop_cycle_is_explicit() {
        let mut runner = DaemonRunner::new();

        let started = runner.start(DaemonStartRequest {
            pid: 4242,
            socket_path: PathBuf::from("/run/user/1000/warder.sock"),
        });
        assert_eq!(started.status, DaemonRuntimeStatus::Running);
        assert_eq!(runner.status().pid, Some(4242));

        let stopped = runner.stop();
        assert_eq!(stopped.status, DaemonRuntimeStatus::Stopped);
        assert_eq!(runner.status().pid, None);
    }

    #[test]
    fn daemon_runner_rejects_duplicate_start_without_losing_original_pid() {
        let mut runner = DaemonRunner::new();
        runner.start(DaemonStartRequest {
            pid: 4242,
            socket_path: PathBuf::from("/run/user/1000/warder.sock"),
        });

        let duplicate = runner.start(DaemonStartRequest {
            pid: 5252,
            socket_path: PathBuf::from("/run/user/1000/warder-2.sock"),
        });

        assert_eq!(duplicate.status, DaemonRuntimeStatus::Running);
        assert_eq!(duplicate.pid, Some(4242));
        assert!(duplicate.message.contains("already running"));
        assert_eq!(runner.status().pid, Some(4242));
    }

    #[test]
    fn daemon_runner_stop_reports_when_not_running() {
        let mut runner = DaemonRunner::new();

        let stopped = runner.stop();

        assert_eq!(stopped.status, DaemonRuntimeStatus::Stopped);
        assert!(stopped.message.contains("not running"));
    }

    #[test]
    fn daemon_coordinator_reports_runtime_identity_and_capability_ticks() {
        let mut coordinator = DaemonCoordinator::new(
            DaemonStartRequest {
                pid: 4242,
                socket_path: PathBuf::from("/tmp/warder.sock"),
            },
            Some(DaemonPolicySnapshot {
                zone_count: 2,
                agent_count: 1,
                network_journal: true,
            }),
        );

        let report = coordinator.runtime_report();
        assert_eq!(report.pid, Some(4242));
        assert_eq!(report.status, DaemonRuntimeStatus::Running);
        assert!(report.message.contains("2 protected zone"));
        assert!(report.message.contains("network journal requested"));

        let tick = coordinator.tick(CapabilityProbe {
            landlock: CapabilityState::Available,
            cgroups: CapabilityState::Available,
            btrfs: CapabilityState::Unavailable("not btrfs".to_string()),
            overlayfs: CapabilityState::Unavailable("not overlayfs".to_string()),
            ebpf: CapabilityState::Available,
        });

        assert_eq!(tick.tick_count, 1);
        assert!(tick.enforcement_ready);
        assert!(tick
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("Btrfs")));
    }

    #[test]
    fn daemon_runtime_file_round_trips_running_state() {
        let path = temp_dir("runtime-file").join("daemon.state");
        let store = DaemonRuntimeFile::new(&path);
        let pid = std::process::id();
        let report = DaemonRuntimeReport {
            status: DaemonRuntimeStatus::Running,
            pid: Some(pid),
            socket_path: Some(PathBuf::from("/run/user/1000/warder.sock")),
            message: format!("daemon running with pid {pid}"),
        };

        store.write_status(&report).unwrap();
        let loaded = store.read_status().unwrap();

        assert_eq!(loaded.status, DaemonRuntimeStatus::Running);
        assert_eq!(loaded.pid, Some(pid));
        assert_eq!(
            loaded.socket_path,
            Some(PathBuf::from("/run/user/1000/warder.sock"))
        );
    }

    #[test]
    fn daemon_runtime_file_write_is_atomic_and_cleans_temp_file() {
        let dir = temp_dir("runtime-file-atomic");
        let path = dir.join("daemon.state");
        let store = DaemonRuntimeFile::new(&path);
        let report = DaemonRuntimeReport {
            status: DaemonRuntimeStatus::Stopped,
            pid: None,
            socket_path: None,
            message: "daemon is not running".to_string(),
        };

        store.write_status(&report).unwrap();

        assert!(path.exists());
        let temp_files = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(temp_files, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_runtime_file_clears_stale_running_pid() {
        let path = temp_dir("runtime-file-stale-pid").join("daemon.state");
        let store = DaemonRuntimeFile::new(&path);
        let report = DaemonRuntimeReport {
            status: DaemonRuntimeStatus::Running,
            pid: Some(u32::MAX),
            socket_path: Some(PathBuf::from("/run/user/1000/warder.sock")),
            message: "daemon running with pid 4294967295".to_string(),
        };
        store.write_status(&report).unwrap();

        let loaded = store.read_status().unwrap();

        assert_eq!(loaded.status, DaemonRuntimeStatus::Stopped);
        assert!(loaded.message.contains("stale runtime file"));
        assert!(!path.exists());
    }

    #[test]
    fn daemon_runtime_file_reports_stopped_when_state_is_missing() {
        let path = temp_dir("missing-runtime-file").join("daemon.state");
        let store = DaemonRuntimeFile::new(&path);

        let loaded = store.read_status().unwrap();

        assert_eq!(loaded.status, DaemonRuntimeStatus::Stopped);
        assert!(loaded.message.contains("not running"));
    }

    #[test]
    fn render_daemon_runtime_report_is_human_readable() {
        let report = DaemonRuntimeReport {
            status: DaemonRuntimeStatus::Running,
            pid: Some(4242),
            socket_path: Some(PathBuf::from("/run/user/1000/warder.sock")),
            message: "daemon running with pid 4242".to_string(),
        };

        let rendered = render_daemon_runtime_report(&report);

        assert!(rendered.contains("daemon: running"));
        assert!(rendered.contains("pid: 4242"));
        assert!(rendered.contains("/run/user/1000/warder.sock"));
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("warder-host-probe-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        path
    }
}
