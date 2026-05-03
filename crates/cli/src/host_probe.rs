use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use warder_enforcement::{
    apply_supervised_seccomp_filter, LandlockAccess, LandlockPlanStatus, LandlockRequirement,
    LandlockRule, LandlockSupport, SyscallLandlockKernel,
};

use crate::{CliError, GLOBAL_SUPERVISION_LIMITATION};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostVerificationFormat {
    Text,
    Json,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostVerificationReport {
    pub checks: Vec<HostVerificationCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostVerificationCheck {
    pub id: &'static str,
    pub label: &'static str,
    pub status: &'static str,
    pub message: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InternalHostProbeKind {
    LandlockWrite,
    LandlockRead,
    SeccompEscape,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalHostProbeResult {
    pub passed: bool,
    pub message: String,
}

pub fn is_internal_host_probe_command<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .nth(1)
        .map(|arg| arg.as_ref() == "__warder-host-probe")
        .unwrap_or(false)
}

pub fn run_internal_host_probe_command<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    match parse_internal_host_probe_args(args)
        .and_then(|(kind, root)| run_internal_host_probe(kind, &root))
    {
        Ok(result) if result.passed => {
            println!("{}", result.message);
            0
        }
        Ok(result) => {
            eprintln!("{}", result.message);
            1
        }
        Err(error) => {
            eprintln!("{}", error.message);
            2
        }
    }
}

pub fn render_host_verification_from_probe(
    probe: warder_daemon::CapabilityProbe,
    format: HostVerificationFormat,
) -> Result<String, CliError> {
    render_host_verification_from_probe_with_runner(probe, format, run_internal_host_probe_child)
}

pub fn render_host_verification_from_probe_with_runner(
    probe: warder_daemon::CapabilityProbe,
    format: HostVerificationFormat,
    mut runner: impl FnMut(InternalHostProbeKind) -> InternalHostProbeResult,
) -> Result<String, CliError> {
    let report = assess_host_verification(probe, &mut runner);
    match format {
        HostVerificationFormat::Text => Ok(render_host_verification(&report)),
        HostVerificationFormat::Json => {
            serde_json::to_string_pretty(&report).map_err(|error| CliError {
                message: format!("failed to render host verification JSON: {error}"),
            })
        }
    }
}

fn parse_internal_host_probe_args<I, S>(
    args: I,
) -> Result<(InternalHostProbeKind, PathBuf), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    if args.len() < 2 || args[1] != "__warder-host-probe" {
        return Err(CliError {
            message: "internal host probe command is required".to_string(),
        });
    }
    args.drain(0..2);

    let mut kind = None;
    let mut root = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--kind" => {
                kind = Some(parse_internal_host_probe_kind(&value_after(
                    &args, index, "--kind",
                )?)?);
                index += 2;
            }
            "--root" => {
                root = Some(PathBuf::from(value_after(&args, index, "--root")?));
                index += 2;
            }
            unknown => {
                return Err(CliError {
                    message: format!("unknown internal host probe option '{unknown}'"),
                });
            }
        }
    }

    Ok((
        kind.ok_or_else(|| CliError {
            message: "internal host probe requires --kind".to_string(),
        })?,
        root.ok_or_else(|| CliError {
            message: "internal host probe requires --root".to_string(),
        })?,
    ))
}

fn value_after(options: &[String], index: usize, flag: &str) -> Result<String, CliError> {
    options.get(index + 1).cloned().ok_or_else(|| CliError {
        message: format!("{flag} requires a value"),
    })
}

fn parse_internal_host_probe_kind(value: &str) -> Result<InternalHostProbeKind, CliError> {
    match value {
        "landlock-write" => Ok(InternalHostProbeKind::LandlockWrite),
        "landlock-read" => Ok(InternalHostProbeKind::LandlockRead),
        "seccomp-escape" => Ok(InternalHostProbeKind::SeccompEscape),
        unknown => Err(CliError {
            message: format!("unknown internal host probe kind '{unknown}'"),
        }),
    }
}

fn internal_host_probe_kind_label(kind: InternalHostProbeKind) -> &'static str {
    match kind {
        InternalHostProbeKind::LandlockWrite => "landlock-write",
        InternalHostProbeKind::LandlockRead => "landlock-read",
        InternalHostProbeKind::SeccompEscape => "seccomp-escape",
    }
}

fn run_internal_host_probe_child(kind: InternalHostProbeKind) -> InternalHostProbeResult {
    let root = std::env::temp_dir().join(format!(
        "warder-host-probe-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let create_result = std::fs::create_dir_all(&root);
    if let Err(error) = create_result {
        return InternalHostProbeResult {
            passed: false,
            message: format!(
                "failed to create host-probe directory '{}': {error}",
                root.display()
            ),
        };
    }
    let output = std::env::current_exe()
        .map_err(|error| CliError {
            message: format!("failed to locate current Warder executable: {error}"),
        })
        .and_then(|executable| {
            Command::new(executable)
                .arg("__warder-host-probe")
                .arg("--kind")
                .arg(internal_host_probe_kind_label(kind))
                .arg("--root")
                .arg(&root)
                .output()
                .map_err(|error| CliError {
                    message: format!("failed to run internal host probe: {error}"),
                })
        });
    let _ = std::fs::remove_dir_all(&root);
    match output {
        Ok(output) if output.status.success() => InternalHostProbeResult {
            passed: true,
            message: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        },
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            InternalHostProbeResult {
                passed: false,
                message: if stderr.is_empty() {
                    format!("internal host probe exited with {}", output.status)
                } else {
                    stderr
                },
            }
        }
        Err(error) => InternalHostProbeResult {
            passed: false,
            message: error.message,
        },
    }
}

fn run_internal_host_probe(
    kind: InternalHostProbeKind,
    root: &Path,
) -> Result<InternalHostProbeResult, CliError> {
    match kind {
        InternalHostProbeKind::LandlockWrite => run_landlock_write_probe(root),
        InternalHostProbeKind::LandlockRead => run_landlock_read_probe(root),
        InternalHostProbeKind::SeccompEscape => run_seccomp_escape_probe(),
    }
}

fn setup_landlock_probe_paths(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf), CliError> {
    let protected = root.join("protected");
    let writable = root.join("writable");
    std::fs::create_dir_all(&protected).map_err(|error| CliError {
        message: format!(
            "failed to create protected probe path '{}': {error}",
            protected.display()
        ),
    })?;
    std::fs::create_dir_all(&writable).map_err(|error| CliError {
        message: format!(
            "failed to create writable probe path '{}': {error}",
            writable.display()
        ),
    })?;
    let secret = protected.join("secret.txt");
    std::fs::write(&secret, "secret\n").map_err(|error| CliError {
        message: format!(
            "failed to seed protected probe file '{}': {error}",
            secret.display()
        ),
    })?;
    Ok((protected, writable, secret))
}

fn apply_probe_landlock(
    protected: PathBuf,
    writable: PathBuf,
    protected_access: LandlockAccess,
) -> Result<InternalHostProbeResult, CliError> {
    let plan = warder_enforcement::plan_landlock_restrictions(
        LandlockRequirement::Required,
        LandlockSupport {
            kernel_available: true,
            apply_available: true,
        },
        vec![
            LandlockRule {
                path: protected,
                access: protected_access,
            },
            LandlockRule {
                path: writable,
                access: LandlockAccess::ReadWrite,
            },
        ],
    );
    if plan.status != LandlockPlanStatus::Apply {
        return Ok(InternalHostProbeResult {
            passed: false,
            message: format!(
                "Landlock probe plan did not apply: {}",
                landlock_plan_status_label(&plan.status)
            ),
        });
    }
    let mut kernel = SyscallLandlockKernel;
    warder_enforcement::apply_landlock_plan_with_kernel(&plan, &mut kernel).map_err(|error| {
        CliError {
            message: format!("failed to apply Landlock probe rules: {}", error.message),
        }
    })?;
    Ok(InternalHostProbeResult {
        passed: true,
        message: "Landlock probe rules applied".to_string(),
    })
}

fn run_landlock_write_probe(root: &Path) -> Result<InternalHostProbeResult, CliError> {
    let (protected, writable, secret) = setup_landlock_probe_paths(root)?;
    let applied = apply_probe_landlock(protected, writable.clone(), LandlockAccess::ReadOnly)?;
    if !applied.passed {
        return Ok(applied);
    }
    let protected_write = std::fs::write(&secret, "changed\n");
    let writable_write = std::fs::write(writable.join("allowed.txt"), "allowed\n");
    match (protected_write, writable_write) {
        (Err(error), Ok(())) if error.kind() == io::ErrorKind::PermissionDenied => {
            Ok(InternalHostProbeResult {
                passed: true,
                message: "protected write was denied and writable root remained writable"
                    .to_string(),
            })
        }
        (Ok(()), _) => Ok(InternalHostProbeResult {
            passed: false,
            message: "protected write unexpectedly succeeded".to_string(),
        }),
        (Err(error), _) => Ok(InternalHostProbeResult {
            passed: false,
            message: format!("protected write failed with unexpected error: {error}"),
        }),
    }
}

fn run_landlock_read_probe(root: &Path) -> Result<InternalHostProbeResult, CliError> {
    let (protected, writable, secret) = setup_landlock_probe_paths(root)?;
    let applied = apply_probe_landlock(protected, writable.clone(), LandlockAccess::NoAccess)?;
    if !applied.passed {
        return Ok(applied);
    }
    let protected_read = std::fs::read_to_string(&secret);
    let writable_write = std::fs::write(writable.join("allowed.txt"), "allowed\n");
    match (protected_read, writable_write) {
        (Err(error), Ok(())) if error.kind() == io::ErrorKind::PermissionDenied => {
            Ok(InternalHostProbeResult {
                passed: true,
                message: "protected read was denied and writable root remained writable"
                    .to_string(),
            })
        }
        (Ok(_), _) => Ok(InternalHostProbeResult {
            passed: false,
            message: "protected read unexpectedly succeeded".to_string(),
        }),
        (Err(error), _) => Ok(InternalHostProbeResult {
            passed: false,
            message: format!("protected read failed with unexpected error: {error}"),
        }),
    }
}

#[cfg(target_os = "linux")]
fn run_seccomp_escape_probe() -> Result<InternalHostProbeResult, CliError> {
    apply_supervised_seccomp_filter().map_err(|error| CliError {
        message: error.message,
    })?;
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode != libc::SECCOMP_MODE_FILTER as i32 {
        return Ok(InternalHostProbeResult {
            passed: false,
            message: "seccomp filter mode was not active after installation".to_string(),
        });
    }
    let result = unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWNS) };
    if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        Ok(InternalHostProbeResult {
            passed: true,
            message: format!(
                "seccomp filter is active and denies {}",
                warder_enforcement::supervised_seccomp_denied_syscalls().join(", ")
            ),
        })
    } else {
        Ok(InternalHostProbeResult {
            passed: false,
            message: "unshare(CLONE_NEWNS) was not denied with EPERM".to_string(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn run_seccomp_escape_probe() -> Result<InternalHostProbeResult, CliError> {
    Ok(InternalHostProbeResult {
        passed: false,
        message: "seccomp probe is only supported on Linux".to_string(),
    })
}

fn assess_host_verification(
    probe: warder_daemon::CapabilityProbe,
    runner: &mut impl FnMut(InternalHostProbeKind) -> InternalHostProbeResult,
) -> HostVerificationReport {
    let cgroup_check = match probe.cgroups {
        warder_daemon::CapabilityState::Available => HostVerificationCheck {
            id: "pre_exec_cgroup_attribution",
            label: "Pre-exec cgroup attribution",
            status: "configured/planned",
            message: "cgroup v2 is visible; supervised launches still need a delegated writable --cgroup-root to prove process-tree attribution".to_string(),
        },
        warder_daemon::CapabilityState::Unavailable(reason) => HostVerificationCheck {
            id: "pre_exec_cgroup_attribution",
            label: "Pre-exec cgroup attribution",
            status: "unsupported",
            message: reason,
        },
    };
    let btrfs_check = match probe.btrfs {
        warder_daemon::CapabilityState::Available => HostVerificationCheck {
            id: "btrfs_snapshot_support",
            label: "Btrfs snapshot support",
            status: "configured/planned",
            message: "a Btrfs filesystem is mounted; use a snapshot-root on that filesystem to prove create/revert for a specific project".to_string(),
        },
        warder_daemon::CapabilityState::Unavailable(reason) => HostVerificationCheck {
            id: "btrfs_snapshot_support",
            label: "Btrfs snapshot support",
            status: "unsupported",
            message: reason,
        },
    };
    let checks = vec![
        probed_check(
            "landlock_write_denial",
            "Landlock write denial",
            &probe.landlock,
            runner(InternalHostProbeKind::LandlockWrite),
        ),
        probed_check(
            "landlock_read_denial",
            "Experimental Landlock read denial",
            &probe.landlock,
            runner(InternalHostProbeKind::LandlockRead),
        ),
        probed_check(
            "seccomp_escape_filter",
            "Seccomp escape-syscall filter",
            &warder_daemon::CapabilityState::Available,
            runner(InternalHostProbeKind::SeccompEscape),
        ),
        cgroup_check,
        ebpf_tracepoint_check(probe.ebpf),
        btrfs_check,
        HostVerificationCheck {
            id: "network_destination_blocking",
            label: "Network destination blocking",
            status: "unsupported",
            message: "network journals are visibility-only in this public beta; allowed destinations are not enforced".to_string(),
        },
    ];

    HostVerificationReport { checks }
}

fn ebpf_tracepoint_check(state: warder_daemon::CapabilityState) -> HostVerificationCheck {
    if state == warder_daemon::CapabilityState::Available
        && warder_journal::live_ebpf_file_attach_available()
        && warder_journal::live_ebpf_network_attach_available()
    {
        HostVerificationCheck {
            id: "ebpf_tracepoint_attach",
            label: "eBPF tracepoint attach",
            status: "configured/planned",
            message: format!(
                "live eBPF objects are configured for {} file and {} network tracepoints; use a privileged smoke test to prove live event capture",
                warder_journal::default_ebpf_file_tracepoints().len(),
                warder_journal::default_ebpf_network_tracepoints().len()
            ),
        }
    } else if state == warder_daemon::CapabilityState::Available {
        HostVerificationCheck {
            id: "ebpf_tracepoint_attach",
            label: "eBPF tracepoint attach",
            status: "degraded",
            message: "bpffs is visible, but live eBPF object paths are not configured for file and network tracepoint attach".to_string(),
        }
    } else {
        HostVerificationCheck {
            id: "ebpf_tracepoint_attach",
            label: "eBPF tracepoint attach",
            status: "unsupported",
            message: match state {
                warder_daemon::CapabilityState::Available => {
                    "eBPF support is unavailable to this Warder process".to_string()
                }
                warder_daemon::CapabilityState::Unavailable(reason) => reason,
            },
        }
    }
}

fn probed_check(
    id: &'static str,
    label: &'static str,
    capability: &warder_daemon::CapabilityState,
    result: InternalHostProbeResult,
) -> HostVerificationCheck {
    match capability {
        warder_daemon::CapabilityState::Unavailable(reason) => HostVerificationCheck {
            id,
            label,
            status: "unsupported",
            message: reason.clone(),
        },
        warder_daemon::CapabilityState::Available if result.passed => HostVerificationCheck {
            id,
            label,
            status: "proven working",
            message: result.message,
        },
        warder_daemon::CapabilityState::Available => HostVerificationCheck {
            id,
            label,
            status: "degraded",
            message: result.message,
        },
    }
}

fn render_host_verification(report: &HostVerificationReport) -> String {
    let mut lines = vec![
        "host verification".to_string(),
        format!("supervision scope: {GLOBAL_SUPERVISION_LIMITATION}"),
        "checks:".to_string(),
    ];
    for check in &report.checks {
        lines.push(format!(
            "- {}: {}: {}",
            check.label, check.status, check.message
        ));
    }
    lines.join("\n")
}

fn landlock_plan_status_label(status: &LandlockPlanStatus) -> String {
    match status {
        LandlockPlanStatus::Apply => "apply".to_string(),
        LandlockPlanStatus::NotRequested => "not requested".to_string(),
        LandlockPlanStatus::Degraded(reason) => format!("degraded: {reason}"),
        LandlockPlanStatus::Blocked(reason) => format!("blocked: {reason}"),
    }
}
