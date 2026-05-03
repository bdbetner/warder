use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnforcementMode {
    Enforced,
    Degraded(String),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LandlockRequirement {
    Required,
    BestEffort,
    Disabled,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LandlockSupport {
    pub kernel_available: bool,
    pub apply_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LandlockRule {
    pub path: PathBuf,
    pub access: LandlockAccess,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LandlockAccess {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LandlockPlan {
    pub status: LandlockPlanStatus,
    pub rules: Vec<LandlockRule>,
    pub handle_read: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LandlockPlanStatus {
    Apply,
    NotRequested,
    Degraded(String),
    Blocked(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LandlockApplyStatus {
    Applied,
    NotRequested,
    Degraded(String),
    Blocked(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LandlockPrepareStatus {
    Prepared { ruleset_fd: i32 },
    NotRequested,
    Degraded(String),
    Blocked(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LandlockApplyError {
    pub message: String,
}

pub trait LandlockKernel {
    fn create_ruleset(&mut self, handled_access_fs: u64) -> Result<i32, LandlockApplyError>;

    fn add_path_rule(
        &mut self,
        ruleset_fd: i32,
        rule: &LandlockRule,
        allowed_access: u64,
    ) -> Result<(), LandlockApplyError>;

    fn restrict_self(&mut self, ruleset_fd: i32) -> Result<(), LandlockApplyError>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallLandlockKernel;

pub fn plan_landlock_restrictions(
    requirement: LandlockRequirement,
    support: LandlockSupport,
    rules: Vec<LandlockRule>,
) -> LandlockPlan {
    let handle_read = rules
        .iter()
        .any(|rule| rule.access == LandlockAccess::NoAccess);
    match requirement {
        LandlockRequirement::Disabled => LandlockPlan {
            status: LandlockPlanStatus::NotRequested,
            rules: Vec::new(),
            handle_read: false,
        },
        LandlockRequirement::Required if !support.kernel_available => LandlockPlan {
            status: LandlockPlanStatus::Blocked(
                "Landlock enforcement is required, but the kernel does not expose Landlock"
                    .to_string(),
            ),
            rules,
            handle_read,
        },
        LandlockRequirement::BestEffort if !support.kernel_available => LandlockPlan {
            status: LandlockPlanStatus::Degraded(
                "Landlock unavailable; filesystem enforcement is degraded".to_string(),
            ),
            rules,
            handle_read,
        },
        LandlockRequirement::Required if !support.apply_available => LandlockPlan {
            status: LandlockPlanStatus::Blocked(
                "Landlock enforcement is required, but Warder cannot apply Landlock rules yet"
                    .to_string(),
            ),
            rules,
            handle_read,
        },
        LandlockRequirement::BestEffort if !support.apply_available => LandlockPlan {
            status: LandlockPlanStatus::Degraded(
                "Landlock apply support is unavailable; filesystem enforcement is degraded"
                    .to_string(),
            ),
            rules,
            handle_read,
        },
        LandlockRequirement::Required | LandlockRequirement::BestEffort => {
            if let Some(message) = validate_landlock_write_rules(&rules) {
                let status = match requirement {
                    LandlockRequirement::Required => LandlockPlanStatus::Blocked(message),
                    LandlockRequirement::BestEffort => LandlockPlanStatus::Degraded(message),
                    LandlockRequirement::Disabled => unreachable!(),
                };
                return LandlockPlan {
                    status,
                    rules,
                    handle_read,
                };
            }
            if let Some(message) = validate_landlock_read_rules(&rules) {
                let status = match requirement {
                    LandlockRequirement::Required => LandlockPlanStatus::Blocked(message),
                    LandlockRequirement::BestEffort => LandlockPlanStatus::Degraded(message),
                    LandlockRequirement::Disabled => unreachable!(),
                };
                return LandlockPlan {
                    status,
                    rules,
                    handle_read,
                };
            }
            LandlockPlan {
                status: LandlockPlanStatus::Apply,
                rules,
                handle_read,
            }
        }
    }
}

fn validate_landlock_write_rules(rules: &[LandlockRule]) -> Option<String> {
    let readonly_rules = rules
        .iter()
        .filter(|rule| {
            matches!(
                rule.access,
                LandlockAccess::ReadOnly | LandlockAccess::NoAccess
            )
        })
        .collect::<Vec<_>>();
    if readonly_rules.is_empty() {
        return None;
    }

    let readwrite_rules = rules
        .iter()
        .filter(|rule| rule.access == LandlockAccess::ReadWrite)
        .collect::<Vec<_>>();
    if readwrite_rules.is_empty() {
        return Some(
            "Landlock write denial requires at least one explicit unrelated writable root"
                .to_string(),
        );
    }

    for writable in &readwrite_rules {
        for readonly in &readonly_rules {
            if paths_overlap(&writable.path, &readonly.path) {
                return Some(format!(
                    "Landlock writable root '{}' must not overlap protected readonly path '{}'",
                    writable.path.display(),
                    readonly.path.display()
                ));
            }
        }
    }

    None
}

fn validate_landlock_read_rules(rules: &[LandlockRule]) -> Option<String> {
    let read_denied_rules = rules
        .iter()
        .filter(|rule| rule.access == LandlockAccess::NoAccess)
        .collect::<Vec<_>>();
    if read_denied_rules.is_empty() {
        return None;
    }

    for readable in rules.iter().filter(|rule| {
        matches!(
            rule.access,
            LandlockAccess::ReadOnly | LandlockAccess::ReadWrite
        )
    }) {
        for denied in &read_denied_rules {
            if paths_overlap(&readable.path, &denied.path) {
                return Some(format!(
                    "Landlock readable root '{}' must not overlap protected read-denied path '{}'",
                    readable.path.display(),
                    denied.path.display()
                ));
            }
        }
    }

    None
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    let left = normalized_existing_or_lexical(left);
    let right = normalized_existing_or_lexical(right);
    left == right || left.starts_with(&right) || right.starts_with(&left)
}

fn normalized_existing_or_lexical(path: &Path) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|_| lexical_normalize(path))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir | Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn checked_landlock_rule_path(path: &Path) -> Result<PathBuf, LandlockApplyError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| LandlockApplyError {
        message: format!(
            "failed to inspect Landlock rule path '{}': {source}",
            path.display()
        ),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(LandlockApplyError {
            message: format!(
                "Landlock rule path '{}' must not be a symlink",
                path.display()
            ),
        });
    }

    path.canonicalize().map_err(|source| LandlockApplyError {
        message: format!(
            "failed to canonicalize Landlock rule path '{}': {source}",
            path.display()
        ),
    })
}

pub fn apply_landlock_plan_with_kernel(
    plan: &LandlockPlan,
    kernel: &mut impl LandlockKernel,
) -> Result<LandlockApplyStatus, LandlockApplyError> {
    let ruleset_fd = match prepare_landlock_ruleset_with_kernel(plan, kernel)? {
        LandlockPrepareStatus::Prepared { ruleset_fd } => ruleset_fd,
        LandlockPrepareStatus::NotRequested => return Ok(LandlockApplyStatus::NotRequested),
        LandlockPrepareStatus::Degraded(message) => {
            return Ok(LandlockApplyStatus::Degraded(message));
        }
        LandlockPrepareStatus::Blocked(message) => {
            return Ok(LandlockApplyStatus::Blocked(message))
        }
    };
    kernel.restrict_self(ruleset_fd)?;

    Ok(LandlockApplyStatus::Applied)
}

pub fn prepare_landlock_ruleset_with_kernel(
    plan: &LandlockPlan,
    kernel: &mut impl LandlockKernel,
) -> Result<LandlockPrepareStatus, LandlockApplyError> {
    match &plan.status {
        LandlockPlanStatus::NotRequested => return Ok(LandlockPrepareStatus::NotRequested),
        LandlockPlanStatus::Degraded(message) => {
            return Ok(LandlockPrepareStatus::Degraded(message.clone()));
        }
        LandlockPlanStatus::Blocked(message) => {
            return Ok(LandlockPrepareStatus::Blocked(message.clone()));
        }
        LandlockPlanStatus::Apply => {}
    }

    let ruleset_fd = kernel.create_ruleset(landlock_handled_rights(plan.handle_read))?;
    for rule in &plan.rules {
        kernel.add_path_rule(
            ruleset_fd,
            rule,
            allowed_landlock_access(rule.access, plan.handle_read),
        )?;
    }

    Ok(LandlockPrepareStatus::Prepared { ruleset_fd })
}

pub fn restrict_current_process_to_landlock_ruleset(
    ruleset_fd: i32,
) -> Result<(), LandlockApplyError> {
    let mut kernel = SyscallLandlockKernel;
    kernel.restrict_self(ruleset_fd)
}

fn landlock_write_rights() -> u64 {
    LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE
}

fn landlock_read_rights() -> u64 {
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
}

fn landlock_handled_rights(handle_read: bool) -> u64 {
    let mut rights = landlock_write_rights();
    if handle_read {
        rights |= landlock_read_rights();
    }
    rights
}

fn allowed_landlock_access(access: LandlockAccess, handle_read: bool) -> u64 {
    match access {
        LandlockAccess::NoAccess => 0,
        LandlockAccess::ReadOnly => {
            if handle_read {
                landlock_read_rights()
            } else {
                0
            }
        }
        LandlockAccess::ReadWrite => {
            if handle_read {
                landlock_read_rights() | landlock_write_rights()
            } else {
                landlock_write_rights()
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl LandlockKernel for SyscallLandlockKernel {
    fn create_ruleset(&mut self, handled_access_fs: u64) -> Result<i32, LandlockApplyError> {
        let attr = LandlockRulesetAttr { handled_access_fs };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };
        syscall_fd("landlock_create_ruleset", fd)
    }

    fn add_path_rule(
        &mut self,
        ruleset_fd: i32,
        rule: &LandlockRule,
        allowed_access: u64,
    ) -> Result<(), LandlockApplyError> {
        let checked_path = checked_landlock_rule_path(&rule.path)?;
        let file = OpenOptions::new()
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&checked_path)
            .map_err(|source| LandlockApplyError {
                message: format!(
                    "failed to open Landlock rule path '{}': {source}",
                    checked_path.display()
                ),
            })?;
        let parent_fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        let attr = LandlockPathBeneathAttr {
            allowed_access,
            parent_fd,
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        syscall_unit("landlock_add_rule", result)
    }

    fn restrict_self(&mut self, ruleset_fd: i32) -> Result<(), LandlockApplyError> {
        let prctl = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if prctl != 0 {
            return Err(LandlockApplyError {
                message: format!(
                    "failed to set no_new_privs before Landlock: {}",
                    std::io::Error::last_os_error()
                ),
            });
        }
        let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
        syscall_unit("landlock_restrict_self", result)
    }
}

#[cfg(not(target_os = "linux"))]
impl LandlockKernel for SyscallLandlockKernel {
    fn create_ruleset(&mut self, _handled_access_fs: u64) -> Result<i32, LandlockApplyError> {
        Err(LandlockApplyError {
            message: "Landlock is only available on Linux".to_string(),
        })
    }

    fn add_path_rule(
        &mut self,
        _ruleset_fd: i32,
        _rule: &LandlockRule,
        _allowed_access: u64,
    ) -> Result<(), LandlockApplyError> {
        Err(LandlockApplyError {
            message: "Landlock is only available on Linux".to_string(),
        })
    }

    fn restrict_self(&mut self, _ruleset_fd: i32) -> Result<(), LandlockApplyError> {
        Err(LandlockApplyError {
            message: "Landlock is only available on Linux".to_string(),
        })
    }
}

fn syscall_fd(name: &str, result: libc::c_long) -> Result<i32, LandlockApplyError> {
    if result < 0 {
        Err(LandlockApplyError {
            message: format!("{name} failed: {}", std::io::Error::last_os_error()),
        })
    } else {
        Ok(result as i32)
    }
}

fn syscall_unit(name: &str, result: libc::c_long) -> Result<(), LandlockApplyError> {
    if result < 0 {
        Err(LandlockApplyError {
            message: format!("{name} failed: {}", std::io::Error::last_os_error()),
        })
    } else {
        Ok(())
    }
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CgroupTagger {
    root: PathBuf,
}

impl CgroupTagger {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn tag_pid(&self, session_id: &str, pid: u32) -> Result<CgroupTagResult, CgroupTagError> {
        let prepared = self.prepare_session_cgroup(session_id)?;
        let Some(session_path) = prepared.cgroup_path else {
            return Ok(prepared);
        };
        let mut procs = open_cgroup_procs(&session_path).map_err(|source| CgroupTagError {
            message: format!("failed to open '{}': {source}", session_path.display()),
        })?;
        writeln!(procs, "{pid}").map_err(|source| CgroupTagError {
            message: format!("failed to tag pid {pid}: {source}"),
        })?;

        Ok(CgroupTagResult {
            cgroup_path: Some(session_path),
            status: CgroupTagStatus::Tagged,
        })
    }

    pub fn prepare_session_cgroup(
        &self,
        session_id: &str,
    ) -> Result<CgroupTagResult, CgroupTagError> {
        validate_session_id(session_id)?;

        if !self.root.exists() {
            return Ok(CgroupTagResult {
                cgroup_path: None,
                status: CgroupTagStatus::Unsupported(format!(
                    "cgroup root '{}' does not exist",
                    self.root.display()
                )),
            });
        }

        if !self.root.join("cgroup.procs").exists() {
            return Ok(CgroupTagResult {
                cgroup_path: None,
                status: CgroupTagStatus::Unsupported(format!(
                    "cgroup root '{}' does not look like cgroup v2: missing cgroup.procs",
                    self.root.display()
                )),
            });
        }

        let session_path = self.root.join("warder").join(session_id);
        fs::create_dir_all(&session_path).map_err(|source| CgroupTagError {
            message: format!(
                "failed to create cgroup '{}': {source}",
                session_path.display()
            ),
        })?;
        open_cgroup_procs(&session_path).map_err(|source| CgroupTagError {
            message: format!(
                "failed to open '{}': {source}",
                session_path.join("cgroup.procs").display()
            ),
        })?;

        Ok(CgroupTagResult {
            cgroup_path: Some(session_path),
            status: CgroupTagStatus::Tagged,
        })
    }
}

pub fn tag_current_process_into_cgroup(cgroup_path: &Path) -> io::Result<()> {
    let mut procs = open_cgroup_procs(cgroup_path)?;
    procs.write_all(b"0\n")
}

fn open_cgroup_procs(cgroup_path: &Path) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(cgroup_path.join("cgroup.procs"))
}

fn validate_session_id(session_id: &str) -> Result<(), CgroupTagError> {
    let is_valid = !session_id.is_empty()
        && session_id
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'));
    if is_valid {
        Ok(())
    } else {
        Err(CgroupTagError {
            message: format!("invalid session id '{session_id}'"),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CgroupTagResult {
    pub cgroup_path: Option<PathBuf>,
    pub status: CgroupTagStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CgroupTagStatus {
    Tagged,
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CgroupTagError {
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeccompFilterError {
    pub message: String,
}

pub fn supervised_seccomp_denied_syscalls() -> &'static [&'static str] {
    &[
        "unshare",
        "mount",
        "umount2",
        "pivot_root",
        "setns",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "perf_event_open",
        "keyctl",
        "fanotify_init",
        "fanotify_mark",
        "bpf",
        "open_by_handle_at",
        "userfaultfd",
        "clone3",
        "init_module",
        "finit_module",
        "delete_module",
        "kexec_load",
        "kexec_file_load",
        "reboot",
    ]
}

pub fn supervised_seccomp_architecture() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "x86_64"
    }
    #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
    {
        #[cfg(target_arch = "aarch64")]
        {
            "aarch64"
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            "unsupported"
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        "non-linux"
    }
}

pub fn supervised_seccomp_policy_summary() -> &'static str {
    "deny-list hardening for namespace, mount, process-inspection, kernel-observation, module-loading, and reboot syscalls; not a default-deny sandbox"
}

#[cfg(target_os = "linux")]
pub fn apply_supervised_seccomp_filter() -> Result<(), SeccompFilterError> {
    let Some(expected_arch) = supervised_seccomp_expected_arch() else {
        return Err(SeccompFilterError {
            message: format!(
                "supervised seccomp filter is not supported on architecture '{}'",
                supervised_seccomp_architecture()
            ),
        });
    };
    unsafe {
        let result = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if result != 0 {
            return Err(SeccompFilterError {
                message: format!(
                    "failed to enable no_new_privs before seccomp: {}",
                    io::Error::last_os_error()
                ),
            });
        }
    }

    let denied = supervised_seccomp_denied_syscall_numbers();
    let mut filters = Vec::with_capacity(5 + denied.len() * 2);
    // Seccomp syscall numbers are architecture-specific. Check the audited
    // architecture first so a process cannot run the deny list under a
    // different syscall ABI and accidentally allow the escape syscalls.
    filters.push(seccomp_stmt(
        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        SECCOMP_DATA_ARCH_OFFSET,
    ));
    filters.push(seccomp_jump(
        (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        expected_arch,
        1,
        0,
    ));
    filters.push(seccomp_stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_KILL_PROCESS,
    ));
    filters.push(seccomp_stmt(
        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        SECCOMP_DATA_NR_OFFSET,
    ));
    for syscall in denied {
        filters.push(seccomp_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            syscall,
            0,
            1,
        ));
        filters.push(seccomp_stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }
    filters.push(seccomp_stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    ));

    let mut program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
        )
    };
    if result != 0 {
        return Err(SeccompFilterError {
            message: format!(
                "failed to install supervised seccomp filter: {}",
                io::Error::last_os_error()
            ),
        });
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_supervised_seccomp_filter() -> Result<(), SeccompFilterError> {
    Ok(())
}

#[cfg(target_os = "linux")]
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
#[cfg(target_os = "linux")]
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn supervised_seccomp_expected_arch() -> Option<u32> {
    Some(AUDIT_ARCH_X86_64)
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn supervised_seccomp_expected_arch() -> Option<u32> {
    Some(AUDIT_ARCH_AARCH64)
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn supervised_seccomp_expected_arch() -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
fn supervised_seccomp_denied_syscall_numbers() -> Vec<u32> {
    vec![
        libc::SYS_unshare as u32,
        libc::SYS_mount as u32,
        libc::SYS_umount2 as u32,
        libc::SYS_pivot_root as u32,
        libc::SYS_setns as u32,
        libc::SYS_ptrace as u32,
        libc::SYS_process_vm_readv as u32,
        libc::SYS_process_vm_writev as u32,
        libc::SYS_perf_event_open as u32,
        libc::SYS_keyctl as u32,
        libc::SYS_fanotify_init as u32,
        libc::SYS_fanotify_mark as u32,
        libc::SYS_bpf as u32,
        libc::SYS_open_by_handle_at as u32,
        libc::SYS_userfaultfd as u32,
        libc::SYS_clone3 as u32,
        libc::SYS_init_module as u32,
        libc::SYS_finit_module as u32,
        libc::SYS_delete_module as u32,
        libc::SYS_kexec_load as u32,
        libc::SYS_kexec_file_load as u32,
        libc::SYS_reboot as u32,
    ]
}

#[cfg(target_os = "linux")]
fn seccomp_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_os = "linux")]
fn seccomp_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn landlock_plan_blocks_required_policy_when_kernel_is_unavailable() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::Required,
            LandlockSupport {
                kernel_available: false,
                apply_available: false,
            },
            vec![readonly_rule("/tmp/notes")],
        );

        assert!(
            matches!(plan.status, LandlockPlanStatus::Blocked(message) if message.contains("required"))
        );
        assert_eq!(plan.rules.len(), 1);
    }

    #[test]
    fn landlock_plan_blocks_required_policy_until_apply_support_exists() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::Required,
            LandlockSupport {
                kernel_available: true,
                apply_available: false,
            },
            vec![readonly_rule("/tmp/notes")],
        );

        assert!(
            matches!(plan.status, LandlockPlanStatus::Blocked(message) if message.contains("cannot apply"))
        );
    }

    #[test]
    fn landlock_plan_degrades_best_effort_policy_without_apply_support() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::BestEffort,
            LandlockSupport {
                kernel_available: true,
                apply_available: false,
            },
            vec![readonly_rule("/tmp/notes")],
        );

        assert!(
            matches!(plan.status, LandlockPlanStatus::Degraded(message) if message.contains("degraded"))
        );
        assert_eq!(plan.rules[0].access, LandlockAccess::ReadOnly);
    }

    #[test]
    fn landlock_plan_skips_disabled_policy() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::Disabled,
            LandlockSupport {
                kernel_available: true,
                apply_available: false,
            },
            vec![readonly_rule("/tmp/notes")],
        );

        assert_eq!(plan.status, LandlockPlanStatus::NotRequested);
        assert!(plan.rules.is_empty());
    }

    #[test]
    fn landlock_plan_blocks_required_policy_without_explicit_writable_roots() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::Required,
            LandlockSupport {
                kernel_available: true,
                apply_available: true,
            },
            vec![readonly_rule("/home/user/research")],
        );

        assert!(
            matches!(plan.status, LandlockPlanStatus::Blocked(message) if message.contains("writable root"))
        );
    }

    #[test]
    fn landlock_plan_blocks_writable_roots_that_overlap_readonly_paths() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::Required,
            LandlockSupport {
                kernel_available: true,
                apply_available: true,
            },
            vec![
                LandlockRule {
                    path: PathBuf::from("/home/user"),
                    access: LandlockAccess::ReadWrite,
                },
                readonly_rule("/home/user/research"),
            ],
        );

        assert!(
            matches!(plan.status, LandlockPlanStatus::Blocked(message) if message.contains("overlap"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn landlock_plan_blocks_canonical_symlink_overlap() {
        let root = temp_path("canonical-symlink-overlap");
        let target = root.join("target");
        let link = root.join("link");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let plan = plan_landlock_restrictions(
            LandlockRequirement::Required,
            LandlockSupport {
                kernel_available: true,
                apply_available: true,
            },
            vec![
                LandlockRule {
                    path: target,
                    access: LandlockAccess::ReadWrite,
                },
                LandlockRule {
                    path: link,
                    access: LandlockAccess::ReadOnly,
                },
            ],
        );

        assert!(
            matches!(plan.status, LandlockPlanStatus::Blocked(message) if message.contains("overlap"))
        );
    }

    #[test]
    fn landlock_plan_allows_unrelated_writable_roots() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::Required,
            LandlockSupport {
                kernel_available: true,
                apply_available: true,
            },
            vec![
                LandlockRule {
                    path: PathBuf::from("/tmp"),
                    access: LandlockAccess::ReadWrite,
                },
                readonly_rule("/home/user/research"),
            ],
        );

        assert_eq!(plan.status, LandlockPlanStatus::Apply);
    }

    #[test]
    fn landlock_plan_blocks_readable_roots_that_overlap_read_denied_paths() {
        let plan = plan_landlock_restrictions(
            LandlockRequirement::Required,
            LandlockSupport {
                kernel_available: true,
                apply_available: true,
            },
            vec![
                LandlockRule {
                    path: PathBuf::from("/home/user"),
                    access: LandlockAccess::ReadOnly,
                },
                LandlockRule {
                    path: PathBuf::from("/tmp"),
                    access: LandlockAccess::ReadWrite,
                },
                LandlockRule {
                    path: PathBuf::from("/home/user/.ssh"),
                    access: LandlockAccess::NoAccess,
                },
            ],
        );

        assert!(matches!(
            plan.status,
            LandlockPlanStatus::Blocked(message) if message.contains("readable root")
        ));
        assert!(plan.handle_read);
    }

    #[test]
    fn landlock_prepare_includes_read_rights_when_read_blocking_is_planned() {
        let plan = LandlockPlan {
            status: LandlockPlanStatus::Apply,
            rules: vec![
                LandlockRule {
                    path: PathBuf::from("/opt/agent"),
                    access: LandlockAccess::ReadOnly,
                },
                LandlockRule {
                    path: PathBuf::from("/tmp"),
                    access: LandlockAccess::ReadWrite,
                },
                LandlockRule {
                    path: PathBuf::from("/home/user/.ssh"),
                    access: LandlockAccess::NoAccess,
                },
            ],
            handle_read: true,
        };
        let mut kernel = RecordingLandlockKernel::default();

        let status = prepare_landlock_ruleset_with_kernel(&plan, &mut kernel).unwrap();

        assert_eq!(status, LandlockPrepareStatus::Prepared { ruleset_fd: 7 });
        assert_eq!(
            kernel.created_rulesets,
            vec![landlock_read_rights() | landlock_write_rights()]
        );
        assert_eq!(
            kernel.added_rules,
            vec![
                (7, PathBuf::from("/opt/agent"), landlock_read_rights()),
                (
                    7,
                    PathBuf::from("/tmp"),
                    landlock_read_rights() | landlock_write_rights()
                ),
                (7, PathBuf::from("/home/user/.ssh"), 0),
            ]
        );
    }

    #[test]
    fn landlock_apply_uses_write_rights_and_rule_access_modes() {
        let plan = LandlockPlan {
            status: LandlockPlanStatus::Apply,
            rules: vec![
                readonly_rule("/tmp/readonly"),
                LandlockRule {
                    path: PathBuf::from("/tmp/readwrite"),
                    access: LandlockAccess::ReadWrite,
                },
            ],
            handle_read: false,
        };
        let mut kernel = RecordingLandlockKernel::default();

        let status = apply_landlock_plan_with_kernel(&plan, &mut kernel).unwrap();

        assert_eq!(status, LandlockApplyStatus::Applied);
        assert_eq!(kernel.created_rulesets, vec![landlock_write_rights()]);
        assert_eq!(
            kernel.added_rules,
            vec![
                (7, PathBuf::from("/tmp/readonly"), 0),
                (7, PathBuf::from("/tmp/readwrite"), landlock_write_rights())
            ]
        );
        assert_eq!(kernel.restricted_rulesets, vec![7]);
    }

    #[test]
    fn landlock_apply_does_not_call_kernel_for_blocked_plan() {
        let plan = LandlockPlan {
            status: LandlockPlanStatus::Blocked("required support missing".to_string()),
            rules: vec![readonly_rule("/tmp/notes")],
            handle_read: false,
        };
        let mut kernel = RecordingLandlockKernel::default();

        let status = apply_landlock_plan_with_kernel(&plan, &mut kernel).unwrap();

        assert_eq!(
            status,
            LandlockApplyStatus::Blocked("required support missing".to_string())
        );
        assert!(kernel.created_rulesets.is_empty());
        assert!(kernel.added_rules.is_empty());
        assert!(kernel.restricted_rulesets.is_empty());
    }

    #[test]
    fn landlock_prepare_builds_ruleset_without_restricting_current_process() {
        let plan = LandlockPlan {
            status: LandlockPlanStatus::Apply,
            rules: vec![readonly_rule("/tmp/readonly")],
            handle_read: false,
        };
        let mut kernel = RecordingLandlockKernel::default();

        let status = prepare_landlock_ruleset_with_kernel(&plan, &mut kernel).unwrap();

        assert_eq!(status, LandlockPrepareStatus::Prepared { ruleset_fd: 7 });
        assert_eq!(kernel.created_rulesets, vec![landlock_write_rights()]);
        assert_eq!(
            kernel.added_rules,
            vec![(7, PathBuf::from("/tmp/readonly"), 0)]
        );
        assert!(kernel.restricted_rulesets.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn landlock_rule_path_rejects_final_symlink() {
        let root = temp_path("rule-final-symlink");
        let target = root.join("target");
        let link = root.join("link");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = checked_landlock_rule_path(&link).unwrap_err();

        assert!(error.message.contains("must not be a symlink"));
    }

    #[test]
    fn landlock_rule_path_returns_canonical_existing_path() {
        let root = temp_path("rule-canonical-path");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();

        let checked = checked_landlock_rule_path(&root.join(".").join("nested")).unwrap();

        assert_eq!(checked, nested.canonicalize().unwrap());
    }

    #[test]
    fn missing_cgroup_root_reports_unsupported() {
        let root = temp_path("missing-root");
        let adapter = CgroupTagger::new(root);

        let result = adapter.tag_pid("session-1", 42).unwrap();

        assert_eq!(result.cgroup_path, None);
        assert!(matches!(
            result.status,
            CgroupTagStatus::Unsupported(message) if message.contains("does not exist")
        ));
    }

    #[test]
    fn root_without_cgroup_procs_reports_unsupported() {
        let root = temp_path("not-cgroup");
        fs::create_dir_all(&root).unwrap();
        let adapter = CgroupTagger::new(root);

        let result = adapter.tag_pid("session-1", 42).unwrap();

        assert_eq!(result.cgroup_path, None);
        assert!(matches!(
            result.status,
            CgroupTagStatus::Unsupported(message) if message.contains("cgroup.procs")
        ));
    }

    #[test]
    fn tag_pid_creates_session_cgroup_and_writes_pid() {
        let root = temp_path("tag-pid");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();
        let adapter = CgroupTagger::new(root.clone());

        let result = adapter.tag_pid("session-1", 4242).unwrap();

        let session_path = root.join("warder").join("session-1");
        assert_eq!(result.cgroup_path, Some(session_path.clone()));
        assert_eq!(result.status, CgroupTagStatus::Tagged);
        assert_eq!(
            fs::read_to_string(session_path.join("cgroup.procs")).unwrap(),
            "4242\n"
        );
    }

    #[test]
    fn prepare_session_cgroup_creates_cgroup_before_spawn_without_pid() {
        let root = temp_path("prepare-cgroup");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();
        let adapter = CgroupTagger::new(root.clone());

        let result = adapter.prepare_session_cgroup("session-1").unwrap();

        let session_path = root.join("warder").join("session-1");
        assert_eq!(result.cgroup_path, Some(session_path.clone()));
        assert_eq!(result.status, CgroupTagStatus::Tagged);
        assert_eq!(
            fs::read_to_string(session_path.join("cgroup.procs")).unwrap(),
            ""
        );
    }

    #[test]
    fn tag_current_process_into_cgroup_uses_current_process_sentinel() {
        let root = temp_path("tag-current");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();

        tag_current_process_into_cgroup(&root).unwrap();

        assert_eq!(
            fs::read_to_string(root.join("cgroup.procs")).unwrap(),
            "0\n"
        );
    }

    #[test]
    fn supervised_seccomp_filter_denies_namespace_and_mount_syscalls() {
        let denied = supervised_seccomp_denied_syscalls();

        for syscall in [
            "unshare",
            "mount",
            "umount2",
            "pivot_root",
            "setns",
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "perf_event_open",
            "keyctl",
            "fanotify_init",
            "fanotify_mark",
            "bpf",
            "open_by_handle_at",
            "userfaultfd",
            "clone3",
            "init_module",
            "finit_module",
            "delete_module",
            "kexec_load",
            "kexec_file_load",
            "reboot",
        ] {
            assert!(denied.contains(&syscall), "{syscall} should be denied");
        }
        assert!(supervised_seccomp_policy_summary().contains("not a default-deny sandbox"));
    }

    #[test]
    fn supervised_seccomp_filter_declares_architecture_scope() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(supervised_seccomp_architecture(), "x86_64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(supervised_seccomp_architecture(), "aarch64");
        #[cfg(target_os = "linux")]
        #[cfg(target_arch = "x86_64")]
        assert_eq!(supervised_seccomp_expected_arch(), Some(AUDIT_ARCH_X86_64));
        #[cfg(target_os = "linux")]
        #[cfg(target_arch = "aarch64")]
        assert_eq!(supervised_seccomp_expected_arch(), Some(AUDIT_ARCH_AARCH64));
    }

    #[test]
    #[ignore = "requires opt-in live cgroup v2 write permissions"]
    fn live_cgroup_v2_tag_current_process_when_writable() {
        let root =
            std::env::var("WARDER_LIVE_CGROUP_ROOT").unwrap_or_else(|_| "/sys/fs/cgroup".into());
        let adapter = CgroupTagger::new(PathBuf::from(root));

        let result = match adapter.tag_pid("warder-live-test", std::process::id()) {
            Ok(result) => result,
            Err(error) if error.message.contains("Permission denied") => {
                eprintln!("live cgroup v2 tagging unsupported here: {}", error.message);
                return;
            }
            Err(error) => panic!("{}", error.message),
        };

        assert_eq!(result.status, CgroupTagStatus::Tagged);
        assert!(result.cgroup_path.is_some());
    }

    #[test]
    fn rejects_session_ids_that_escape_cgroup_root() {
        let root = temp_path("bad-session-id");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();
        let adapter = CgroupTagger::new(root);

        let error = adapter.tag_pid("../escaped", 4242).unwrap_err();

        assert!(error.message.contains("invalid session id"));
    }

    fn temp_path(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("warder-cgroup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn readonly_rule(path: &str) -> LandlockRule {
        LandlockRule {
            path: PathBuf::from(path),
            access: LandlockAccess::ReadOnly,
        }
    }

    #[derive(Default)]
    struct RecordingLandlockKernel {
        created_rulesets: Vec<u64>,
        added_rules: Vec<(i32, PathBuf, u64)>,
        restricted_rulesets: Vec<i32>,
    }

    impl LandlockKernel for RecordingLandlockKernel {
        fn create_ruleset(&mut self, handled_access_fs: u64) -> Result<i32, LandlockApplyError> {
            self.created_rulesets.push(handled_access_fs);
            Ok(7)
        }

        fn add_path_rule(
            &mut self,
            ruleset_fd: i32,
            rule: &LandlockRule,
            allowed_access: u64,
        ) -> Result<(), LandlockApplyError> {
            self.added_rules
                .push((ruleset_fd, rule.path.clone(), allowed_access));
            Ok(())
        }

        fn restrict_self(&mut self, ruleset_fd: i32) -> Result<(), LandlockApplyError> {
            self.restricted_rulesets.push(ruleset_fd);
            Ok(())
        }
    }
}
