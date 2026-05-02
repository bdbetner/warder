use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalPlaceholder;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileJournalEvent {
    pub session_id: String,
    pub timestamp: SystemTime,
    pub process_id: Option<u32>,
    pub protected_zone_id: Option<String>,
    pub path: PathBuf,
    pub operation: FileOperation,
    pub decision: FileDecision,
    pub source: JournalSource,
    pub confidence: JournalConfidence,
    pub attribution: JournalAttribution,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedJournalZone {
    pub id: String,
    pub root_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InotifyObservedEvent {
    pub zone_id: String,
    pub root_path: PathBuf,
    pub relative_path: Option<PathBuf>,
    pub mask: u32,
    pub timestamp: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LandlockDeniedEvent {
    pub process_id: Option<u32>,
    pub path: PathBuf,
    pub operation: FileOperation,
    pub timestamp: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfFileAccessEvent {
    pub process_id: Option<u32>,
    pub cgroup_id: Option<u64>,
    pub path: PathBuf,
    pub operation: FileOperation,
    pub denied: bool,
    pub timestamp: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkJournalEvent {
    pub session_id: String,
    pub timestamp: SystemTime,
    pub process_id: Option<u32>,
    pub destination: String,
    pub destination_port: Option<u16>,
    pub protocol: NetworkProtocol,
    pub decision: NetworkDecision,
    pub source: JournalSource,
    pub confidence: JournalConfidence,
    pub attribution: JournalAttribution,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfNetworkEgressEvent {
    pub process_id: Option<u32>,
    pub cgroup_id: Option<u64>,
    pub destination: String,
    pub destination_port: Option<u16>,
    pub protocol: NetworkProtocol,
    pub denied: bool,
    pub timestamp: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcfsNetworkSocketEvent {
    pub process_id: Option<u32>,
    pub destination: String,
    pub destination_port: Option<u16>,
    pub protocol: NetworkProtocol,
    pub socket_inode: String,
    pub timestamp: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfFileJournalAttachOptions {
    pub bpf_fs: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfNetworkJournalAttachOptions {
    pub bpf_fs: PathBuf,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EbpfFileJournalSupport {
    pub bpffs_available: bool,
    pub attach_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfFileJournalAttachPlan {
    pub status: EbpfFileJournalAttachStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EbpfFileJournalAttachStatus {
    Attach,
    Unavailable(String),
}

pub fn default_ebpf_file_tracepoints() -> &'static [(&'static str, &'static str)] {
    &[
        ("warder_file_access", "sys_enter_openat"),
        ("warder_file_open", "sys_enter_open"),
        ("warder_file_openat2", "sys_enter_openat2"),
        ("warder_file_creat", "sys_enter_creat"),
        ("warder_file_truncate", "sys_enter_truncate"),
        ("warder_file_ftruncate", "sys_enter_ftruncate"),
        ("warder_file_write", "sys_enter_write"),
        ("warder_file_writev", "sys_enter_writev"),
        ("warder_file_pwrite64", "sys_enter_pwrite64"),
        ("warder_file_pwritev", "sys_enter_pwritev"),
        ("warder_file_pwritev2", "sys_enter_pwritev2"),
        ("warder_file_mmap", "sys_enter_mmap"),
        ("warder_file_mprotect", "sys_enter_mprotect"),
        ("warder_file_sendfile", "sys_enter_sendfile"),
        ("warder_file_splice", "sys_enter_splice"),
        ("warder_file_copy_file_range", "sys_enter_copy_file_range"),
        ("warder_file_rename", "sys_enter_rename"),
        ("warder_file_renameat", "sys_enter_renameat"),
        ("warder_file_renameat2", "sys_enter_renameat2"),
        ("warder_file_link", "sys_enter_link"),
        ("warder_file_linkat", "sys_enter_linkat"),
        ("warder_file_symlink", "sys_enter_symlink"),
        ("warder_file_symlinkat", "sys_enter_symlinkat"),
        ("warder_file_unlink", "sys_enter_unlink"),
        ("warder_file_unlinkat", "sys_enter_unlinkat"),
        ("warder_file_mkdir", "sys_enter_mkdir"),
        ("warder_file_mkdirat", "sys_enter_mkdirat"),
        ("warder_file_mknod", "sys_enter_mknod"),
        ("warder_file_mknodat", "sys_enter_mknodat"),
    ]
}

pub fn default_ebpf_network_tracepoints() -> &'static [(&'static str, &'static str)] {
    &[
        ("warder_network_egress", "sys_enter_connect"),
        ("warder_network_sendto", "sys_enter_sendto"),
        ("warder_network_send", "sys_enter_send"),
        ("warder_network_sendmsg", "sys_enter_sendmsg"),
        ("warder_network_sendmmsg", "sys_enter_sendmmsg"),
        ("warder_network_sendfile", "sys_enter_sendfile"),
        ("warder_network_splice", "sys_enter_splice"),
    ]
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EbpfNetworkJournalSupport {
    pub bpffs_available: bool,
    pub attach_available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EbpfNetworkJournalAttachPlan {
    pub status: EbpfNetworkJournalAttachStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EbpfNetworkJournalAttachStatus {
    Attach,
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileJournalWatchError {
    pub message: String,
}

pub trait EbpfFileAccessReader {
    fn read_available_events(&mut self) -> Result<Vec<EbpfFileAccessEvent>, FileJournalWatchError>;
}

pub trait EbpfNetworkEgressReader {
    fn read_available_events(
        &mut self,
    ) -> Result<Vec<EbpfNetworkEgressEvent>, FileJournalWatchError>;
}

#[derive(Debug)]
pub struct EbpfFileJournalCollector<R> {
    reader: R,
    zones: Vec<ProtectedJournalZone>,
}

#[derive(Debug)]
pub struct EbpfNetworkJournalCollector<R> {
    reader: R,
}

#[derive(Debug)]
pub struct RawEbpfFileAccessReader<R> {
    source: R,
    pending: Vec<u8>,
}

#[derive(Debug)]
pub struct RawEbpfNetworkEgressReader<R> {
    source: R,
    pending: Vec<u8>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ProcfsNetworkSocketReader {
    proc_root: PathBuf,
    root_pid: u32,
    seen: BTreeSet<String>,
}

#[derive(Debug)]
pub struct LiveEbpfFileAccessReader {
    inner: LiveEbpfFileAccessReaderInner,
}

#[derive(Debug)]
pub struct LiveEbpfNetworkEgressReader {
    inner: LiveEbpfNetworkEgressReaderInner,
}

#[derive(Debug)]
enum LiveEbpfFileAccessReaderInner {
    #[cfg(feature = "live-ebpf")]
    Aya(AyaLiveEbpfFileAccessReader),
    #[cfg(not(feature = "live-ebpf"))]
    #[allow(dead_code)]
    Placeholder,
}

#[derive(Debug)]
enum LiveEbpfNetworkEgressReaderInner {
    #[cfg(feature = "live-ebpf")]
    Aya(AyaLiveEbpfNetworkEgressReader),
    #[cfg(not(feature = "live-ebpf"))]
    #[allow(dead_code)]
    Placeholder,
}

#[cfg(feature = "live-ebpf")]
struct AyaLiveEbpfFileAccessReader {
    _bpf: aya::Ebpf,
    buffers: Vec<aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>>,
    scratch: Vec<bytes::BytesMut>,
}

#[cfg(feature = "live-ebpf")]
struct AyaLiveEbpfNetworkEgressReader {
    _bpf: aya::Ebpf,
    buffers: Vec<aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>>,
    scratch: Vec<bytes::BytesMut>,
}

#[cfg(feature = "live-ebpf")]
impl std::fmt::Debug for AyaLiveEbpfFileAccessReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AyaLiveEbpfFileAccessReader")
            .field("buffers", &self.buffers.len())
            .field("scratch", &self.scratch.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "live-ebpf")]
impl std::fmt::Debug for AyaLiveEbpfNetworkEgressReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AyaLiveEbpfNetworkEgressReader")
            .field("buffers", &self.buffers.len())
            .field("scratch", &self.scratch.len())
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct InotifyFileJournalWatcher {
    fd: i32,
    targets: Vec<InotifyWatchTarget>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct InotifyWatchTarget {
    watch_descriptor: i32,
    zone_id: String,
    root_path: PathBuf,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileDecision {
    Allowed,
    Denied,
    Observed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(String),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NetworkDecision {
    Allowed,
    Denied,
    Observed,
    Unknown,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JournalSource {
    Landlock,
    Inotify,
    Ebpf,
    Procfs,
    Cgroup,
    Snapshot,
    Manual,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JournalConfidence {
    Enforced,
    Observed,
    Degraded,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JournalAttribution {
    DirectProcess,
    SessionWindow,
    PolicyEnforcement,
    Unknown,
}

pub const INOTIFY_EVENT_MODIFY: u32 = 0x0000_0002;
pub const INOTIFY_EVENT_CLOSE_WRITE: u32 = 0x0000_0008;
pub const INOTIFY_EVENT_CREATE: u32 = 0x0000_0100;
pub const INOTIFY_EVENT_DELETE: u32 = 0x0000_0200;
pub const INOTIFY_EVENT_MOVED_FROM: u32 = 0x0000_0040;
pub const INOTIFY_EVENT_MOVED_TO: u32 = 0x0000_0080;
pub const EBPF_FILE_OPERATION_READ: u8 = 1;
pub const EBPF_FILE_OPERATION_WRITE: u8 = 2;
pub const EBPF_FILE_OPERATION_CREATE: u8 = 3;
pub const EBPF_FILE_OPERATION_DELETE: u8 = 4;
pub const EBPF_FILE_OPERATION_RENAME: u8 = 5;
pub const EBPF_FILE_ACCESS_PATH_BYTES: usize = 256;
pub const EBPF_FILE_ACCESS_RECORD_SIZE: usize = 4 + 1 + 1 + 8 + 8 + EBPF_FILE_ACCESS_PATH_BYTES;
pub const EBPF_NETWORK_PROTOCOL_TCP: u8 = 1;
pub const EBPF_NETWORK_PROTOCOL_UDP: u8 = 2;
pub const EBPF_NETWORK_PROTOCOL_ICMP: u8 = 3;
pub const EBPF_NETWORK_PROTOCOL_SOCKET_FD: u8 = 4;
pub const EBPF_NETWORK_DESTINATION_BYTES: usize = 64;
pub const EBPF_NETWORK_EGRESS_RECORD_SIZE: usize =
    4 + 1 + 1 + 2 + 8 + 8 + EBPF_NETWORK_DESTINATION_BYTES;

pub fn render_file_journal_summary(events: &[FileJournalEvent]) -> String {
    if events.is_empty() {
        return "file journal: no events".to_string();
    }

    let mut lines = vec![format!("file journal: {} event(s)", events.len())];
    lines.push(format!(
        "zones: {}",
        render_count_summary(events.iter().map(|event| {
            event
                .protected_zone_id
                .as_deref()
                .unwrap_or("unmatched")
                .to_string()
        }))
    ));
    lines.push(format!(
        "sources: {}",
        render_count_summary(
            events
                .iter()
                .map(|event| source_label(event.source).to_string())
        )
    ));
    lines.push(format!(
        "attribution: {}",
        render_count_summary(
            events
                .iter()
                .map(|event| attribution_label(event.attribution).to_string())
        )
    ));
    for event in events {
        lines.push(format!(
            "{} pid={} zone={} {} {} {} via {} ({}) attribution={}",
            event.session_id,
            event
                .process_id
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            event.protected_zone_id.as_deref().unwrap_or("unmatched"),
            operation_label(event.operation),
            decision_label(event.decision),
            event.path.display(),
            source_label(event.source),
            confidence_label(event.confidence),
            attribution_label(event.attribution),
        ));
        if !event.message.is_empty() {
            lines.push(format!("  {}", event.message));
        }
    }
    lines.join("\n")
}

pub fn render_network_journal_summary(events: &[NetworkJournalEvent]) -> String {
    if events.is_empty() {
        return "network journal: no events".to_string();
    }

    let mut lines = vec![format!("network journal: {} event(s)", events.len())];
    lines.push(format!(
        "destinations: {}",
        render_count_summary(events.iter().map(network_destination_label))
    ));
    lines.push(format!(
        "protocols: {}",
        render_count_summary(events.iter().map(|event| protocol_label(&event.protocol)))
    ));
    lines.push(format!(
        "sources: {}",
        render_count_summary(
            events
                .iter()
                .map(|event| source_label(event.source).to_string())
        )
    ));
    lines.push(format!(
        "attribution: {}",
        render_count_summary(
            events
                .iter()
                .map(|event| attribution_label(event.attribution).to_string())
        )
    ));
    lines.push(format!("visibility: {}", network_visibility_contract()));
    for event in events {
        lines.push(format!(
            "{} pid={} {} {} via {} ({}) attribution={}",
            event.session_id,
            event
                .process_id
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            protocol_label(&event.protocol),
            network_decision_label(event.decision),
            source_label(event.source),
            confidence_label(event.confidence),
            attribution_label(event.attribution),
        ));
        lines.push(format!(
            "  destination: {}",
            network_destination_label(event)
        ));
        if !event.message.is_empty() {
            lines.push(format!("  {}", event.message));
        }
    }
    lines.join("\n")
}

pub fn network_visibility_contract() -> &'static str {
    "limited to observed TCP connect(2), UDP sendto(2)/sendmsg(2)/sendmmsg(2), socket send(2), and socket-like sendfile(2)/splice(2) fd activity when live eBPF network journaling is attached, plus connected socket snapshots from procfs during supervised runs; not complete socket forensics or enforcement"
}

pub fn file_visibility_contract() -> &'static str {
    "limited to inotify protected-path changes plus live eBPF observations of common path syscalls, fd writes, ftruncate(2), writable mmap(2)/mprotect(2), sendfile(2), splice(2), and copy_file_range(2) when attached; fd and mmap observations may not resolve back to protected paths and remain visibility-only, not enforcement"
}

fn render_count_summary(labels: impl Iterator<Item = String>) -> String {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for label in labels {
        *counts.entry(label).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn plan_inotify_observed_event(
    session_id: &str,
    process_id: Option<u32>,
    observed: InotifyObservedEvent,
) -> Option<FileJournalEvent> {
    let operation = inotify_operation(observed.mask)?;
    let path = match observed.relative_path {
        Some(relative_path) => observed.root_path.join(relative_path),
        None => observed.root_path,
    };
    Some(FileJournalEvent {
        session_id: session_id.to_string(),
        timestamp: observed.timestamp,
        process_id,
        protected_zone_id: Some(observed.zone_id),
        path,
        operation,
        decision: FileDecision::Observed,
        source: JournalSource::Inotify,
        confidence: JournalConfidence::Observed,
        attribution: JournalAttribution::SessionWindow,
        message: "file activity observed by inotify".to_string(),
    })
}

pub fn plan_landlock_denial_event(
    session_id: &str,
    denied: LandlockDeniedEvent,
    zones: &[ProtectedJournalZone],
) -> FileJournalEvent {
    FileJournalEvent {
        session_id: session_id.to_string(),
        timestamp: denied.timestamp,
        process_id: denied.process_id,
        protected_zone_id: matching_zone_id(&denied.path, zones),
        path: denied.path,
        operation: denied.operation,
        decision: FileDecision::Denied,
        source: JournalSource::Landlock,
        confidence: JournalConfidence::Enforced,
        attribution: if denied.process_id.is_some() {
            JournalAttribution::DirectProcess
        } else {
            JournalAttribution::PolicyEnforcement
        },
        message: "file access denied by Landlock".to_string(),
    }
}

pub fn plan_ebpf_file_access_event(
    session_id: &str,
    observed: EbpfFileAccessEvent,
    zones: &[ProtectedJournalZone],
) -> FileJournalEvent {
    FileJournalEvent {
        session_id: session_id.to_string(),
        timestamp: observed.timestamp,
        process_id: observed.process_id,
        protected_zone_id: matching_zone_id(&observed.path, zones),
        path: observed.path,
        operation: observed.operation,
        decision: if observed.denied {
            FileDecision::Denied
        } else {
            FileDecision::Observed
        },
        source: JournalSource::Ebpf,
        confidence: JournalConfidence::Observed,
        attribution: if observed.process_id.is_some() {
            JournalAttribution::DirectProcess
        } else {
            JournalAttribution::SessionWindow
        },
        message: if observed.denied {
            "file access denial observed by eBPF".to_string()
        } else {
            "file activity observed by eBPF".to_string()
        },
    }
}

pub fn plan_ebpf_network_egress_event(
    session_id: &str,
    observed: EbpfNetworkEgressEvent,
) -> NetworkJournalEvent {
    NetworkJournalEvent {
        session_id: session_id.to_string(),
        timestamp: observed.timestamp,
        process_id: observed.process_id,
        destination: observed.destination,
        destination_port: observed.destination_port,
        protocol: observed.protocol,
        decision: if observed.denied {
            NetworkDecision::Denied
        } else {
            NetworkDecision::Observed
        },
        source: JournalSource::Ebpf,
        confidence: JournalConfidence::Observed,
        attribution: if observed.process_id.is_some() {
            JournalAttribution::DirectProcess
        } else {
            JournalAttribution::SessionWindow
        },
        message: if observed.denied {
            "network egress denial observed by eBPF".to_string()
        } else {
            "network egress observed by eBPF".to_string()
        },
    }
}

pub fn plan_procfs_network_socket_event(
    session_id: &str,
    observed: ProcfsNetworkSocketEvent,
) -> NetworkJournalEvent {
    NetworkJournalEvent {
        session_id: session_id.to_string(),
        timestamp: observed.timestamp,
        process_id: observed.process_id,
        destination: observed.destination,
        destination_port: observed.destination_port,
        protocol: observed.protocol,
        decision: NetworkDecision::Observed,
        source: JournalSource::Procfs,
        confidence: JournalConfidence::Observed,
        attribution: if observed.process_id.is_some() {
            JournalAttribution::DirectProcess
        } else {
            JournalAttribution::SessionWindow
        },
        message: format!(
            "connected socket observed by procfs inode={}",
            observed.socket_inode
        ),
    }
}

pub fn plan_file_event(
    session_id: &str,
    process_id: Option<u32>,
    path: PathBuf,
    operation: FileOperation,
    zones: &[ProtectedJournalZone],
    source: JournalSource,
) -> FileJournalEvent {
    FileJournalEvent {
        session_id: session_id.to_string(),
        timestamp: SystemTime::now(),
        process_id,
        protected_zone_id: matching_zone_id(&path, zones),
        path,
        operation,
        decision: FileDecision::Observed,
        source,
        confidence: JournalConfidence::Observed,
        attribution: if process_id.is_some() {
            JournalAttribution::DirectProcess
        } else {
            JournalAttribution::Unknown
        },
        message: "file activity observed".to_string(),
    }
}

pub fn plan_ebpf_file_journal_attach(support: EbpfFileJournalSupport) -> EbpfFileJournalAttachPlan {
    if !support.bpffs_available {
        return EbpfFileJournalAttachPlan {
            status: EbpfFileJournalAttachStatus::Unavailable(
                "eBPF file journaling unavailable: bpffs is unavailable".to_string(),
            ),
        };
    }

    if !support.attach_available {
        return EbpfFileJournalAttachPlan {
            status: EbpfFileJournalAttachStatus::Unavailable(
                "eBPF file journaling unavailable: live attach is not implemented yet".to_string(),
            ),
        };
    }

    EbpfFileJournalAttachPlan {
        status: EbpfFileJournalAttachStatus::Attach,
    }
}

pub fn plan_ebpf_network_journal_attach(
    support: EbpfNetworkJournalSupport,
) -> EbpfNetworkJournalAttachPlan {
    if !support.bpffs_available {
        return EbpfNetworkJournalAttachPlan {
            status: EbpfNetworkJournalAttachStatus::Unavailable(
                "eBPF network journaling unavailable: bpffs is unavailable".to_string(),
            ),
        };
    }

    if !support.attach_available {
        return EbpfNetworkJournalAttachPlan {
            status: EbpfNetworkJournalAttachStatus::Unavailable(
                "eBPF network journaling unavailable: live attach is not implemented yet"
                    .to_string(),
            ),
        };
    }

    EbpfNetworkJournalAttachPlan {
        status: EbpfNetworkJournalAttachStatus::Attach,
    }
}

pub fn live_ebpf_file_attach_available() -> bool {
    cfg!(feature = "live-ebpf") && std::env::var_os("WARDER_EBPF_FILE_OBJECT").is_some()
}

pub fn live_ebpf_network_attach_available() -> bool {
    cfg!(feature = "live-ebpf") && std::env::var_os("WARDER_EBPF_NETWORK_OBJECT").is_some()
}

pub fn decode_ebpf_file_access_record(
    record: &[u8],
) -> Result<EbpfFileAccessEvent, FileJournalWatchError> {
    if record.len() < EBPF_FILE_ACCESS_RECORD_SIZE {
        return Err(watch_error(format!(
            "truncated eBPF file-access record: expected {} bytes, got {}",
            EBPF_FILE_ACCESS_RECORD_SIZE,
            record.len()
        )));
    }

    let pid = u32::from_ne_bytes(read_record_bytes(record, 0..4, "file-access pid")?);
    let operation = decode_ebpf_file_operation(record[4])?;
    let denied = record[5] != 0;
    let timestamp_nanos =
        u64::from_ne_bytes(read_record_bytes(record, 6..14, "file-access timestamp")?);
    let cgroup_id = u64::from_ne_bytes(read_record_bytes(record, 14..22, "file-access cgroup id")?);
    let path = decode_ebpf_file_access_path(&record[22..22 + EBPF_FILE_ACCESS_PATH_BYTES])?;

    Ok(EbpfFileAccessEvent {
        process_id: (pid != 0).then_some(pid),
        cgroup_id: (cgroup_id != 0).then_some(cgroup_id),
        path,
        operation,
        denied,
        timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(timestamp_nanos),
    })
}

pub fn decode_ebpf_file_access_records(
    buffer: &[u8],
) -> Result<Vec<EbpfFileAccessEvent>, FileJournalWatchError> {
    if !buffer.len().is_multiple_of(EBPF_FILE_ACCESS_RECORD_SIZE) {
        return Err(watch_error(format!(
            "eBPF file-access buffer length {} is not aligned to record size {}",
            buffer.len(),
            EBPF_FILE_ACCESS_RECORD_SIZE
        )));
    }

    buffer
        .chunks_exact(EBPF_FILE_ACCESS_RECORD_SIZE)
        .map(decode_ebpf_file_access_record)
        .collect()
}

pub fn decode_ebpf_network_egress_record(
    record: &[u8],
) -> Result<EbpfNetworkEgressEvent, FileJournalWatchError> {
    if record.len() < EBPF_NETWORK_EGRESS_RECORD_SIZE {
        return Err(watch_error(format!(
            "truncated eBPF network-egress record: expected {} bytes, got {}",
            EBPF_NETWORK_EGRESS_RECORD_SIZE,
            record.len()
        )));
    }

    let pid = u32::from_ne_bytes(read_record_bytes(record, 0..4, "network-egress pid")?);
    let protocol = decode_ebpf_network_protocol(record[4]);
    let denied = record[5] != 0;
    let destination_port =
        u16::from_ne_bytes(read_record_bytes(record, 6..8, "network-egress port")?);
    let timestamp_nanos = u64::from_ne_bytes(read_record_bytes(
        record,
        8..16,
        "network-egress timestamp",
    )?);
    let cgroup_id = u64::from_ne_bytes(read_record_bytes(
        record,
        16..24,
        "network-egress cgroup id",
    )?);
    let destination =
        decode_ebpf_network_destination(&record[24..24 + EBPF_NETWORK_DESTINATION_BYTES])?;

    Ok(EbpfNetworkEgressEvent {
        process_id: (pid != 0).then_some(pid),
        cgroup_id: (cgroup_id != 0).then_some(cgroup_id),
        destination,
        destination_port: (destination_port != 0).then_some(destination_port),
        protocol,
        denied,
        timestamp: SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(timestamp_nanos),
    })
}

pub fn decode_ebpf_network_egress_records(
    buffer: &[u8],
) -> Result<Vec<EbpfNetworkEgressEvent>, FileJournalWatchError> {
    if !buffer.len().is_multiple_of(EBPF_NETWORK_EGRESS_RECORD_SIZE) {
        return Err(watch_error(format!(
            "eBPF network-egress buffer length {} is not aligned to record size {}",
            buffer.len(),
            EBPF_NETWORK_EGRESS_RECORD_SIZE
        )));
    }

    buffer
        .chunks_exact(EBPF_NETWORK_EGRESS_RECORD_SIZE)
        .map(decode_ebpf_network_egress_record)
        .collect()
}

fn read_record_bytes<const N: usize>(
    record: &[u8],
    range: std::ops::Range<usize>,
    field: &str,
) -> Result<[u8; N], FileJournalWatchError> {
    let expected_len = N;
    let Some(bytes) = record.get(range) else {
        return Err(watch_error(format!(
            "truncated eBPF record while reading {field}: expected {expected_len} bytes"
        )));
    };

    bytes.try_into().map_err(|_| {
        watch_error(format!(
            "invalid eBPF record field length for {field}: expected {expected_len} bytes, got {}",
            bytes.len()
        ))
    })
}

impl<R> EbpfFileJournalCollector<R>
where
    R: EbpfFileAccessReader,
{
    pub fn new(reader: R, zones: Vec<ProtectedJournalZone>) -> Self {
        Self { reader, zones }
    }

    pub fn read_available_events(
        &mut self,
        session_id: &str,
    ) -> Result<Vec<FileJournalEvent>, FileJournalWatchError> {
        Ok(self
            .reader
            .read_available_events()?
            .into_iter()
            .map(|event| plan_ebpf_file_access_event(session_id, event, &self.zones))
            .filter(should_persist_ebpf_file_journal_event)
            .collect())
    }
}

fn should_persist_ebpf_file_journal_event(event: &FileJournalEvent) -> bool {
    event.protected_zone_id.is_some() || event.decision == FileDecision::Denied
}

impl<R> EbpfNetworkJournalCollector<R>
where
    R: EbpfNetworkEgressReader,
{
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn read_available_events(
        &mut self,
        session_id: &str,
    ) -> Result<Vec<NetworkJournalEvent>, FileJournalWatchError> {
        Ok(self
            .reader
            .read_available_events()?
            .into_iter()
            .map(|event| plan_ebpf_network_egress_event(session_id, event))
            .collect())
    }
}

impl<R> RawEbpfFileAccessReader<R>
where
    R: std::io::Read,
{
    pub fn new(source: R) -> Self {
        Self {
            source,
            pending: Vec::new(),
        }
    }
}

impl<R> EbpfFileAccessReader for RawEbpfFileAccessReader<R>
where
    R: std::io::Read,
{
    fn read_available_events(&mut self) -> Result<Vec<EbpfFileAccessEvent>, FileJournalWatchError> {
        let mut buffer = [0_u8; EBPF_FILE_ACCESS_RECORD_SIZE * 16];
        let bytes_read = self.source.read(&mut buffer).map_err(|error| {
            watch_error(format!("failed to read eBPF file-access records: {error}"))
        })?;
        if bytes_read == 0 && self.pending.len() < EBPF_FILE_ACCESS_RECORD_SIZE {
            return Ok(Vec::new());
        }

        self.pending.extend_from_slice(&buffer[..bytes_read]);
        let complete_len =
            (self.pending.len() / EBPF_FILE_ACCESS_RECORD_SIZE) * EBPF_FILE_ACCESS_RECORD_SIZE;
        if complete_len == 0 {
            return Ok(Vec::new());
        }

        let complete = self.pending[..complete_len].to_vec();
        self.pending.drain(..complete_len);
        decode_ebpf_file_access_records(&complete)
    }
}

impl<R> RawEbpfNetworkEgressReader<R>
where
    R: std::io::Read,
{
    pub fn new(source: R) -> Self {
        Self {
            source,
            pending: Vec::new(),
        }
    }
}

#[cfg(target_os = "linux")]
impl ProcfsNetworkSocketReader {
    pub fn new(pid: u32) -> Self {
        Self::with_proc_root(PathBuf::from("/proc"), pid)
    }

    pub fn with_proc_root(proc_root: PathBuf, pid: u32) -> Self {
        Self {
            proc_root,
            root_pid: pid,
            seen: BTreeSet::new(),
        }
    }

    pub fn read_available_events(
        &mut self,
    ) -> Result<Vec<ProcfsNetworkSocketEvent>, FileJournalWatchError> {
        let process_socket_inodes =
            read_procfs_process_socket_inodes(&self.proc_root, self.root_pid)?;
        if process_socket_inodes.is_empty() {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        for (pid, socket_inodes) in process_socket_inodes {
            for (file_name, protocol) in [
                ("tcp", NetworkProtocol::Tcp),
                ("udp", NetworkProtocol::Udp),
                ("tcp6", NetworkProtocol::Tcp),
                ("udp6", NetworkProtocol::Udp),
            ] {
                let path = self
                    .proc_root
                    .join(pid.to_string())
                    .join("net")
                    .join(file_name);
                let mut entries = read_procfs_network_table(&path, protocol.clone())?;
                if pid != self.root_pid {
                    let root_path = self
                        .proc_root
                        .join(self.root_pid.to_string())
                        .join("net")
                        .join(file_name);
                    entries.extend(read_procfs_network_table(&root_path, protocol)?);
                }
                for entry in entries {
                    if !socket_inodes.contains(&entry.socket_inode) {
                        continue;
                    }
                    let key = format!(
                        "{}|{}|{}|{}|{}",
                        pid,
                        protocol_label(&entry.protocol),
                        entry.destination,
                        entry.destination_port.unwrap_or(0),
                        entry.socket_inode
                    );
                    if !self.seen.insert(key) {
                        continue;
                    }
                    events.push(ProcfsNetworkSocketEvent {
                        process_id: Some(pid),
                        destination: entry.destination,
                        destination_port: entry.destination_port,
                        protocol: entry.protocol,
                        socket_inode: entry.socket_inode,
                        timestamp: SystemTime::now(),
                    });
                }
            }
        }
        Ok(events)
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct ProcfsNetworkSocketReader;

#[cfg(not(target_os = "linux"))]
impl ProcfsNetworkSocketReader {
    pub fn new(_pid: u32) -> Self {
        Self
    }

    pub fn read_available_events(
        &mut self,
    ) -> Result<Vec<ProcfsNetworkSocketEvent>, FileJournalWatchError> {
        Ok(Vec::new())
    }
}

impl<R> EbpfNetworkEgressReader for RawEbpfNetworkEgressReader<R>
where
    R: std::io::Read,
{
    fn read_available_events(
        &mut self,
    ) -> Result<Vec<EbpfNetworkEgressEvent>, FileJournalWatchError> {
        let mut buffer = [0_u8; EBPF_NETWORK_EGRESS_RECORD_SIZE * 16];
        let bytes_read = self.source.read(&mut buffer).map_err(|error| {
            watch_error(format!(
                "failed to read eBPF network-egress records: {error}"
            ))
        })?;
        if bytes_read == 0 && self.pending.len() < EBPF_NETWORK_EGRESS_RECORD_SIZE {
            return Ok(Vec::new());
        }

        self.pending.extend_from_slice(&buffer[..bytes_read]);
        let complete_len = (self.pending.len() / EBPF_NETWORK_EGRESS_RECORD_SIZE)
            * EBPF_NETWORK_EGRESS_RECORD_SIZE;
        if complete_len == 0 {
            return Ok(Vec::new());
        }

        let complete = self.pending[..complete_len].to_vec();
        self.pending.drain(..complete_len);
        decode_ebpf_network_egress_records(&complete)
    }
}

impl LiveEbpfFileAccessReader {
    pub fn attach(options: EbpfFileJournalAttachOptions) -> Result<Self, FileJournalWatchError> {
        if !options.bpf_fs.exists() {
            return Err(watch_error(format!(
                "eBPF file journaling unavailable: bpffs path '{}' is unavailable",
                options.bpf_fs.display()
            )));
        }
        if !options.bpf_fs.is_dir() {
            return Err(watch_error(format!(
                "eBPF file journaling unavailable: bpffs path '{}' is not a directory",
                options.bpf_fs.display()
            )));
        }
        if let Err(error) = std::fs::read_dir(&options.bpf_fs) {
            return Err(watch_error(format!(
                "eBPF file journaling unavailable: bpffs path '{}' is not readable: {error}",
                options.bpf_fs.display()
            )));
        }
        let Some(object_path) = std::env::var_os("WARDER_EBPF_FILE_OBJECT").map(PathBuf::from)
        else {
            return Err(watch_error(
                "live eBPF file journaling is not implemented yet: set WARDER_EBPF_FILE_OBJECT to an eBPF object built for Warder's file-access record ABI",
            ));
        };

        #[cfg(feature = "live-ebpf")]
        {
            return AyaLiveEbpfFileAccessReader::attach(object_path).map(|reader| Self {
                inner: LiveEbpfFileAccessReaderInner::Aya(reader),
            });
        }

        #[cfg(not(feature = "live-ebpf"))]
        {
            let _ = object_path;
            Err(watch_error(
                "live eBPF file journaling requires building warder-journal with the live-ebpf feature",
            ))
        }
    }
}

impl EbpfFileAccessReader for LiveEbpfFileAccessReader {
    fn read_available_events(&mut self) -> Result<Vec<EbpfFileAccessEvent>, FileJournalWatchError> {
        match &mut self.inner {
            #[cfg(feature = "live-ebpf")]
            LiveEbpfFileAccessReaderInner::Aya(reader) => reader.read_available_events(),
            #[cfg(not(feature = "live-ebpf"))]
            LiveEbpfFileAccessReaderInner::Placeholder => Ok(Vec::new()),
        }
    }
}

impl LiveEbpfNetworkEgressReader {
    pub fn attach(options: EbpfNetworkJournalAttachOptions) -> Result<Self, FileJournalWatchError> {
        if !options.bpf_fs.exists() {
            return Err(watch_error(format!(
                "eBPF network journaling unavailable: bpffs path '{}' is unavailable",
                options.bpf_fs.display()
            )));
        }
        if !options.bpf_fs.is_dir() {
            return Err(watch_error(format!(
                "eBPF network journaling unavailable: bpffs path '{}' is not a directory",
                options.bpf_fs.display()
            )));
        }
        if let Err(error) = std::fs::read_dir(&options.bpf_fs) {
            return Err(watch_error(format!(
                "eBPF network journaling unavailable: bpffs path '{}' is not readable: {error}",
                options.bpf_fs.display()
            )));
        }
        let Some(object_path) = std::env::var_os("WARDER_EBPF_NETWORK_OBJECT").map(PathBuf::from)
        else {
            return Err(watch_error(
                "live eBPF network journaling is not implemented yet: set WARDER_EBPF_NETWORK_OBJECT to an eBPF object built for Warder's network-egress record ABI",
            ));
        };

        #[cfg(feature = "live-ebpf")]
        {
            return AyaLiveEbpfNetworkEgressReader::attach(object_path).map(|reader| Self {
                inner: LiveEbpfNetworkEgressReaderInner::Aya(reader),
            });
        }

        #[cfg(not(feature = "live-ebpf"))]
        {
            let _ = object_path;
            Err(watch_error(
                "live eBPF network journaling requires building warder-journal with the live-ebpf feature",
            ))
        }
    }
}

impl EbpfNetworkEgressReader for LiveEbpfNetworkEgressReader {
    fn read_available_events(
        &mut self,
    ) -> Result<Vec<EbpfNetworkEgressEvent>, FileJournalWatchError> {
        match &mut self.inner {
            #[cfg(feature = "live-ebpf")]
            LiveEbpfNetworkEgressReaderInner::Aya(reader) => reader.read_available_events(),
            #[cfg(not(feature = "live-ebpf"))]
            LiveEbpfNetworkEgressReaderInner::Placeholder => Ok(Vec::new()),
        }
    }
}

#[cfg(feature = "live-ebpf")]
impl AyaLiveEbpfFileAccessReader {
    fn attach(object_path: PathBuf) -> Result<Self, FileJournalWatchError> {
        use aya::maps::perf::PerfEventArray;

        let mut bpf = aya::Ebpf::load_file(&object_path).map_err(|error| {
            watch_error(format!(
                "failed to load eBPF file journal object '{}': {error}",
                object_path.display()
            ))
        })?;

        if let Ok(program_name) = std::env::var("WARDER_EBPF_FILE_PROGRAM") {
            let tracepoint_category = std::env::var("WARDER_EBPF_FILE_TRACEPOINT_CATEGORY")
                .unwrap_or_else(|_| "syscalls".to_string());
            let tracepoint_name = std::env::var("WARDER_EBPF_FILE_TRACEPOINT_NAME")
                .unwrap_or_else(|_| "sys_enter_openat".to_string());
            attach_file_tracepoint(
                &mut bpf,
                &object_path,
                &program_name,
                &tracepoint_category,
                &tracepoint_name,
            )?;
        } else {
            for (program_name, tracepoint_name) in default_ebpf_file_tracepoints() {
                attach_file_tracepoint(
                    &mut bpf,
                    &object_path,
                    program_name,
                    "syscalls",
                    tracepoint_name,
                )?;
            }
        }

        let map_name =
            std::env::var("WARDER_EBPF_FILE_MAP").unwrap_or_else(|_| "EVENTS".to_string());
        let map = bpf.take_map(&map_name).ok_or_else(|| {
            watch_error(format!(
                "eBPF file journal object '{}' does not contain perf event array map '{map_name}'",
                object_path.display()
            ))
        })?;
        let mut events = PerfEventArray::try_from(map).map_err(|error| {
            watch_error(format!(
                "eBPF file journal map '{map_name}' is not a perf event array: {error}"
            ))
        })?;

        let perf_pages = std::env::var("WARDER_EBPF_FILE_PERF_PAGES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(64);
        let mut buffers = Vec::new();
        for cpu_id in aya::util::online_cpus().map_err(|(_, error)| {
            watch_error(format!(
                "failed to list online CPUs for eBPF file journal: {error}"
            ))
        })? {
            buffers.push(events.open(cpu_id, Some(perf_pages)).map_err(|error| {
                watch_error(format!(
                    "failed to open eBPF file journal perf buffer for CPU {cpu_id}: {error}"
                ))
            })?);
        }

        let scratch = (0..256)
            .map(|_| bytes::BytesMut::with_capacity(EBPF_FILE_ACCESS_RECORD_SIZE))
            .collect();

        Ok(Self {
            _bpf: bpf,
            buffers,
            scratch,
        })
    }

    fn read_available_events(&mut self) -> Result<Vec<EbpfFileAccessEvent>, FileJournalWatchError> {
        let mut events = Vec::new();
        for buffer in &mut self.buffers {
            for scratch in &mut self.scratch {
                scratch.clear();
            }
            let read = buffer.read_events(&mut self.scratch).map_err(|error| {
                watch_error(format!(
                    "failed to read eBPF file journal perf events: {error}"
                ))
            })?;
            for record in self.scratch.iter().take(read.read) {
                events.push(decode_ebpf_file_access_record(record)?);
            }
            if read.lost > 0 {
                return Err(watch_error(format!(
                    "lost {} eBPF file journal perf event(s)",
                    read.lost
                )));
            }
        }
        Ok(events)
    }
}

#[cfg(feature = "live-ebpf")]
fn attach_file_tracepoint(
    bpf: &mut aya::Ebpf,
    object_path: &Path,
    program_name: &str,
    tracepoint_category: &str,
    tracepoint_name: &str,
) -> Result<(), FileJournalWatchError> {
    use aya::programs::TracePoint;
    use std::convert::TryInto;

    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| {
            watch_error(format!(
                "eBPF file journal object '{}' does not contain program '{program_name}'",
                object_path.display()
            ))
        })?
        .try_into()
        .map_err(|error| {
            watch_error(format!(
                "eBPF file journal program '{program_name}' is not a tracepoint program: {error}"
            ))
        })?;
    program.load().map_err(|error| {
        watch_error(format!(
            "failed to load eBPF file journal tracepoint program '{program_name}': {error}"
        ))
    })?;
    program
        .attach(tracepoint_category, tracepoint_name)
        .map_err(|error| {
            watch_error(format!(
                "failed to attach eBPF file journal program '{program_name}' to tracepoint '{tracepoint_category}:{tracepoint_name}': {error}"
            ))
        })?;
    Ok(())
}

#[cfg(feature = "live-ebpf")]
impl AyaLiveEbpfNetworkEgressReader {
    fn attach(object_path: PathBuf) -> Result<Self, FileJournalWatchError> {
        use aya::maps::perf::PerfEventArray;

        let mut bpf = aya::Ebpf::load_file(&object_path).map_err(|error| {
            watch_error(format!(
                "failed to load eBPF network journal object '{}': {error}",
                object_path.display()
            ))
        })?;

        if let Ok(program_name) = std::env::var("WARDER_EBPF_NETWORK_PROGRAM") {
            let tracepoint_category = std::env::var("WARDER_EBPF_NETWORK_TRACEPOINT_CATEGORY")
                .unwrap_or_else(|_| "syscalls".to_string());
            let tracepoint_name = std::env::var("WARDER_EBPF_NETWORK_TRACEPOINT_NAME")
                .unwrap_or_else(|_| "sys_enter_connect".to_string());
            attach_network_tracepoint(
                &mut bpf,
                &object_path,
                &program_name,
                &tracepoint_category,
                &tracepoint_name,
            )?;
        } else {
            for (program_name, tracepoint_name) in default_ebpf_network_tracepoints() {
                attach_network_tracepoint(
                    &mut bpf,
                    &object_path,
                    program_name,
                    "syscalls",
                    tracepoint_name,
                )?;
            }
        }

        let map_name =
            std::env::var("WARDER_EBPF_NETWORK_MAP").unwrap_or_else(|_| "EVENTS".to_string());
        let map = bpf.take_map(&map_name).ok_or_else(|| {
            watch_error(format!(
                "eBPF network journal object '{}' does not contain perf event array map '{map_name}'",
                object_path.display()
            ))
        })?;
        let mut events = PerfEventArray::try_from(map).map_err(|error| {
            watch_error(format!(
                "eBPF network journal map '{map_name}' is not a perf event array: {error}"
            ))
        })?;

        let perf_pages = std::env::var("WARDER_EBPF_NETWORK_PERF_PAGES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(64);
        let mut buffers = Vec::new();
        for cpu_id in aya::util::online_cpus().map_err(|(_, error)| {
            watch_error(format!(
                "failed to list online CPUs for eBPF network journal: {error}"
            ))
        })? {
            buffers.push(events.open(cpu_id, Some(perf_pages)).map_err(|error| {
                watch_error(format!(
                    "failed to open eBPF network journal perf buffer for CPU {cpu_id}: {error}"
                ))
            })?);
        }

        let scratch = (0..256)
            .map(|_| bytes::BytesMut::with_capacity(EBPF_NETWORK_EGRESS_RECORD_SIZE))
            .collect();

        Ok(Self {
            _bpf: bpf,
            buffers,
            scratch,
        })
    }

    fn read_available_events(
        &mut self,
    ) -> Result<Vec<EbpfNetworkEgressEvent>, FileJournalWatchError> {
        let mut events = Vec::new();
        for buffer in &mut self.buffers {
            for scratch in &mut self.scratch {
                scratch.clear();
            }
            let read = buffer.read_events(&mut self.scratch).map_err(|error| {
                watch_error(format!(
                    "failed to read eBPF network journal perf events: {error}"
                ))
            })?;
            for record in self.scratch.iter().take(read.read) {
                events.push(decode_ebpf_network_egress_record(record)?);
            }
            if read.lost > 0 {
                return Err(watch_error(format!(
                    "lost {} eBPF network journal perf event(s)",
                    read.lost
                )));
            }
        }
        Ok(events)
    }
}

#[cfg(feature = "live-ebpf")]
fn attach_network_tracepoint(
    bpf: &mut aya::Ebpf,
    object_path: &Path,
    program_name: &str,
    tracepoint_category: &str,
    tracepoint_name: &str,
) -> Result<(), FileJournalWatchError> {
    use aya::programs::TracePoint;
    use std::convert::TryInto;

    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| {
            watch_error(format!(
                "eBPF network journal object '{}' does not contain program '{program_name}'",
                object_path.display()
            ))
        })?
        .try_into()
        .map_err(|error| {
            watch_error(format!(
                "eBPF network journal program '{program_name}' is not a tracepoint program: {error}"
            ))
        })?;
    program.load().map_err(|error| {
        watch_error(format!(
            "failed to load eBPF network journal tracepoint program '{program_name}': {error}"
        ))
    })?;
    program
        .attach(tracepoint_category, tracepoint_name)
        .map_err(|error| {
            watch_error(format!(
                "failed to attach eBPF network journal program '{program_name}' to tracepoint '{tracepoint_category}:{tracepoint_name}': {error}"
            ))
        })?;
    Ok(())
}

#[cfg(target_os = "linux")]
impl InotifyFileJournalWatcher {
    pub fn watch_zones(zones: &[ProtectedJournalZone]) -> Result<Self, FileJournalWatchError> {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(watch_error(format!(
                "failed to initialize inotify: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut targets = Vec::new();
        for zone in zones {
            for root_path in &zone.root_paths {
                if let Err(error) = add_inotify_watch_tree(fd, zone, root_path, &mut targets) {
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(error);
                }
            }
        }

        Ok(Self { fd, targets })
    }

    pub fn read_available_events(
        &mut self,
        session_id: &str,
        process_id: Option<u32>,
    ) -> Result<Vec<FileJournalEvent>, FileJournalWatchError> {
        let mut buffer = vec![0_u8; 16 * 1024];
        let bytes_read = unsafe {
            libc::read(
                self.fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if bytes_read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(Vec::new());
            }
            return Err(watch_error(format!(
                "failed to read inotify events: {error}"
            )));
        }

        let (events, directories_to_watch) = parse_inotify_events(
            session_id,
            process_id,
            &buffer[..bytes_read as usize],
            &self.targets,
        );
        for directory in directories_to_watch {
            if self
                .targets
                .iter()
                .any(|target| target.root_path == directory.path)
            {
                continue;
            }
            add_inotify_watch_tree_for_zone(
                self.fd,
                &directory.zone_id,
                &directory.path,
                &mut self.targets,
            )?;
        }
        Ok(events)
    }
}

#[cfg(target_os = "linux")]
impl Drop for InotifyFileJournalWatcher {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct InotifyFileJournalWatcher;

#[cfg(not(target_os = "linux"))]
impl InotifyFileJournalWatcher {
    pub fn watch_zones(_zones: &[ProtectedJournalZone]) -> Result<Self, FileJournalWatchError> {
        Err(watch_error(
            "inotify file journaling is only available on Linux",
        ))
    }

    pub fn read_available_events(
        &mut self,
        _session_id: &str,
        _process_id: Option<u32>,
    ) -> Result<Vec<FileJournalEvent>, FileJournalWatchError> {
        Err(watch_error(
            "inotify file journaling is only available on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
fn add_inotify_watch(fd: i32, root_path: &Path) -> Result<i32, FileJournalWatchError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(root_path.as_os_str().as_bytes()).map_err(|_| {
        watch_error(format!(
            "failed to watch '{}': path contains a NUL byte",
            root_path.display()
        ))
    })?;
    let mask = libc::IN_CREATE
        | libc::IN_MODIFY
        | libc::IN_CLOSE_WRITE
        | libc::IN_DELETE
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO;
    let watch_descriptor = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) };
    if watch_descriptor < 0 {
        return Err(watch_error(format!(
            "failed to watch '{}': {}",
            root_path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(watch_descriptor)
}

#[cfg(target_os = "linux")]
fn add_inotify_watch_tree(
    fd: i32,
    zone: &ProtectedJournalZone,
    root_path: &Path,
    targets: &mut Vec<InotifyWatchTarget>,
) -> Result<(), FileJournalWatchError> {
    add_inotify_watch_tree_for_zone(fd, &zone.id, root_path, targets)
}

#[cfg(target_os = "linux")]
fn add_inotify_watch_tree_for_zone(
    fd: i32,
    zone_id: &str,
    root_path: &Path,
    targets: &mut Vec<InotifyWatchTarget>,
) -> Result<(), FileJournalWatchError> {
    let mut pending = vec![root_path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let watch_descriptor = add_inotify_watch(fd, &directory)?;
        targets.push(InotifyWatchTarget {
            watch_descriptor,
            zone_id: zone_id.to_string(),
            root_path: directory.clone(),
        });

        let entries = std::fs::read_dir(&directory).map_err(|error| {
            watch_error(format!(
                "failed to list watched directory '{}': {error}",
                directory.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                watch_error(format!(
                    "failed to read watched directory entry below '{}': {error}",
                    directory.display()
                ))
            })?;
            let file_type = entry.file_type().map_err(|error| {
                watch_error(format!(
                    "failed to inspect watched directory entry '{}': {error}",
                    entry.path().display()
                ))
            })?;
            if file_type.is_dir() && !file_type.is_symlink() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct InotifyDirectoryToWatch {
    zone_id: String,
    path: PathBuf,
}

#[cfg(target_os = "linux")]
fn parse_inotify_events(
    session_id: &str,
    process_id: Option<u32>,
    buffer: &[u8],
    targets: &[InotifyWatchTarget],
) -> (Vec<FileJournalEvent>, Vec<InotifyDirectoryToWatch>) {
    use std::ffi::OsStr;
    use std::mem::size_of;
    use std::os::unix::ffi::OsStrExt;

    let mut events = Vec::new();
    let mut directories_to_watch = Vec::new();
    let mut offset = 0;
    while offset + size_of::<libc::inotify_event>() <= buffer.len() {
        let event = unsafe {
            std::ptr::read_unaligned(buffer[offset..].as_ptr().cast::<libc::inotify_event>())
        };
        let name_start = offset + size_of::<libc::inotify_event>();
        let name_end = name_start
            .saturating_add(event.len as usize)
            .min(buffer.len());
        let relative_path = if event.len == 0 || name_start >= name_end {
            None
        } else {
            let name = &buffer[name_start..name_end];
            let name = &name[..name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len())];
            if name.is_empty() {
                None
            } else {
                Some(PathBuf::from(OsStr::from_bytes(name)))
            }
        };

        if let Some(target) = targets
            .iter()
            .find(|target| target.watch_descriptor == event.wd)
        {
            let observed_path = match relative_path.clone() {
                Some(relative_path) => target.root_path.join(relative_path),
                None => target.root_path.clone(),
            };
            let created_directory = event.mask & libc::IN_ISDIR != 0
                && event.mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0;
            if created_directory {
                directories_to_watch.push(InotifyDirectoryToWatch {
                    zone_id: target.zone_id.clone(),
                    path: observed_path,
                });
            }
            if let Some(event) = plan_inotify_observed_event(
                session_id,
                process_id,
                InotifyObservedEvent {
                    zone_id: target.zone_id.clone(),
                    root_path: target.root_path.clone(),
                    relative_path,
                    mask: event.mask,
                    timestamp: SystemTime::now(),
                },
            ) {
                events.push(event);
            }
        }

        offset = name_end;
    }
    (events, directories_to_watch)
}

fn inotify_operation(mask: u32) -> Option<FileOperation> {
    if mask & INOTIFY_EVENT_CREATE != 0 {
        Some(FileOperation::Create)
    } else if mask & INOTIFY_EVENT_DELETE != 0 {
        Some(FileOperation::Delete)
    } else if mask & (INOTIFY_EVENT_MOVED_FROM | INOTIFY_EVENT_MOVED_TO) != 0 {
        Some(FileOperation::Rename)
    } else if mask & (INOTIFY_EVENT_MODIFY | INOTIFY_EVENT_CLOSE_WRITE) != 0 {
        Some(FileOperation::Write)
    } else {
        None
    }
}

fn decode_ebpf_file_operation(operation: u8) -> Result<FileOperation, FileJournalWatchError> {
    match operation {
        EBPF_FILE_OPERATION_READ => Ok(FileOperation::Read),
        EBPF_FILE_OPERATION_WRITE => Ok(FileOperation::Write),
        EBPF_FILE_OPERATION_CREATE => Ok(FileOperation::Create),
        EBPF_FILE_OPERATION_DELETE => Ok(FileOperation::Delete),
        EBPF_FILE_OPERATION_RENAME => Ok(FileOperation::Rename),
        unknown => Err(watch_error(format!(
            "unknown eBPF file operation code {unknown}"
        ))),
    }
}

fn decode_ebpf_file_access_path(path_bytes: &[u8]) -> Result<PathBuf, FileJournalWatchError> {
    let path_bytes = &path_bytes[..path_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path_bytes.len())];
    if path_bytes.is_empty() {
        return Err(watch_error("empty eBPF file-access path"));
    }

    Ok(path_buf_from_bytes(path_bytes))
}

fn decode_ebpf_network_protocol(protocol: u8) -> NetworkProtocol {
    match protocol {
        EBPF_NETWORK_PROTOCOL_TCP => NetworkProtocol::Tcp,
        EBPF_NETWORK_PROTOCOL_UDP => NetworkProtocol::Udp,
        EBPF_NETWORK_PROTOCOL_ICMP => NetworkProtocol::Icmp,
        EBPF_NETWORK_PROTOCOL_SOCKET_FD => NetworkProtocol::Other("socket-fd".to_string()),
        unknown => NetworkProtocol::Other(format!("protocol-{unknown}")),
    }
}

fn decode_ebpf_network_destination(
    destination_bytes: &[u8],
) -> Result<String, FileJournalWatchError> {
    let destination_bytes = &destination_bytes[..destination_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(destination_bytes.len())];
    if destination_bytes.is_empty() {
        return Err(watch_error("empty eBPF network destination"));
    }

    Ok(String::from_utf8_lossy(destination_bytes).into_owned())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcfsNetworkTableEntry {
    destination: String,
    destination_port: Option<u16>,
    protocol: NetworkProtocol,
    socket_inode: String,
}

#[cfg(target_os = "linux")]
fn read_procfs_socket_inodes(
    proc_root: &Path,
    pid: u32,
) -> Result<BTreeSet<String>, FileJournalWatchError> {
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(error) if is_quiet_procfs_read_error(&error) => {
            return Ok(BTreeSet::new());
        }
        Err(error) => {
            return Err(watch_error(format!(
                "failed to read procfs fd directory '{}': {error}",
                fd_dir.display()
            )));
        }
    };

    let mut inodes = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            watch_error(format!(
                "failed to read procfs fd entry below '{}': {error}",
                fd_dir.display()
            ))
        })?;
        let target = match std::fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if is_quiet_procfs_read_error(&error) => {
                continue;
            }
            Err(error) => {
                return Err(watch_error(format!(
                    "failed to read procfs fd link '{}': {error}",
                    entry.path().display()
                )));
            }
        };
        if let Some(inode) = parse_procfs_socket_inode(&target.to_string_lossy()) {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

#[cfg(target_os = "linux")]
fn read_procfs_process_socket_inodes(
    proc_root: &Path,
    root_pid: u32,
) -> Result<BTreeMap<u32, BTreeSet<String>>, FileJournalWatchError> {
    let mut process_socket_inodes = BTreeMap::new();
    for pid in read_procfs_descendant_pids(proc_root, root_pid)? {
        let socket_inodes = read_procfs_socket_inodes(proc_root, pid)?;
        if !socket_inodes.is_empty() {
            process_socket_inodes.insert(pid, socket_inodes);
        }
    }
    Ok(process_socket_inodes)
}

#[cfg(target_os = "linux")]
fn read_procfs_descendant_pids(
    proc_root: &Path,
    root_pid: u32,
) -> Result<BTreeSet<u32>, FileJournalWatchError> {
    let entries = match std::fs::read_dir(proc_root) {
        Ok(entries) => entries,
        Err(error) if is_quiet_procfs_read_error(&error) => {
            return Ok(BTreeSet::from([root_pid]));
        }
        Err(error) => {
            return Err(watch_error(format!(
                "failed to read procfs root '{}': {error}",
                proc_root.display()
            )));
        }
    };

    let mut parents = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            watch_error(format!(
                "failed to read procfs entry below '{}': {error}",
                proc_root.display()
            ))
        })?;
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        if let Some(parent_pid) = read_procfs_parent_pid(&entry.path().join("stat"))? {
            parents.insert(pid, parent_pid);
        }
    }

    let mut descendants = BTreeSet::from([root_pid]);
    let mut changed = true;
    while changed {
        changed = false;
        for (pid, parent_pid) in &parents {
            if descendants.contains(parent_pid) && descendants.insert(*pid) {
                changed = true;
            }
        }
    }
    Ok(descendants)
}

#[cfg(target_os = "linux")]
fn read_procfs_parent_pid(stat_path: &Path) -> Result<Option<u32>, FileJournalWatchError> {
    let contents = match std::fs::read_to_string(stat_path) {
        Ok(contents) => contents,
        Err(error) if is_quiet_procfs_read_error(&error) => {
            return Ok(None);
        }
        Err(error) => {
            return Err(watch_error(format!(
                "failed to read procfs stat '{}': {error}",
                stat_path.display()
            )));
        }
    };
    Ok(parse_procfs_parent_pid(&contents))
}

#[cfg(target_os = "linux")]
fn parse_procfs_parent_pid(contents: &str) -> Option<u32> {
    let after_comm = contents.rsplit_once(") ")?;
    let mut fields = after_comm.1.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse::<u32>().ok()
}

#[cfg(target_os = "linux")]
fn parse_procfs_socket_inode(target: &str) -> Option<String> {
    target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[cfg(target_os = "linux")]
fn read_procfs_network_table(
    path: &Path,
    protocol: NetworkProtocol,
) -> Result<Vec<ProcfsNetworkTableEntry>, FileJournalWatchError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if is_quiet_procfs_read_error(&error) => {
            return Ok(Vec::new());
        }
        Err(error) => {
            return Err(watch_error(format!(
                "failed to read procfs network table '{}': {error}",
                path.display()
            )));
        }
    };
    Ok(parse_procfs_network_table(&contents, protocol))
}

#[cfg(target_os = "linux")]
fn is_quiet_procfs_read_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
    ) || error.raw_os_error() == Some(3)
}

#[cfg(target_os = "linux")]
fn parse_procfs_network_table(
    contents: &str,
    protocol: NetworkProtocol,
) -> Vec<ProcfsNetworkTableEntry> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| parse_procfs_network_table_line(line, protocol.clone()))
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_procfs_network_table_line(
    line: &str,
    protocol: NetworkProtocol,
) -> Option<ProcfsNetworkTableEntry> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let remote = *fields.get(2)?;
    let inode = *fields.get(9)?;
    let (destination, destination_port) = parse_procfs_remote_endpoint(remote)?;
    if is_unspecified_procfs_destination(&destination) || destination_port == 0 {
        return None;
    }
    Some(ProcfsNetworkTableEntry {
        destination,
        destination_port: Some(destination_port),
        protocol,
        socket_inode: inode.to_string(),
    })
}

#[cfg(target_os = "linux")]
fn parse_procfs_remote_endpoint(value: &str) -> Option<(String, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let destination = if address.len() == 8 {
        format!("ipv4:{}", procfs_ipv4_hex_to_network_order(address)?)
    } else if address.len() == 32 {
        format!("ipv6:{}", address.to_ascii_lowercase())
    } else {
        return None;
    };
    Some((destination, port))
}

#[cfg(target_os = "linux")]
fn procfs_ipv4_hex_to_network_order(value: &str) -> Option<String> {
    let bytes = (0..4)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(
        bytes
            .into_iter()
            .rev()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(""),
    )
}

#[cfg(target_os = "linux")]
fn is_unspecified_procfs_destination(destination: &str) -> bool {
    destination == "ipv4:00000000" || destination == "ipv6:00000000000000000000000000000000"
}

#[cfg(unix)]
fn path_buf_from_bytes(path_bytes: &[u8]) -> PathBuf {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    PathBuf::from(OsStr::from_bytes(path_bytes))
}

#[cfg(not(unix))]
fn path_buf_from_bytes(path_bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(path_bytes).into_owned())
}

fn matching_zone_id(path: &std::path::Path, zones: &[ProtectedJournalZone]) -> Option<String> {
    zones
        .iter()
        .find(|zone| zone.root_paths.iter().any(|root| path.starts_with(root)))
        .map(|zone| zone.id.clone())
}

fn watch_error(message: impl Into<String>) -> FileJournalWatchError {
    FileJournalWatchError {
        message: message.into(),
    }
}

fn operation_label(operation: FileOperation) -> &'static str {
    match operation {
        FileOperation::Read => "read",
        FileOperation::Write => "write",
        FileOperation::Create => "create",
        FileOperation::Delete => "delete",
        FileOperation::Rename => "rename",
    }
}

fn decision_label(decision: FileDecision) -> &'static str {
    match decision {
        FileDecision::Allowed => "allowed",
        FileDecision::Denied => "denied",
        FileDecision::Observed => "observed",
        FileDecision::Unknown => "unknown",
    }
}

fn network_decision_label(decision: NetworkDecision) -> &'static str {
    match decision {
        NetworkDecision::Allowed => "allowed",
        NetworkDecision::Denied => "denied",
        NetworkDecision::Observed => "observed",
        NetworkDecision::Unknown => "unknown",
    }
}

fn source_label(source: JournalSource) -> &'static str {
    match source {
        JournalSource::Landlock => "Landlock",
        JournalSource::Inotify => "inotify",
        JournalSource::Ebpf => "eBPF",
        JournalSource::Procfs => "procfs",
        JournalSource::Cgroup => "cgroup",
        JournalSource::Snapshot => "snapshot",
        JournalSource::Manual => "manual",
    }
}

fn confidence_label(confidence: JournalConfidence) -> &'static str {
    match confidence {
        JournalConfidence::Enforced => "enforced",
        JournalConfidence::Observed => "observed",
        JournalConfidence::Degraded => "degraded",
    }
}

pub fn attribution_label(attribution: JournalAttribution) -> &'static str {
    match attribution {
        JournalAttribution::DirectProcess => "direct-process",
        JournalAttribution::SessionWindow => "session-window",
        JournalAttribution::PolicyEnforcement => "policy-enforcement",
        JournalAttribution::Unknown => "unknown",
    }
}

fn protocol_label(protocol: &NetworkProtocol) -> String {
    match protocol {
        NetworkProtocol::Tcp => "tcp".to_string(),
        NetworkProtocol::Udp => "udp".to_string(),
        NetworkProtocol::Icmp => "icmp".to_string(),
        NetworkProtocol::Other(value) => value.to_ascii_lowercase(),
    }
}

fn network_destination_label(event: &NetworkJournalEvent) -> String {
    match event.destination_port {
        Some(port) => format!("{}:{port}", event.destination),
        None => event.destination.clone(),
    }
}

#[cfg(test)]
mod tests;
