use super::*;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
fn unique_test_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{}-{}-{}",
        prefix,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn file_journal_event_records_protected_zone_write_denial() {
    let event = FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: UNIX_EPOCH + Duration::from_secs(10),
        process_id: Some(4242),
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/home/user/notes/todo.md"),
        operation: FileOperation::Write,
        decision: FileDecision::Denied,
        source: JournalSource::Landlock,
        confidence: JournalConfidence::Enforced,
        attribution: JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    };

    assert_eq!(event.operation, FileOperation::Write);
    assert_eq!(event.decision, FileDecision::Denied);
    assert_eq!(event.protected_zone_id, Some("notes".to_string()));
}

#[test]
fn render_file_journal_summary_is_human_readable() {
    let event = FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: UNIX_EPOCH + Duration::from_secs(10),
        process_id: Some(4242),
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/home/user/notes/todo.md"),
        operation: FileOperation::Write,
        decision: FileDecision::Denied,
        source: JournalSource::Landlock,
        confidence: JournalConfidence::Enforced,
        attribution: JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    };

    let summary = render_file_journal_summary(&[event]);

    assert!(summary.contains("session-1"));
    assert!(summary.contains("write denied"));
    assert!(summary.contains("/home/user/notes/todo.md"));
    assert!(summary.contains("Landlock"));
}

#[test]
fn render_file_journal_summary_includes_scan_friendly_counts() {
    let first = FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: UNIX_EPOCH + Duration::from_secs(10),
        process_id: Some(4242),
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/home/user/notes/todo.md"),
        operation: FileOperation::Write,
        decision: FileDecision::Denied,
        source: JournalSource::Landlock,
        confidence: JournalConfidence::Enforced,
        attribution: JournalAttribution::DirectProcess,
        message: "write denied by Landlock".to_string(),
    };
    let second = FileJournalEvent {
        session_id: "session-1".to_string(),
        timestamp: UNIX_EPOCH + Duration::from_secs(11),
        process_id: None,
        protected_zone_id: Some("notes".to_string()),
        path: PathBuf::from("/home/user/notes/todo-2.md"),
        operation: FileOperation::Create,
        decision: FileDecision::Observed,
        source: JournalSource::Inotify,
        confidence: JournalConfidence::Observed,
        attribution: JournalAttribution::SessionWindow,
        message: "file activity observed by inotify".to_string(),
    };

    let summary = render_file_journal_summary(&[first, second]);

    assert!(summary.contains("zones: notes=2"));
    assert!(summary.contains("sources: Landlock=1, inotify=1"));
    assert!(summary.contains("attribution: direct-process=1, session-window=1"));
}

#[test]
fn ebpf_network_egress_event_maps_to_network_journal_event() {
    let event = plan_ebpf_network_egress_event(
        "session-1",
        EbpfNetworkEgressEvent {
            process_id: Some(4242),
            destination: "203.0.113.10".to_string(),
            destination_port: Some(443),
            protocol: NetworkProtocol::Tcp,
            denied: false,
            timestamp: UNIX_EPOCH + Duration::from_secs(15),
        },
    );

    assert_eq!(event.session_id, "session-1");
    assert_eq!(event.process_id, Some(4242));
    assert_eq!(event.destination, "203.0.113.10");
    assert_eq!(event.destination_port, Some(443));
    assert_eq!(event.protocol, NetworkProtocol::Tcp);
    assert_eq!(event.decision, NetworkDecision::Observed);
    assert_eq!(event.source, JournalSource::Ebpf);
    assert_eq!(event.confidence, JournalConfidence::Observed);
    assert_eq!(event.attribution, JournalAttribution::DirectProcess);
    assert!(event.message.contains("network egress observed"));
}

#[test]
fn render_network_journal_summary_is_scan_friendly() {
    let first = plan_ebpf_network_egress_event(
        "session-1",
        EbpfNetworkEgressEvent {
            process_id: Some(4242),
            destination: "203.0.113.10".to_string(),
            destination_port: Some(443),
            protocol: NetworkProtocol::Tcp,
            denied: false,
            timestamp: UNIX_EPOCH + Duration::from_secs(15),
        },
    );
    let second = plan_ebpf_network_egress_event(
        "session-1",
        EbpfNetworkEgressEvent {
            process_id: None,
            destination: "example.test".to_string(),
            destination_port: Some(53),
            protocol: NetworkProtocol::Udp,
            denied: true,
            timestamp: UNIX_EPOCH + Duration::from_secs(16),
        },
    );

    let summary = render_network_journal_summary(&[first, second]);

    assert!(summary.contains("network journal: 2 event(s)"));
    assert!(summary.contains("destinations: 203.0.113.10:443=1, example.test:53=1"));
    assert!(summary.contains("protocols: tcp=1, udp=1"));
    assert!(summary.contains("sources: eBPF=2"));
    assert!(summary.contains("attribution: direct-process=1, session-window=1"));
    assert!(summary
        .contains("visibility: limited to observed TCP connect(2) and UDP sendto(2)/sendmsg(2)/sendmmsg(2) attempts"));
    assert!(summary.contains("tcp observed via eBPF"));
    assert!(summary.contains("udp denied via eBPF"));
}

#[test]
fn network_visibility_contract_does_not_claim_complete_forensics() {
    let contract = network_visibility_contract();

    assert!(contract.contains("TCP connect(2)"));
    assert!(contract.contains("UDP sendto(2)"));
    assert!(contract.contains("sendmsg(2)"));
    assert!(contract.contains("sendmmsg(2)"));
    assert!(contract.contains("connected socket snapshots from procfs"));
    assert!(contract.contains("not complete socket forensics or enforcement"));
}

#[test]
fn procfs_network_socket_event_maps_to_network_journal_event() {
    let event = plan_procfs_network_socket_event(
        "session-1",
        ProcfsNetworkSocketEvent {
            process_id: Some(4242),
            destination: "ipv4:7f000001".to_string(),
            destination_port: Some(443),
            protocol: NetworkProtocol::Tcp,
            socket_inode: "12345".to_string(),
            timestamp: UNIX_EPOCH + Duration::from_secs(20),
        },
    );

    assert_eq!(event.session_id, "session-1");
    assert_eq!(event.process_id, Some(4242));
    assert_eq!(event.destination, "ipv4:7f000001");
    assert_eq!(event.destination_port, Some(443));
    assert_eq!(event.protocol, NetworkProtocol::Tcp);
    assert_eq!(event.decision, NetworkDecision::Observed);
    assert_eq!(event.source, JournalSource::Procfs);
    assert_eq!(event.confidence, JournalConfidence::Observed);
    assert_eq!(event.attribution, JournalAttribution::DirectProcess);
    assert!(event
        .message
        .contains("connected socket observed by procfs"));
    assert!(event.message.contains("inode=12345"));
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_network_socket_reader_maps_process_socket_inodes_to_destinations() {
    let proc_root = unique_test_dir("warder-procfs-network-reader");
    let pid = 4242_u32;
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let net_dir = proc_root.join(pid.to_string()).join("net");
    std::fs::create_dir_all(&fd_dir).unwrap();
    std::fs::create_dir_all(&net_dir).unwrap();
    std::os::unix::fs::symlink("socket:[12345]", fd_dir.join("3")).unwrap();
    std::os::unix::fs::symlink("/tmp/not-a-socket", fd_dir.join("4")).unwrap();
    std::fs::write(
        net_dir.join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B2 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000\n\
           1: 0100007F:A1B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000\n",
    )
    .unwrap();
    std::fs::write(net_dir.join("udp"), "").unwrap();

    let mut reader = ProcfsNetworkSocketReader::with_proc_root(proc_root.clone(), pid);
    let events = reader.read_available_events().unwrap();
    let second_read = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].process_id, Some(pid));
    assert_eq!(events[0].destination, "ipv4:7f000001");
    assert_eq!(events[0].destination_port, Some(443));
    assert_eq!(events[0].protocol, NetworkProtocol::Tcp);
    assert_eq!(events[0].socket_inode, "12345");
    assert!(second_read.is_empty());

    let _ = std::fs::remove_dir_all(proc_root);
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_network_socket_reader_maps_descendant_socket_inodes_to_destinations() {
    let proc_root = unique_test_dir("warder-procfs-network-descendants");
    let root_pid = 4242_u32;
    let child_pid = 4243_u32;
    let grandchild_pid = 4244_u32;
    for pid in [root_pid, child_pid, grandchild_pid] {
        std::fs::create_dir_all(proc_root.join(pid.to_string()).join("fd")).unwrap();
        std::fs::create_dir_all(proc_root.join(pid.to_string()).join("net")).unwrap();
    }
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("stat"),
        format!("{root_pid} (root command) S 1 1 1 0 0\n"),
    )
    .unwrap();
    std::fs::write(
        proc_root.join(child_pid.to_string()).join("stat"),
        format!("{child_pid} (child command) S {root_pid} 1 1 0 0\n"),
    )
    .unwrap();
    std::fs::write(
        proc_root.join(grandchild_pid.to_string()).join("stat"),
        format!("{grandchild_pid} (grandchild command) S {child_pid} 1 1 0 0\n"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "socket:[22345]",
        proc_root.join(child_pid.to_string()).join("fd").join("3"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "socket:[32345]",
        proc_root
            .join(grandchild_pid.to_string())
            .join("fd")
            .join("4"),
    )
    .unwrap();
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("net").join("tcp"),
        "",
    )
    .unwrap();
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("net").join("udp"),
        "",
    )
    .unwrap();
    std::fs::write(
        proc_root.join(child_pid.to_string()).join("net").join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 22345 1 0000000000000000\n",
    )
    .unwrap();
    std::fs::write(
        proc_root
            .join(child_pid.to_string())
            .join("net")
            .join("udp"),
        "",
    )
    .unwrap();
    std::fs::write(
        proc_root.join(grandchild_pid.to_string()).join("net").join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B3 0100007F:2329 01 00000000:00000000 00:00000000 00000000  1000        0 32345 1 0000000000000000\n",
    )
    .unwrap();
    std::fs::write(
        proc_root
            .join(grandchild_pid.to_string())
            .join("net")
            .join("udp"),
        "",
    )
    .unwrap();

    let mut reader = ProcfsNetworkSocketReader::with_proc_root(proc_root.clone(), root_pid);
    let events = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].process_id, Some(child_pid));
    assert_eq!(events[0].destination_port, Some(8080));
    assert_eq!(events[0].socket_inode, "22345");
    assert_eq!(events[1].process_id, Some(grandchild_pid));
    assert_eq!(events[1].destination_port, Some(9001));
    assert_eq!(events[1].socket_inode, "32345");

    let _ = std::fs::remove_dir_all(proc_root);
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_network_socket_reader_resolves_descendant_socket_from_root_net_table() {
    let proc_root = unique_test_dir("warder-procfs-network-root-table-fallback");
    let root_pid = 4242_u32;
    let child_pid = 4243_u32;

    std::fs::create_dir_all(proc_root.join(root_pid.to_string()).join("fd")).unwrap();
    std::fs::create_dir_all(proc_root.join(root_pid.to_string()).join("net")).unwrap();
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("stat"),
        format!("{root_pid} (root command) S 1 1 1 0 0\n"),
    )
    .unwrap();
    std::fs::create_dir_all(proc_root.join(child_pid.to_string()).join("fd")).unwrap();
    std::fs::write(
        proc_root.join(child_pid.to_string()).join("stat"),
        format!("{child_pid} (short lived child) S {root_pid} 1 1 0 0\n"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "socket:[22345]",
        proc_root.join(child_pid.to_string()).join("fd").join("3"),
    )
    .unwrap();
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("net").join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 22345 1 0000000000000000\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("net").join("udp"),
        "",
    )
    .unwrap();

    let mut reader = ProcfsNetworkSocketReader::with_proc_root(proc_root.clone(), root_pid);
    let events = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].process_id, Some(child_pid));
    assert_eq!(events[0].destination_port, Some(8080));
    assert_eq!(events[0].socket_inode, "22345");

    let _ = std::fs::remove_dir_all(proc_root);
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_network_socket_reader_uses_root_net_table_when_child_table_misses_inode() {
    let proc_root = unique_test_dir("warder-procfs-network-root-table-missing-inode");
    let root_pid = 4242_u32;
    let child_pid = 4243_u32;

    for pid in [root_pid, child_pid] {
        std::fs::create_dir_all(proc_root.join(pid.to_string()).join("fd")).unwrap();
        std::fs::create_dir_all(proc_root.join(pid.to_string()).join("net")).unwrap();
    }
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("stat"),
        format!("{root_pid} (root command) S 1 1 1 0 0\n"),
    )
    .unwrap();
    std::fs::write(
        proc_root.join(child_pid.to_string()).join("stat"),
        format!("{child_pid} (child command) S {root_pid} 1 1 0 0\n"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "socket:[22345]",
        proc_root.join(child_pid.to_string()).join("fd").join("3"),
    )
    .unwrap();
    std::fs::write(
        proc_root.join(child_pid.to_string()).join("net").join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B2 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000\n",
    )
    .unwrap();
    std::fs::write(
        proc_root
            .join(child_pid.to_string())
            .join("net")
            .join("udp"),
        "",
    )
    .unwrap();
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("net").join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 22345 1 0000000000000000\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join(root_pid.to_string()).join("net").join("udp"),
        "",
    )
    .unwrap();

    let mut reader = ProcfsNetworkSocketReader::with_proc_root(proc_root.clone(), root_pid);
    let events = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].process_id, Some(child_pid));
    assert_eq!(events[0].destination_port, Some(8080));
    assert_eq!(events[0].socket_inode, "22345");

    let _ = std::fs::remove_dir_all(proc_root);
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_network_table_parser_skips_malformed_and_unspecified_rows() {
    let entries = parse_procfs_network_table(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:A1B2 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000\n\
           1: 0100007F:A1B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000\n\
           2: 0100007F:A1B4 0100007F:ZZZZ 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000\n\
           malformed row\n",
        NetworkProtocol::Tcp,
    );

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].destination, "ipv4:7f000001");
    assert_eq!(entries[0].destination_port, Some(443));
    assert_eq!(entries[0].socket_inode, "12345");
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_network_table_parser_handles_ipv6_rows() {
    let entries = parse_procfs_network_table(
        "  sl  local_address                         rem_address                          st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 00000000000000000000000000000000:A1B2 00000000000000000000000000000001:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000\n\
           1: 00000000000000000000000000000000:A1B3 00000000000000000000000000000000:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000\n",
        NetworkProtocol::Tcp,
    );

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].destination,
        "ipv6:00000000000000000000000000000001"
    );
    assert_eq!(entries[0].destination_port, Some(443));
    assert_eq!(entries[0].socket_inode, "12345");
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_network_socket_reader_treats_unreadable_fd_dir_as_quiet_degraded_surface() {
    use std::os::unix::fs::PermissionsExt;

    let proc_root = unique_test_dir("warder-procfs-network-unreadable");
    let pid = 4243_u32;
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    std::fs::create_dir_all(&fd_dir).unwrap();
    let mut permissions = std::fs::metadata(&fd_dir).unwrap().permissions();
    permissions.set_mode(0o000);
    std::fs::set_permissions(&fd_dir, permissions).unwrap();

    let mut reader = ProcfsNetworkSocketReader::with_proc_root(proc_root.clone(), pid);
    let events = reader.read_available_events().unwrap();

    let mut permissions = std::fs::metadata(&fd_dir).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&fd_dir, permissions).unwrap();
    let _ = std::fs::remove_dir_all(proc_root);

    assert!(events.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn procfs_read_errors_treat_disappearing_process_as_quiet_surface() {
    let error = std::io::Error::from_raw_os_error(3);

    assert!(is_quiet_procfs_read_error(&error));
}

#[test]
fn decodes_raw_ebpf_network_egress_record() {
    let raw = raw_ebpf_network_record(
        4242,
        EBPF_NETWORK_PROTOCOL_TCP,
        false,
        Some(443),
        "203.0.113.10",
    );

    let event = decode_ebpf_network_egress_record(&raw).unwrap();

    assert_eq!(event.process_id, Some(4242));
    assert_eq!(event.destination, "203.0.113.10");
    assert_eq!(event.destination_port, Some(443));
    assert_eq!(event.protocol, NetworkProtocol::Tcp);
    assert!(!event.denied);
    assert_eq!(event.timestamp, UNIX_EPOCH + Duration::from_nanos(60));
}

#[test]
fn decodes_multiple_ebpf_network_egress_records_from_buffer() {
    let first = raw_ebpf_network_record(
        100,
        EBPF_NETWORK_PROTOCOL_TCP,
        false,
        Some(443),
        "203.0.113.10",
    );
    let second = raw_ebpf_network_record(
        101,
        EBPF_NETWORK_PROTOCOL_UDP,
        true,
        Some(53),
        "example.test",
    );
    let mut buffer = first;
    buffer.extend(second);

    let events = decode_ebpf_network_egress_records(&buffer).unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].protocol, NetworkProtocol::Tcp);
    assert_eq!(events[0].destination_port, Some(443));
    assert_eq!(events[1].protocol, NetworkProtocol::Udp);
    assert!(events[1].denied);
}

#[test]
fn raw_ebpf_network_reader_decodes_available_records_from_stream() {
    let first = raw_ebpf_network_record(
        100,
        EBPF_NETWORK_PROTOCOL_TCP,
        false,
        Some(443),
        "203.0.113.10",
    );
    let second = raw_ebpf_network_record(
        101,
        EBPF_NETWORK_PROTOCOL_UDP,
        true,
        Some(53),
        "example.test",
    );
    let mut buffer = first;
    buffer.extend(second);
    let mut reader = RawEbpfNetworkEgressReader::new(Cursor::new(buffer));

    let events = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].process_id, Some(100));
    assert_eq!(events[0].destination, "203.0.113.10");
    assert_eq!(events[1].process_id, Some(101));
    assert_eq!(events[1].destination, "example.test");
    assert!(events[1].denied);
}

#[test]
fn raw_ebpf_network_reader_keeps_partial_record_for_next_read() {
    let record = raw_ebpf_network_record(
        100,
        EBPF_NETWORK_PROTOCOL_TCP,
        false,
        Some(443),
        "203.0.113.10",
    );
    let split_at = EBPF_NETWORK_EGRESS_RECORD_SIZE / 2;
    let chunks = ChunkedRawReader {
        chunks: vec![record[..split_at].to_vec(), record[split_at..].to_vec()],
    };
    let mut reader = RawEbpfNetworkEgressReader::new(chunks);

    assert!(reader.read_available_events().unwrap().is_empty());
    let events = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].destination, "203.0.113.10");
}

#[test]
fn rejects_malformed_ebpf_network_egress_records_plainly() {
    let truncated = decode_ebpf_network_egress_record(&[0_u8; 12]).unwrap_err();
    assert!(truncated.message.contains("truncated"));

    let mut empty_destination = vec![0_u8; EBPF_NETWORK_EGRESS_RECORD_SIZE];
    empty_destination[4] = EBPF_NETWORK_PROTOCOL_TCP;
    let empty = decode_ebpf_network_egress_record(&empty_destination).unwrap_err();
    assert!(empty.message.contains("empty"));

    let misaligned = decode_ebpf_network_egress_records(&[0_u8; 3]).unwrap_err();
    assert!(misaligned.message.contains("not aligned"));
}

#[test]
fn ebpf_network_collector_maps_reader_events_into_network_journal_events() {
    let mut collector = EbpfNetworkJournalCollector::new(FakeEbpfNetworkReader {
        events: vec![EbpfNetworkEgressEvent {
            process_id: Some(4242),
            destination: "203.0.113.10".to_string(),
            destination_port: Some(443),
            protocol: NetworkProtocol::Tcp,
            denied: false,
            timestamp: UNIX_EPOCH + Duration::from_secs(60),
        }],
    });

    let events = collector.read_available_events("session-1").unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].session_id, "session-1");
    assert_eq!(events[0].source, JournalSource::Ebpf);
    assert_eq!(events[0].protocol, NetworkProtocol::Tcp);
    assert_eq!(events[0].destination, "203.0.113.10");
    assert_eq!(events[0].decision, NetworkDecision::Observed);
}

#[test]
fn plan_file_event_matches_protected_zone_by_path_prefix() {
    let event = plan_file_event(
        "session-1",
        Some(4242),
        PathBuf::from("/home/user/notes/todo.md"),
        FileOperation::Write,
        &[ProtectedJournalZone {
            id: "notes".to_string(),
            root_paths: vec![PathBuf::from("/home/user/notes")],
        }],
        JournalSource::Inotify,
    );

    assert_eq!(event.protected_zone_id, Some("notes".to_string()));
    assert_eq!(event.decision, FileDecision::Observed);
    assert_eq!(event.confidence, JournalConfidence::Observed);
}

#[test]
fn inotify_observed_event_maps_create_to_file_journal_event() {
    let event = plan_inotify_observed_event(
        "session-1",
        None,
        InotifyObservedEvent {
            zone_id: "notes".to_string(),
            root_path: PathBuf::from("/home/user/notes"),
            relative_path: Some(PathBuf::from("todo.md")),
            mask: INOTIFY_EVENT_CREATE,
            timestamp: UNIX_EPOCH + Duration::from_secs(20),
        },
    )
    .unwrap();

    assert_eq!(event.protected_zone_id, Some("notes".to_string()));
    assert_eq!(event.path, PathBuf::from("/home/user/notes/todo.md"));
    assert_eq!(event.operation, FileOperation::Create);
    assert_eq!(event.decision, FileDecision::Observed);
    assert_eq!(event.source, JournalSource::Inotify);
    assert_eq!(event.confidence, JournalConfidence::Observed);
    assert_eq!(event.attribution, JournalAttribution::SessionWindow);
}

#[test]
fn landlock_denial_event_maps_to_enforced_journal_event() {
    let event = plan_landlock_denial_event(
        "session-1",
        LandlockDeniedEvent {
            process_id: Some(4242),
            path: PathBuf::from("/home/user/notes/todo.md"),
            operation: FileOperation::Write,
            timestamp: UNIX_EPOCH + Duration::from_secs(30),
        },
        &[ProtectedJournalZone {
            id: "notes".to_string(),
            root_paths: vec![PathBuf::from("/home/user/notes")],
        }],
    );

    assert_eq!(event.protected_zone_id, Some("notes".to_string()));
    assert_eq!(event.path, PathBuf::from("/home/user/notes/todo.md"));
    assert_eq!(event.operation, FileOperation::Write);
    assert_eq!(event.decision, FileDecision::Denied);
    assert_eq!(event.source, JournalSource::Landlock);
    assert_eq!(event.confidence, JournalConfidence::Enforced);
    assert_eq!(event.attribution, JournalAttribution::DirectProcess);
    assert!(event.message.contains("denied by Landlock"));
}

#[test]
fn ebpf_file_access_event_maps_denied_write_to_observed_denial() {
    let event = plan_ebpf_file_access_event(
        "session-1",
        EbpfFileAccessEvent {
            process_id: Some(4242),
            path: PathBuf::from("/home/user/notes/todo.md"),
            operation: FileOperation::Write,
            denied: true,
            timestamp: UNIX_EPOCH + Duration::from_secs(40),
        },
        &[ProtectedJournalZone {
            id: "notes".to_string(),
            root_paths: vec![PathBuf::from("/home/user/notes")],
        }],
    );

    assert_eq!(event.protected_zone_id, Some("notes".to_string()));
    assert_eq!(event.decision, FileDecision::Denied);
    assert_eq!(event.source, JournalSource::Ebpf);
    assert_eq!(event.confidence, JournalConfidence::Observed);
    assert_eq!(event.attribution, JournalAttribution::DirectProcess);
    assert!(event.message.contains("denial observed by eBPF"));
}

#[test]
fn ebpf_collector_maps_reader_events_into_file_journal_events() {
    let mut collector = EbpfFileJournalCollector::new(
        FakeEbpfReader {
            events: vec![
                EbpfFileAccessEvent {
                    process_id: Some(4242),
                    path: PathBuf::from("/home/user/notes/todo.md"),
                    operation: FileOperation::Read,
                    denied: false,
                    timestamp: UNIX_EPOCH + Duration::from_secs(50),
                },
                EbpfFileAccessEvent {
                    process_id: Some(4242),
                    path: PathBuf::from("/usr/lib/libc.so.6"),
                    operation: FileOperation::Read,
                    denied: false,
                    timestamp: UNIX_EPOCH + Duration::from_secs(51),
                },
            ],
        },
        vec![ProtectedJournalZone {
            id: "notes".to_string(),
            root_paths: vec![PathBuf::from("/home/user/notes")],
        }],
    );

    let events = collector.read_available_events("session-1").unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].source, JournalSource::Ebpf);
    assert_eq!(events[0].operation, FileOperation::Read);
    assert_eq!(events[0].decision, FileDecision::Observed);
    assert_eq!(events[0].protected_zone_id, Some("notes".to_string()));
}

#[test]
fn ebpf_collector_keeps_unmatched_denials() {
    let mut collector = EbpfFileJournalCollector::new(
        FakeEbpfReader {
            events: vec![EbpfFileAccessEvent {
                process_id: Some(4242),
                path: PathBuf::from("/etc/shadow"),
                operation: FileOperation::Read,
                denied: true,
                timestamp: UNIX_EPOCH + Duration::from_secs(55),
            }],
        },
        vec![ProtectedJournalZone {
            id: "notes".to_string(),
            root_paths: vec![PathBuf::from("/home/user/notes")],
        }],
    );

    let events = collector.read_available_events("session-1").unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].protected_zone_id, None);
    assert_eq!(events[0].decision, FileDecision::Denied);
    assert_eq!(events[0].source, JournalSource::Ebpf);
}

#[test]
fn ebpf_collector_surfaces_reader_failures() {
    let mut collector = EbpfFileJournalCollector::new(
        FailingEbpfReader {
            message: "missing CAP_BPF".to_string(),
        },
        Vec::new(),
    );

    let error = collector.read_available_events("session-1").unwrap_err();

    assert!(error.message.contains("missing CAP_BPF"));
}

#[test]
fn decodes_raw_ebpf_ring_buffer_file_access_record() {
    let mut raw = vec![0_u8; EBPF_FILE_ACCESS_RECORD_SIZE];
    raw[0..4].copy_from_slice(&4242_u32.to_ne_bytes());
    raw[4] = EBPF_FILE_OPERATION_WRITE;
    raw[5] = 1;
    raw[6..14].copy_from_slice(&50_u64.to_ne_bytes());
    let path = b"/home/user/notes\0";
    raw[14..14 + path.len()].copy_from_slice(path);

    let event = decode_ebpf_file_access_record(&raw).unwrap();

    assert_eq!(event.process_id, Some(4242));
    assert_eq!(event.operation, FileOperation::Write);
    assert!(event.denied);
    assert_eq!(event.timestamp, UNIX_EPOCH + Duration::from_nanos(50));
    assert_eq!(event.path, PathBuf::from("/home/user/notes"));
}

#[test]
fn decodes_multiple_ebpf_file_access_records_from_buffer() {
    let first = raw_ebpf_record(
        100,
        EBPF_FILE_OPERATION_READ,
        false,
        "/home/user/notes/a.md",
    );
    let second = raw_ebpf_record(
        101,
        EBPF_FILE_OPERATION_WRITE,
        true,
        "/home/user/notes/b.md",
    );
    let mut buffer = first;
    buffer.extend(second);

    let events = decode_ebpf_file_access_records(&buffer).unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].operation, FileOperation::Read);
    assert!(!events[0].denied);
    assert_eq!(events[1].operation, FileOperation::Write);
    assert!(events[1].denied);
}

#[test]
fn raw_ebpf_reader_decodes_available_records_from_stream() {
    let first = raw_ebpf_record(
        100,
        EBPF_FILE_OPERATION_READ,
        false,
        "/home/user/notes/a.md",
    );
    let second = raw_ebpf_record(
        101,
        EBPF_FILE_OPERATION_WRITE,
        true,
        "/home/user/notes/b.md",
    );
    let mut buffer = first;
    buffer.extend(second);
    let mut reader = RawEbpfFileAccessReader::new(Cursor::new(buffer));

    let events = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].process_id, Some(100));
    assert_eq!(events[0].operation, FileOperation::Read);
    assert_eq!(events[0].path, PathBuf::from("/home/user/notes/a.md"));
    assert_eq!(events[1].process_id, Some(101));
    assert_eq!(events[1].operation, FileOperation::Write);
    assert!(events[1].denied);
}

#[test]
fn raw_ebpf_reader_keeps_partial_record_for_next_read() {
    let record = raw_ebpf_record(
        100,
        EBPF_FILE_OPERATION_READ,
        false,
        "/home/user/notes/a.md",
    );
    let split_at = EBPF_FILE_ACCESS_RECORD_SIZE / 2;
    let chunks = ChunkedRawReader {
        chunks: vec![record[..split_at].to_vec(), record[split_at..].to_vec()],
    };
    let mut reader = RawEbpfFileAccessReader::new(chunks);

    assert!(reader.read_available_events().unwrap().is_empty());
    let events = reader.read_available_events().unwrap();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].path, PathBuf::from("/home/user/notes/a.md"));
}

#[test]
fn rejects_malformed_ebpf_file_access_records_plainly() {
    let truncated = decode_ebpf_file_access_record(&[0_u8; 12]).unwrap_err();
    assert!(truncated.message.contains("truncated"));

    let mut unknown_operation = vec![0_u8; EBPF_FILE_ACCESS_RECORD_SIZE];
    unknown_operation[4] = 99;
    unknown_operation[14] = b'/';
    let unknown = decode_ebpf_file_access_record(&unknown_operation).unwrap_err();
    assert!(unknown.message.contains("unknown eBPF file operation"));

    let mut empty_path = vec![0_u8; EBPF_FILE_ACCESS_RECORD_SIZE];
    empty_path[4] = EBPF_FILE_OPERATION_READ;
    let empty = decode_ebpf_file_access_record(&empty_path).unwrap_err();
    assert!(empty.message.contains("empty"));
}

#[test]
fn live_ebpf_reader_reports_missing_bpffs_plainly() {
    let missing_bpffs =
        std::env::temp_dir().join(format!("warder-missing-bpffs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&missing_bpffs);

    let error = LiveEbpfFileAccessReader::attach(EbpfFileJournalAttachOptions {
        bpf_fs: missing_bpffs,
    })
    .unwrap_err();

    assert!(error.message.contains("bpffs"));
    assert!(error.message.contains("unavailable"));
}

#[cfg(unix)]
#[test]
fn live_ebpf_reader_reports_unreadable_bpffs_plainly() {
    use std::os::unix::fs::PermissionsExt;

    let bpf = std::env::temp_dir().join(format!("warder-unreadable-bpffs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&bpf);
    std::fs::create_dir_all(&bpf).unwrap();
    let original_permissions = std::fs::metadata(&bpf).unwrap().permissions();
    std::fs::set_permissions(&bpf, std::fs::Permissions::from_mode(0o000)).unwrap();

    let error = LiveEbpfFileAccessReader::attach(EbpfFileJournalAttachOptions {
        bpf_fs: bpf.clone(),
    })
    .unwrap_err();

    std::fs::set_permissions(&bpf, original_permissions).unwrap();
    let _ = std::fs::remove_dir_all(&bpf);

    assert!(error.message.contains("not readable"));
}

#[test]
fn live_ebpf_reader_requires_configured_object_after_bpffs_probe() {
    let _env_guard = ebpf_env_lock().lock().unwrap();
    let original_object = std::env::var_os("WARDER_EBPF_FILE_OBJECT");
    std::env::remove_var("WARDER_EBPF_FILE_OBJECT");

    let bpf = writable_temp_bpffs("warder-missing-ebpf-object");
    let error = LiveEbpfFileAccessReader::attach(EbpfFileJournalAttachOptions {
        bpf_fs: bpf.clone(),
    })
    .unwrap_err();

    restore_env_var("WARDER_EBPF_FILE_OBJECT", original_object);
    let _ = std::fs::remove_dir_all(&bpf);

    assert!(error.message.contains("WARDER_EBPF_FILE_OBJECT"));
}

#[cfg(not(feature = "live-ebpf"))]
#[test]
fn live_ebpf_reader_reports_feature_gate_when_object_is_configured() {
    let _env_guard = ebpf_env_lock().lock().unwrap();
    let original_object = std::env::var_os("WARDER_EBPF_FILE_OBJECT");

    let bpf = writable_temp_bpffs("warder-feature-gated-ebpf-object");
    let object_path = bpf.join("warder_file_access.bpf.o");
    std::fs::write(&object_path, b"not a real object").unwrap();
    std::env::set_var("WARDER_EBPF_FILE_OBJECT", &object_path);

    let error = LiveEbpfFileAccessReader::attach(EbpfFileJournalAttachOptions {
        bpf_fs: bpf.clone(),
    })
    .unwrap_err();

    restore_env_var("WARDER_EBPF_FILE_OBJECT", original_object);
    let _ = std::fs::remove_dir_all(&bpf);

    assert!(error.message.contains("live-ebpf feature"));
}

#[cfg(feature = "live-ebpf")]
#[test]
fn live_ebpf_reader_reports_invalid_object_load_failure() {
    let _env_guard = ebpf_env_lock().lock().unwrap();
    let original_object = std::env::var_os("WARDER_EBPF_FILE_OBJECT");

    let bpf = writable_temp_bpffs("warder-invalid-ebpf-object");
    let object_path = bpf.join("warder_file_access.bpf.o");
    std::fs::write(&object_path, b"not a real object").unwrap();
    std::env::set_var("WARDER_EBPF_FILE_OBJECT", &object_path);

    let error = LiveEbpfFileAccessReader::attach(EbpfFileJournalAttachOptions {
        bpf_fs: bpf.clone(),
    })
    .unwrap_err();

    restore_env_var("WARDER_EBPF_FILE_OBJECT", original_object);
    let _ = std::fs::remove_dir_all(&bpf);

    assert!(error
        .message
        .contains("failed to load eBPF file journal object"));
}

#[test]
fn live_ebpf_network_reader_requires_configured_object_after_bpffs_probe() {
    let _env_guard = ebpf_env_lock().lock().unwrap();
    let original_object = std::env::var_os("WARDER_EBPF_NETWORK_OBJECT");
    std::env::remove_var("WARDER_EBPF_NETWORK_OBJECT");

    let bpf = writable_temp_bpffs("warder-missing-ebpf-network-object");
    let error = LiveEbpfNetworkEgressReader::attach(EbpfNetworkJournalAttachOptions {
        bpf_fs: bpf.clone(),
    })
    .unwrap_err();

    restore_env_var("WARDER_EBPF_NETWORK_OBJECT", original_object);
    let _ = std::fs::remove_dir_all(&bpf);

    assert!(error.message.contains("WARDER_EBPF_NETWORK_OBJECT"));
}

#[cfg(not(feature = "live-ebpf"))]
#[test]
fn live_ebpf_network_reader_reports_feature_gate_when_object_is_configured() {
    let _env_guard = ebpf_env_lock().lock().unwrap();
    let original_object = std::env::var_os("WARDER_EBPF_NETWORK_OBJECT");

    let bpf = writable_temp_bpffs("warder-feature-gated-ebpf-network-object");
    let object_path = bpf.join("warder_network_egress.bpf.o");
    std::fs::write(&object_path, b"not a real object").unwrap();
    std::env::set_var("WARDER_EBPF_NETWORK_OBJECT", &object_path);

    let error = LiveEbpfNetworkEgressReader::attach(EbpfNetworkJournalAttachOptions {
        bpf_fs: bpf.clone(),
    })
    .unwrap_err();

    restore_env_var("WARDER_EBPF_NETWORK_OBJECT", original_object);
    let _ = std::fs::remove_dir_all(&bpf);

    assert!(error.message.contains("live-ebpf feature"));
}

#[cfg(feature = "live-ebpf")]
#[test]
fn live_ebpf_network_reader_reports_invalid_object_load_failure() {
    let _env_guard = ebpf_env_lock().lock().unwrap();
    let original_object = std::env::var_os("WARDER_EBPF_NETWORK_OBJECT");

    let bpf = writable_temp_bpffs("warder-invalid-ebpf-network-object");
    let object_path = bpf.join("warder_network_egress.bpf.o");
    std::fs::write(&object_path, b"not a real object").unwrap();
    std::env::set_var("WARDER_EBPF_NETWORK_OBJECT", &object_path);

    let error = LiveEbpfNetworkEgressReader::attach(EbpfNetworkJournalAttachOptions {
        bpf_fs: bpf.clone(),
    })
    .unwrap_err();

    restore_env_var("WARDER_EBPF_NETWORK_OBJECT", original_object);
    let _ = std::fs::remove_dir_all(&bpf);

    assert!(error
        .message
        .contains("failed to load eBPF network journal object"));
}

#[test]
fn ebpf_attach_plan_blocks_without_bpffs() {
    let plan = plan_ebpf_file_journal_attach(EbpfFileJournalSupport {
        bpffs_available: false,
        attach_available: true,
    });

    assert!(matches!(
        plan.status,
        EbpfFileJournalAttachStatus::Unavailable(message)
            if message.contains("bpffs")
    ));
}

#[test]
fn ebpf_attach_plan_degrades_until_live_reader_exists() {
    let plan = plan_ebpf_file_journal_attach(EbpfFileJournalSupport {
        bpffs_available: true,
        attach_available: false,
    });

    assert!(matches!(
        plan.status,
        EbpfFileJournalAttachStatus::Unavailable(message)
            if message.contains("not implemented")
    ));
}

#[test]
fn ebpf_network_attach_plan_uses_network_journal_language() {
    let missing_bpffs = plan_ebpf_network_journal_attach(EbpfNetworkJournalSupport {
        bpffs_available: false,
        attach_available: true,
    });
    assert!(matches!(
        missing_bpffs.status,
        EbpfNetworkJournalAttachStatus::Unavailable(message)
            if message == "eBPF network journaling unavailable: bpffs is unavailable"
    ));

    let unwired_attach = plan_ebpf_network_journal_attach(EbpfNetworkJournalSupport {
        bpffs_available: true,
        attach_available: false,
    });
    assert!(matches!(
        unwired_attach.status,
        EbpfNetworkJournalAttachStatus::Unavailable(message)
            if message == "eBPF network journaling unavailable: live attach is not implemented yet"
    ));
}

#[derive(Debug)]
struct FakeEbpfReader {
    events: Vec<EbpfFileAccessEvent>,
}

impl EbpfFileAccessReader for FakeEbpfReader {
    fn read_available_events(&mut self) -> Result<Vec<EbpfFileAccessEvent>, FileJournalWatchError> {
        Ok(std::mem::take(&mut self.events))
    }
}

#[derive(Debug)]
struct FakeEbpfNetworkReader {
    events: Vec<EbpfNetworkEgressEvent>,
}

impl EbpfNetworkEgressReader for FakeEbpfNetworkReader {
    fn read_available_events(
        &mut self,
    ) -> Result<Vec<EbpfNetworkEgressEvent>, FileJournalWatchError> {
        Ok(std::mem::take(&mut self.events))
    }
}

fn ebpf_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn restore_env_var(key: &str, value: Option<std::ffi::OsString>) {
    match value {
        Some(value) => std::env::set_var(key, value),
        None => std::env::remove_var(key),
    }
}

fn writable_temp_bpffs(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[derive(Debug)]
struct FailingEbpfReader {
    message: String,
}

#[derive(Debug)]
struct ChunkedRawReader {
    chunks: Vec<Vec<u8>>,
}

impl std::io::Read for ChunkedRawReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.chunks.is_empty() {
            return Ok(0);
        }
        let chunk = self.chunks.remove(0);
        let len = chunk.len().min(buffer.len());
        buffer[..len].copy_from_slice(&chunk[..len]);
        Ok(len)
    }
}

impl EbpfFileAccessReader for FailingEbpfReader {
    fn read_available_events(&mut self) -> Result<Vec<EbpfFileAccessEvent>, FileJournalWatchError> {
        Err(FileJournalWatchError {
            message: self.message.clone(),
        })
    }
}

fn raw_ebpf_record(pid: u32, operation: u8, denied: bool, path: &str) -> Vec<u8> {
    let mut raw = vec![0_u8; EBPF_FILE_ACCESS_RECORD_SIZE];
    raw[0..4].copy_from_slice(&pid.to_ne_bytes());
    raw[4] = operation;
    raw[5] = u8::from(denied);
    raw[6..14].copy_from_slice(&50_u64.to_ne_bytes());
    let path = path.as_bytes();
    raw[14..14 + path.len()].copy_from_slice(path);
    raw[14 + path.len()] = 0;
    raw
}

fn raw_ebpf_network_record(
    pid: u32,
    protocol: u8,
    denied: bool,
    destination_port: Option<u16>,
    destination: &str,
) -> Vec<u8> {
    let mut raw = vec![0_u8; EBPF_NETWORK_EGRESS_RECORD_SIZE];
    raw[0..4].copy_from_slice(&pid.to_ne_bytes());
    raw[4] = protocol;
    raw[5] = u8::from(denied);
    raw[6..8].copy_from_slice(&destination_port.unwrap_or(0).to_ne_bytes());
    raw[8..16].copy_from_slice(&60_u64.to_ne_bytes());
    let destination = destination.as_bytes();
    raw[16..16 + destination.len()].copy_from_slice(destination);
    raw[16 + destination.len()] = 0;
    raw
}

#[cfg(target_os = "linux")]
#[test]
fn inotify_watcher_observes_created_file_in_protected_zone() {
    let root = std::env::temp_dir().join(format!(
        "warder-journal-inotify-{}-{}",
        std::process::id(),
        (UNIX_EPOCH + Duration::from_secs(20))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut watcher = InotifyFileJournalWatcher::watch_zones(&[ProtectedJournalZone {
        id: "notes".to_string(),
        root_paths: vec![root.clone()],
    }])
    .unwrap();

    std::fs::write(root.join("todo.md"), "hello").unwrap();

    let mut events = Vec::new();
    for _ in 0..20 {
        events.extend(watcher.read_available_events("session-1", None).unwrap());
        if events
            .iter()
            .any(|event| event.path == root.join("todo.md"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = std::fs::remove_dir_all(&root);

    assert!(events.iter().any(|event| {
        event.protected_zone_id == Some("notes".to_string())
            && event.path == root.join("todo.md")
            && event.source == JournalSource::Inotify
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn inotify_watcher_observes_created_file_in_existing_nested_directory() {
    let root = std::env::temp_dir().join(format!(
        "warder-journal-inotify-nested-{}-{}",
        std::process::id(),
        (UNIX_EPOCH + Duration::from_secs(30))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let nested = root.join("workspace").join("crate-a");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&nested).unwrap();
    let mut watcher = InotifyFileJournalWatcher::watch_zones(&[ProtectedJournalZone {
        id: "notes".to_string(),
        root_paths: vec![root.clone()],
    }])
    .unwrap();

    std::fs::write(nested.join("todo.md"), "hello").unwrap();

    let mut events = Vec::new();
    for _ in 0..20 {
        events.extend(watcher.read_available_events("session-1", None).unwrap());
        if events
            .iter()
            .any(|event| event.path == nested.join("todo.md"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = std::fs::remove_dir_all(&root);

    assert!(events.iter().any(|event| {
        event.protected_zone_id == Some("notes".to_string())
            && event.path == nested.join("todo.md")
            && event.source == JournalSource::Inotify
            && event.attribution == JournalAttribution::SessionWindow
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn inotify_watcher_observes_file_in_directory_created_after_watch_start() {
    let root = std::env::temp_dir().join(format!(
        "warder-journal-inotify-dynamic-{}-{}",
        std::process::id(),
        (UNIX_EPOCH + Duration::from_secs(40))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let dynamic = root.join("new-workspace");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut watcher = InotifyFileJournalWatcher::watch_zones(&[ProtectedJournalZone {
        id: "notes".to_string(),
        root_paths: vec![root.clone()],
    }])
    .unwrap();

    std::fs::create_dir_all(&dynamic).unwrap();
    for _ in 0..20 {
        let _ = watcher.read_available_events("session-1", None).unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }

    std::fs::write(dynamic.join("todo.md"), "hello").unwrap();

    let mut events = Vec::new();
    for _ in 0..20 {
        events.extend(watcher.read_available_events("session-1", None).unwrap());
        if events
            .iter()
            .any(|event| event.path == dynamic.join("todo.md"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = std::fs::remove_dir_all(&root);

    assert!(events.iter().any(|event| {
        event.protected_zone_id == Some("notes".to_string())
            && event.path == dynamic.join("todo.md")
            && event.source == JournalSource::Inotify
            && event.attribution == JournalAttribution::SessionWindow
    }));
}
