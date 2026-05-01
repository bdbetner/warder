# Receipts And Journals

Warder records local accountability data for supervised sessions. The user-facing result is a receipt, backed by file and network journals where coverage is available.

## Receipt Summary

A receipt should quickly answer:

- What command ran?
- Which agent label and session id were used?
- Which protected zones applied?
- Which protections were active?
- Which protections degraded, and why?
- What file activity was observed?
- What network-journal coverage existed?
- Was a snapshot created?
- What should the user review next?

## Journal Contents

The journal can include:

- Session start and end.
- Agent label and command.
- cgroup tagging status.
- Landlock status.
- Snapshot status.
- Protected path write attempts or changes.
- File-access events from inotify and optional eBPF file-event producers.
- Persisted network egress events where available.
- Degraded-mode warnings.

File journal events use one normalized record shape regardless of source. Network egress events have typed journal records, SQLite persistence, readable summaries, CLI readback through `warder journal --network`, combined file/network readback through `warder journal --all`, and receipt rollups for persisted events.

See [eBPF File Journal](ebpf-file-journal.md) for privileged-host file-journal details.

## Network Visibility Contract

The current live network journal is limited to observed TCP `connect(2)` and UDP `sendto(2)`, `sendmsg(2)`, and `sendmmsg(2)` attempts when live eBPF network journaling is built, configured, and attached, plus procfs connected-socket snapshots during supervised runs when `/proc/<pid>/fd`, `/proc/<pid>/stat`, and `/proc/<pid>/net/*` are readable for the supervised process tree. It is local accountability evidence, not complete socket forensics and not network enforcement.

Known blind spots include short-lived sockets that open and close between procfs polls, connected-socket writes where procfs is unreadable, batched `sendmmsg(2)` destinations after the first message, sockets in processes outside the supervised process tree, destination interpretation above the syscall sockaddr layer, and traffic outside the supervised process attribution window.

Receipts and journal output should keep these limits visible whenever network events are present or when network coverage is degraded.

The journal is local accountability, not tamper-proof forensics.
