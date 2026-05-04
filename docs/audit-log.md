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

The current live file eBPF journal covers common path-based file syscalls plus fd-write, `ftruncate(2)`, writable `mmap(2)`/`mprotect(2)`, `sendfile(2)`, `splice(2)`, and `copy_file_range(2)` surfaces when built, configured, and attached. Descriptor and mmap observations are synthetic warning signals because syscall tracepoints cannot always resolve them back to stable protected paths. The current live network journal covers observed TCP `connect(2)`, UDP `sendto(2)`, `sendmsg(2)`, and `sendmmsg(2)` attempts, selected socket-fd send surfaces, plus procfs connected-socket snapshots during supervised runs when `/proc/<pid>/fd`, `/proc/<pid>/stat`, and `/proc/<pid>/net/*` are readable for the supervised process tree. It is local accountability evidence, not complete socket forensics and not network enforcement.

Known blind spots include fd and mmap observations that cannot be resolved to protected paths, bind mounts, namespace changes, unsupported syscall families, short-lived sockets that open and close between procfs polls, connected-socket writes where neither eBPF nor procfs can resolve the peer, batched `sendmmsg(2)` destinations after the first message, sockets in processes outside the supervised process tree, destination interpretation above the syscall sockaddr layer, and traffic outside the supervised process attribution window.

If a config contains `network.allowed_destinations`, receipts must not imply that those destinations were enforced until Warder has a blocking egress implementation. In the current public beta, destination policy should be reported as planned or non-enforcing metadata.

Pre-launch readiness, receipts, and journal output should keep these limits visible. Warder reports journal blind spots as visibility limits, separate from enforcement readiness, so users can distinguish "write blocking is unavailable" from "observation is incomplete."

## Receipt Signing

Receipts can be signed with a local HMAC-SHA256 key file:

```bash
warder receipt-key init --output ~/.local/state/warder/receipt-signing.key
warder receipt --db .warder/warder.db --session <session-id> --signing-key-file <path>
# Equivalent alias for an externally managed key path:
warder receipt --db .warder/warder.db --session <session-id> --receipt-key $XDG_RUNTIME_DIR/warder/receipt.key
```

The key file must contain at least 32 bytes after trailing line endings are trimmed. On Unix-like systems, Warder refuses signing keys that are readable or writable by group/other users. Keep the key outside any path the supervised command can write.

To verify a receipt signature, render the same receipt format with the same key and pass the expected hex signature:

```bash
warder receipt --db .warder/warder.db --session <session-id> --signing-key-file <path> --verify-signature <hex>
```

This is local shared-secret integrity, not public-key non-repudiation. A same-UID process, user, or malware that can modify Warder's local state or read/write the signing key can still undermine receipt trust, even when Warder enforces private state-directory placement.

## Local Receipt Integrity Chain

Warder stores a local hash-chain entry whenever a session record is created or updated. This lets reviewers detect common local tampering such as edited session rows or missing integrity history:

```sh
warder verify-receipts --db .warder/warder.db --external-key $XDG_RUNTIME_DIR/warder/receipt.key
```

The command fails closed if any session has no integrity entry, if the chain links are inconsistent, or if the current session record no longer matches the latest logged payload hash. This is still local accountability, not tamper-proof forensics: a same-UID process with write access to Warder's state can attempt to alter both the data and the chain.
