# Security Model

Warder treats agent processes as untrusted. The core boundary is not a cooperative API; it is the execution context Warder creates for an agent session.

## What Warder Can Do

- Launch a command as a supervised session.
- Apply protected-zone policy to that session.
- Deny protected writes with Landlock where supported.
- Tag the session with cgroups where available.
- Watch protected paths for file activity.
- Record network observations where configured and supported.
- Snapshot supported Btrfs roots before a session.
- Produce receipts that explain active and degraded protections.

## What Warder Cannot Promise

- It cannot supervise commands that were not launched through Warder.
- It cannot make unsupported kernels or filesystems enforce features they do not support.
- It cannot provide tamper-proof local forensics.
- It cannot prove that quiet logs mean nothing happened.
- It cannot provide complete socket forensics or network enforcement in the current alpha.
- It cannot enforce `network.allowed_destinations` yet; that field must be treated as non-blocking until a network enforcement backend exists.

## Protected Zones

A protected zone is a named set of paths with policy. Paths are explicit and local. Whole-home protection is not inferred by default.

## Session Identity

Each supervised run has a session id, agent label, process metadata, and cgroup tagging state. If Warder cannot tag the process tree, the session must report degraded enforcement.

Current session ids are local receipt identifiers, not secrets or authentication tokens. The alpha should replace predictable ids with random ids before relying on them for privacy-sensitive workflows.

## Filesystem Enforcement

Landlock is the preferred mechanism for preventing writes to protected paths. Path checks must canonicalize where possible and handle symlink/traversal cases deliberately.

Path canonicalization is a hardening priority. Config validation, policy checks, snapshot restore inputs, and enforcement planning must converge on one tested path-normalization model so symlink and traversal behavior is deliberate rather than accidental.

## Observation

inotify watches protected paths for changes. eBPF file journaling can record live file access on privileged hosts and reports degraded coverage when BPF privileges or host support are unavailable.

Network egress journaling has typed storage/readback, optional live eBPF observation for TCP `connect(2)` and UDP `sendto(2)`/`sendmsg(2)`/`sendmmsg(2)` attempts, and procfs connected-socket snapshots for the supervised process tree during supervised runs when the host exposes process fd and network tables.

These journals improve accountability. They are not the primary write-denial boundary and must not be described as complete socket forensics or network enforcement.

Cgroup tagging supports attribution for journals and receipts. If tagging happens after spawn or fails for a process tree, the receipt should treat the attribution window as incomplete even when Landlock enforcement was installed through the child setup path.

## Snapshots

Snapshots make supported sessions reversible. A policy may require a snapshot before allowing the agent to start. If no backend is available, Warder must fail closed or clearly mark the session as unsnapshotted according to policy.
