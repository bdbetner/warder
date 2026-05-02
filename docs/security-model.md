# Security Model

Warder treats agent processes as untrusted. The core boundary is not a cooperative API; it is the execution context Warder creates for an agent session.

## What Warder Can Do

- Launch a command as a supervised session.
- Apply protected-zone policy to that session.
- Deny protected writes with Landlock where supported.
- Deny protected reads only when an explicit experimental read-blocking policy and disjoint readable-root allowlist are configured.
- Tag the session with cgroups where available.
- Watch protected paths for file activity.
- Record network observations where configured and supported.
- Snapshot supported Btrfs roots before a session.
- Produce receipts that explain active and degraded protections.

## What Warder Cannot Promise

- It cannot supervise commands that were not launched through `warder run` or the Warder desktop launcher. Direct launches or processes started by malware are completely unsupervised.
- It cannot make unsupported kernels or filesystems enforce features they do not support.
- It cannot provide tamper-proof local forensics.
- It cannot prove that quiet logs mean nothing happened.
- It cannot provide complete socket forensics or network enforcement in the current alpha.
- It cannot enforce `network.allowed_destinations` yet; that field must be treated as non-blocking until a network enforcement backend exists.

## Protected Zones

A protected zone is a named set of paths with policy. Paths are explicit and local. Whole-home protection is not inferred by default.

## Session Identity

Each supervised run has a session id, agent label, process metadata, and cgroup tagging state. If Warder cannot tag the process tree, the session must report degraded enforcement.

Session ids are random local receipt identifiers, not secrets or authentication tokens. They are suitable for lookup and correlation, but they should not be used as proof of identity or authorization.

## Filesystem Enforcement

Landlock is the preferred mechanism for preventing writes to protected paths. Path checks canonicalize where possible and reject traversal or unsafe overlaps in config, policy, snapshot, and enforcement planning paths. Missing paths and symlinks are handled deliberately so receipts can describe what was actually enforced or degraded.

`read_deny = true` or `read_policy = "deny"` is available as an explicit experimental policy. It requires `enforcement.readable_roots` and rejects readable roots that overlap read-denied protected paths. Warder also rejects parent/child protected-zone overlaps when read denial is active. Landlock is allowlist-based, so read blocking is not a subtractive "hide this one folder from everything" rule. A bad readable-root allowlist can block agent dependencies or accidentally re-allow a protected path, so Warder fails config validation on contradictory read/write policy and overlapping readable roots.

Best-effort launches may continue with degraded protection only after the caller passes `warder run --accept-degraded`. Without that acknowledgement, Warder refuses to spawn the command when pre-launch checks find degraded coverage. Strict launches with `warder run --require-enforcement` refuse to start when any required protected write blocking is not active or when `--receipt-key <path>` is missing/unreadable.

Snapshot ids are validated before restore path construction. Restore planning must continue to reject path separators, traversal, absolute paths, and empty ids before joining anything below a snapshot root.

## Observation

inotify watches protected paths for changes. eBPF file journaling can record live file access on privileged hosts and reports degraded coverage when BPF privileges or host support are unavailable.

Network egress journaling has typed storage/readback, optional live eBPF observation for TCP `connect(2)`, UDP `sendto(2)`/`sendmsg(2)`/`sendmmsg(2)`, selected socket-fd send surfaces, and procfs connected-socket snapshots for the supervised process tree during supervised runs when the host exposes process fd and network tables.

These journals improve accountability. They are not the primary write-denial boundary and must not be described as complete socket forensics or network enforcement.

Cgroup tagging supports attribution for journals and receipts. Warder-launched sessions create the session cgroup before spawn and move the child into it from the child setup path before `exec`. If cgroup setup fails, the launch fails or degrades according to policy; processes launched directly outside Warder remain out of scope.

The supervised setup path also installs a small seccomp filter that denies mount and namespace escape syscalls including `unshare`, `mount`, `umount2`, `pivot_root`, and `setns`.

## Snapshots

Snapshots make supported sessions reversible. A policy may require a snapshot before allowing the agent to start. If no backend is available, Warder must fail closed or clearly mark the session as unsnapshotted according to policy.
