# Security Review Triage

This note records the current response to the 2026-05-01 independent security and code reviews. It is a working maintainer-facing summary, not a vulnerability advisory.

## Immediate Priority

The first engineering passes focused on defects that were concrete, local, and testable:

- Snapshot ids are validated before any path join under a snapshot root.
- SQLite state creation, permissions, migrations, concurrency settings, and session ids were hardened.
- `network.allowed_destinations` is reported as non-enforcing metadata until a blocking backend exists.
- Path canonicalization and traversal handling now have focused tests across config, policy, snapshot, and Landlock planning.
- Config validation rejects Landlock writable roots that overlap write-denied protected zones and warns when writable roots are ignored because Landlock is disabled.
- Live eBPF records now include kernel cgroup ids and attach broader fd-write, writable-mmap, file-copy, and socket-fd tracepoints, while receipts still state that unresolved fd/mmap observations are visibility-only.
- SQLite uses WAL with full synchronous durability for Warder connections, and session records have a local Merkle-style hash chain with `warder verify-receipts` fail-closed verification.
- The cgroup spawn/tag attribution race is reported in receipts; true pre-spawn placement remains a future launcher/helper.

The product-completion pass is now in alpha review. The next security pass should focus on issues that need deeper design or privileged-host evidence: true pre-spawn cgroup placement, broader live-journal coverage, public-key or external receipt attestation, optional seccomp/capability boundaries, and daemon coordination only if a tested workflow requires it.

## Accepted Findings

- Snapshot restore path construction must continue to reject unsafe snapshot ids before path joins.
- DB migrations should keep using fixed allowlisted identifiers.
- Local DB/state storage should keep restrictive permissions and concurrency settings.
- Session ids are random local receipt identifiers, not authentication tokens.
- Cgroup tagging occurs after spawn, creating a journal attribution window before tagging is complete.
- Network destination allowlists are parsed but not enforced.
- Config validation should keep catching policy contradictions such as writable roots overlapping write-denied protected zones.
- Default state paths are user-scoped XDG paths; old `.warder` paths should remain a compatibility concern.
- Daemon runtime state uses atomic writes and stale-PID checks.
- The daemon remains an experimental runtime skeleton, not an active enforcement service.
- eBPF and inotify coverage have known syscall/event blind spots that should be visible in receipts.
- Default secret-path templates need broader, user-extensible coverage.
- Release workflows should pin actions and verify release tags against passing CI.
- The desktop CSP must not be null, and Tauri capability tests should keep plugin permissions narrow.
- Desktop launches should default toward strict write-blocking, with best-effort degraded launches remaining an explicit user choice.
- Desktop launch commands must fail closed unless the request records that launch readiness was reviewed, so the doctor/review gate is not only a disabled frontend button.
- CLI launches now fail closed on degraded pre-launch readiness unless `--accept-degraded` is passed. The desktop passes that acknowledgement only for best-effort mode; strict write-blocking remains the default setup posture.
- Receipt text and JSON should always state the limits around outside-Warder commands, read protection, network enforcement, and local receipt tamper resistance.
- CI should include `cargo audit` so known RustSec vulnerabilities are visible before release.

## Reframed Findings

- The migration helper is unsafe by shape, but it is not currently externally attacker-controlled SQL injection. Fix it as hardening, not as an active injection path.
- `token_hash` is vestigial state. It should either be removed or backed by real runtime authentication, but current configs do not promise authenticated agent identity.
- The cgroup race does not mean Landlock is installed after the child starts; Landlock setup is in the child setup path. The unresolved risk is process attribution and journal coverage before cgroup tagging.
- eBPF is intentionally observation-only today. The bug is any UI, config, or receipt wording that implies observation equals blocking.
- Expanding eBPF to broad syscall, LSM, or cgroup-map coverage is not a small bug fix. Treat it as a privileged-host observability project with its own design and validation matrix.
- Local HMAC receipt signing should remain optional in alpha. Requiring a key for every receipt would make basic receipt review fragile; the correct current behavior is to fail closed only when signing, signature verification, or local receipt-chain verification is explicitly requested.
- `cargo audit --deny warnings` is not yet a practical CI gate because Tauri's Linux desktop stack currently pulls transitive RustSec warnings for unmaintained GTK3/WebKit-adjacent crates. Keep the vulnerability scan, document the warning debt, and reassess when the upstream stack has a migration path.
- Capability dropping, seccomp, stronger public-key receipt signing, reproducible builds, and GPG signatures are worthwhile future work after the narrower correctness fixes.

## Deferred Or Strategic

- Full network enforcement.
- Expanded Landlock read/execute policy.
- Pre-spawn cgroup placement or a minimal launcher/helper that eliminates the current attribution race.
- Seccomp and capability-bounded execution.
- Independent/public-key receipt verification beyond the current local HMAC workflow.
- Daemon IPC and active session coordination.
- Additional snapshot backends.
- eBPF migration or broader syscall/LSM/cgroup-map coverage.

## Documentation Rule

Public docs should describe Warder as an alpha supervised-session tool. They may call it a safety tool, but must not imply complete sandboxing, always-on protection, network blocking, tamper-proof forensics, or complete socket/file coverage.
