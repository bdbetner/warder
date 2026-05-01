# Security Review Triage

This note records the current response to the 2026-05-01 independent security and code reviews. It is a working maintainer-facing summary, not a vulnerability advisory.

## Immediate Priority

The first engineering passes focused on defects that were concrete, local, and testable:

- Snapshot ids are validated before any path join under a snapshot root.
- SQLite state creation, permissions, migrations, concurrency settings, and session ids were hardened.
- `network.allowed_destinations` is reported as non-enforcing metadata until a blocking backend exists.
- Path canonicalization and traversal handling now have focused tests across config, policy, snapshot, and Landlock planning.
- The cgroup spawn/tag attribution race is reported in receipts; true pre-spawn placement remains a future launcher/helper.

The product-completion pass is now in alpha review. The next security pass should focus on issues that need deeper design or privileged-host evidence: true pre-spawn cgroup placement, broader live-journal coverage, public-key or external receipt attestation, optional seccomp/capability boundaries, and daemon coordination only if a tested workflow requires it.

## Accepted Findings

- Snapshot restore path construction must continue to reject unsafe snapshot ids before path joins.
- DB migrations should keep using fixed allowlisted identifiers.
- Local DB/state storage should keep restrictive permissions and concurrency settings.
- Session ids are random local receipt identifiers, not authentication tokens.
- Cgroup tagging occurs after spawn, creating a journal attribution window before tagging is complete.
- Network destination allowlists are parsed but not enforced.
- Default state paths are user-scoped XDG paths; old `.warder` paths should remain a compatibility concern.
- Daemon runtime state uses atomic writes and stale-PID checks.
- The daemon remains an experimental runtime skeleton, not an active enforcement service.
- eBPF and inotify coverage have known syscall/event blind spots that should be visible in receipts.
- Default secret-path templates need broader, user-extensible coverage.
- Release workflows should pin actions and verify release tags against passing CI.

## Reframed Findings

- The migration helper is unsafe by shape, but it is not currently externally attacker-controlled SQL injection. Fix it as hardening, not as an active injection path.
- `token_hash` is vestigial state. It should either be removed or backed by real runtime authentication, but current configs do not promise authenticated agent identity.
- The cgroup race does not mean Landlock is installed after the child starts; Landlock setup is in the child setup path. The unresolved risk is process attribution and journal coverage before cgroup tagging.
- eBPF is intentionally observation-only today. The bug is any UI, config, or receipt wording that implies observation equals blocking.
- Capability dropping, seccomp, stronger public-key receipt signing, reproducible builds, and GPG signatures are worthwhile future work after the narrower correctness fixes.

## Deferred Or Strategic

- Full network enforcement.
- Expanded Landlock read/execute policy.
- Seccomp and capability-bounded execution.
- Independent/public-key receipt verification beyond the current local HMAC workflow.
- Daemon IPC and active session coordination.
- Additional snapshot backends.
- eBPF migration or broader syscall coverage.
- Desktop IPC and Tauri capability audit.

## Documentation Rule

Public docs should describe Warder as an alpha supervised-session tool. They may call it a safety tool, but must not imply complete sandboxing, always-on protection, network blocking, tamper-proof forensics, or complete socket/file coverage.
