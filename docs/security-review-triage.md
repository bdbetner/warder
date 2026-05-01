# Security Review Triage

This note records the current response to the 2026-05-01 independent security and code reviews. It is a working maintainer-facing summary, not a vulnerability advisory.

## Immediate Priority

The next engineering pass should focus on defects that are concrete, local, and testable:

- Validate snapshot ids before any path join under a snapshot root.
- Harden SQLite state creation, permissions, migrations, concurrency settings, and predictable session ids.
- Make `network.allowed_destinations` impossible to mistake for enforced egress policy.
- Unify path canonicalization and traversal handling across config, policy, snapshot, and Landlock planning.
- Reduce or clearly report the cgroup spawn/tag attribution race.

## Accepted Findings

- Snapshot restore path construction trusts caller-provided snapshot ids too much.
- DB migrations use raw identifier interpolation, even though current callers are internal.
- Local DB/state storage needs stricter permissions and better concurrency behavior.
- Session ids are predictable and should become random.
- Cgroup tagging occurs after spawn, creating a journal attribution window before tagging is complete.
- Network destination allowlists are parsed but not enforced.
- Default `.warder` state paths are per-current-directory, which fragments records and daemon status.
- Daemon runtime state needs atomic writes and stale-PID checks.
- The daemon remains an experimental runtime skeleton, not an active enforcement service.
- eBPF and inotify coverage have known syscall/event blind spots that should be visible in receipts.
- Default secret-path templates need broader, user-extensible coverage.
- Release workflows should pin actions and verify release tags against passing CI.

## Reframed Findings

- The migration helper is unsafe by shape, but it is not currently externally attacker-controlled SQL injection. Fix it as hardening, not as an active injection path.
- `token_hash` is vestigial state. It should either be removed or backed by real runtime authentication, but current configs do not promise authenticated agent identity.
- The cgroup race does not mean Landlock is installed after the child starts; Landlock setup is in the child setup path. The unresolved risk is process attribution and journal coverage before cgroup tagging.
- eBPF is intentionally observation-only today. The bug is any UI, config, or receipt wording that implies observation equals blocking.
- Capability dropping, seccomp, receipt signing, reproducible builds, and GPG signatures are worthwhile future work, but the first hardening slice should fix narrower correctness issues with tests.

## Deferred Or Strategic

- Full network enforcement.
- Expanded Landlock read/execute policy.
- Seccomp and capability-bounded execution.
- Receipt signing and independent verification.
- Daemon IPC and active session coordination.
- Additional snapshot backends.
- eBPF migration or broader syscall coverage.
- Desktop IPC and Tauri capability audit.

## Documentation Rule

Until the hardening backlog is complete, public docs should describe Warder as an alpha supervised-session tool. They may call it a safety tool, but must not imply complete sandboxing, always-on protection, network blocking, tamper-proof forensics, or complete socket/file coverage.
