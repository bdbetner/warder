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
- Warder-launched sessions prepare the session cgroup before spawn and move the child into it from the child setup path before exec.
- Strict launches require an external receipt key, and `warder verify-receipts --external-key` validates that key path while checking the local hash chain.
- Supervised child setup installs a small seccomp filter for namespace and mount escape syscalls.
- Experimental read denial is available through `read_deny = true` or `read_policy = "deny"` with explicit disjoint readable roots.
- Landlock rule paths are revalidated immediately before `landlock_restrict_self` in the supervised child setup path.
- Launch state paths must be outside protected/writable policy surfaces and, on Unix, inside private parent directories.
- Warder attempts best-effort cgroup resource limits for launched sessions and records applied limits or degraded failures.
- Receipts include a non-numeric journal coverage estimate and concrete blind-spot list instead of implying complete forensic coverage.
- Config validation rejects shared scratch roots such as `/tmp` and warns on common cache/build scratch paths.

The product-completion pass is now in public-beta preparation. The remaining strategic item is global always-on supervision for processes not launched through Warder; it remains out of scope until a real privileged host service can be designed and tested.

## Resolved Production Items

The final production-hardening pass resolved the concrete items that were previously tracked as blockers for Warder-launched sessions:

- Pre-exec cgroup setup is implemented for Warder-launched sessions; the child setup path joins the session cgroup before `exec`.
- The supervised seccomp filter blocks namespace and mount escape syscalls for Warder-launched sessions.
- Experimental Landlock read denial is wired through policy, receipts, doctor output, and semantic validation.
- Strict launches require an external receipt key, and receipt verification supports the same external-key path.
- Doctor and pre-launch output render per-hook eBPF tracepoint readiness instead of a single coarse status line.
- Receipts, pre-launch output, doctor, docs, and the desktop first-launch banner all state that Warder does not supervise direct launches outside `warder run` or the desktop launcher.

## Accepted Findings

- Snapshot restore path construction must continue to reject unsafe snapshot ids before path joins.
- DB migrations should keep using fixed allowlisted identifiers.
- Local DB/state storage should keep restrictive permissions and concurrency settings.
- Local DB/state storage is still not tamper-proof against unrelated same-UID malware, even with private directory checks.
- Session ids are random local receipt identifiers, not authentication tokens.
- Cgroup tagging for `warder run --launch` is prepared before spawn and applied in the child setup path before exec. Commands launched directly outside Warder are still completely unsupervised.
- Network destination allowlists are parsed but not enforced.
- Config validation should keep catching policy contradictions such as writable roots overlapping write-denied protected zones.
- Default state paths are user-scoped XDG paths; old `.warder` paths should remain a compatibility concern.
- Daemon runtime state uses atomic writes and stale-PID checks.
- The daemon remains an experimental runtime skeleton, not an active enforcement service.
- eBPF and inotify coverage have known syscall/event blind spots that should be visible in receipts.
- Snapshot fallback beyond Btrfs/OverlayFS remains a reliability improvement, not a hidden enforcement guarantee.
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
- Pre-exec cgroup tagging and Landlock setup now share the supervised child setup path for Warder-launched sessions. The unresolved risk is global bypass: processes launched outside Warder are not supervised.
- eBPF is intentionally observation-only today. The bug is any UI, config, or receipt wording that implies observation equals blocking.
- Expanding eBPF to broad syscall, LSM, or cgroup-map coverage is not a small bug fix. Treat it as a privileged-host observability project with its own design and validation matrix.
- Local HMAC receipt signing remains optional for best-effort review, but strict launches require an external receipt key so strict sessions can produce externally signed receipts.
- `cargo audit --deny warnings` is not yet a practical CI gate because Tauri's Linux desktop stack currently pulls transitive RustSec warnings for unmaintained GTK3/WebKit-adjacent crates. Keep the vulnerability scan, document the warning debt, and reassess when the upstream stack has a migration path.
- Capability dropping, broader public-key receipt transparency, reproducible builds, and package-manager signatures remain worthwhile future work after the narrower correctness fixes.

## Deferred Or Strategic

- Global always-on supervision or a privileged host service for commands not launched through Warder.

## Future Hardening Candidates

- Full network enforcement.
- Productionizing experimental read denial beyond the current Landlock allowlist model.
- Capability-bounded execution beyond the current seccomp syscall filter.
- Independent/public-key receipt transparency beyond the current local HMAC/hash-chain workflow.
- Daemon IPC and active session coordination.
- Additional snapshot backends.
- eBPF migration or broader syscall/LSM/cgroup-map coverage.

## Documentation Rule

Public docs should describe Warder as a supervised-session safety tool. They may call it a safety layer for Warder-launched sessions, but must not imply complete sandboxing, always-on protection, network blocking, tamper-proof forensics, or complete socket/file coverage.
