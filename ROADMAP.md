# Roadmap

Warder is currently an alpha Linux safety tool for local agent sessions. The CLI, receipt model, protected zones, desktop app, release artifacts, and core Linux enforcement path exist. Future work should make those paths easier to trust before expanding into broader agent-security features.

## Current Alpha Focus

- Fix the highest-confidence security review findings before expanding feature scope.
- Keep README, install, release, and security docs aligned with the real implementation.
- Make receipt and dry-run output impossible to confuse with stronger enforcement than Warder currently provides.
- Improve protected-zone templates for common secrets and personal data.
- Keep degraded protections obvious before and after launch.
- Continue validating release artifacts, checksums, and attestations.

## Security Hardening Backlog

These items take priority over new integrations:

- Validate snapshot ids before any snapshot-root path construction or restore planning.
- Harden local SQLite state with restrictive permissions, WAL/busy-timeout behavior, and safer migration identifier handling.
- Replace predictable timestamp-based session ids with random session ids.
- Unify path canonicalization and traversal handling across config validation, policy decisions, and Landlock enforcement planning.
- Reduce the cgroup spawn/tag attribution race, and keep receipts honest when a race or tagging failure leaves journal coverage incomplete.
- Warn clearly when `network.allowed_destinations` is configured, because destination policy is not enforced in the current alpha.
- Move default state paths toward stable user-scoped XDG locations instead of per-working-directory `.warder` paths.
- Add adversarial tests for symlink/traversal paths, snapshot restore inputs, concurrent DB access, degraded hosts, and journal blind spots.

## Next Product Improvements

- Richer receipt review for file changes, blocked writes, network observations, dependency-file changes, snapshots, and recovery actions.
- Safer defaults for common credential paths such as SSH, GPG, cloud credentials, kube config, `.env` files, browser profiles, and wallet files.
- More guided desktop setup for non-expert users.
- Better command examples for common local agent tools.
- Clearer recovery flows around Btrfs snapshots and guarded revert.
- More host-readiness checks in `warder doctor`.

## Enforcement And Observability

- Keep Landlock write denial the primary local enforcement story.
- Harden cgroup tagging and process-tree attribution.
- Expand eBPF file and network journal validation on privileged hosts.
- Keep network journaling framed as visibility, not complete network control.
- Treat `network.allowed_destinations` as non-enforcing until a blocking implementation exists.
- Add stronger warnings when running inside containers or other environments that hide process trees or host paths.
- Consider additional snapshot backends only after the Btrfs path remains stable.

## Later Candidates

These features fit Warder only if they strengthen supervised local execution, policy previews, receipts, or recovery:

- Command allow/deny policy for commands launched through `warder run`.
- Dependency-change awareness in receipts without becoming a full vulnerability scanner.
- MCP and external-tool inventory for supervised sessions.
- Optional daemon-backed observation for long-running workflows.
- Destination-aware network policy after live egress logging is reliable enough.
- Receipt signing/verification after basic local state permissions and DB concurrency are hardened.
- Seccomp/capability-bound execution after the current Landlock/cgroup invariants are tested.

## Non-Goals

Warder should not become a general AI governance platform, cloud scanner, model evaluator, RAG system, browser automation suite, or broad application-security scanner.
