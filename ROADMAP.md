# Roadmap

Warder is currently an alpha Linux safety tool for local agent sessions. The CLI, receipt model, protected zones, desktop app, release artifacts, and core Linux enforcement path exist. The `v0.1.0-alpha.11` release is ready for reviewer feedback; future work should make those paths easier to trust before expanding into broader agent-security features.

## Current Reviewer Feedback Focus

- Keep release docs, reviewer guide, and package smoke tests aligned with `v0.1.0-alpha.11`.
- Collect reviewer feedback through the GitHub issue templates and turn accepted findings into focused tasks.
- Keep README, install, release, and security docs aligned with the real implementation before each alpha tag.
- Keep receipt, dry-run, and GUI output impossible to confuse with stronger enforcement than Warder currently provides.
- Keep degraded protections obvious before and after launch.
- Continue validating release artifacts, checksums, and local receipt-key behavior.

## Security Hardening Backlog

These review-driven items are implemented and should remain protected by tests:

- Validate snapshot ids before any snapshot-root path construction or restore planning.
- Harden local SQLite state with restrictive permissions, WAL/busy-timeout behavior, and safer migration identifier handling.
- Use random session ids for local receipt/session identifiers.
- Unify path canonicalization and traversal handling across config validation, policy decisions, and Landlock enforcement planning.
- Report the cgroup spawn/tag attribution race when journal coverage may be incomplete.
- Warn clearly when `network.allowed_destinations` is configured, because destination policy is not enforced in the current alpha.
- Use stable user-scoped XDG state paths by default instead of per-working-directory `.warder` paths.
- Cover symlink/traversal paths, snapshot restore inputs, concurrent DB access, degraded hosts, and journal blind spots with focused tests.

Remaining hardening should focus on true pre-spawn cgroup placement, broader live-journal coverage on privileged hosts, public-key or external receipt attestation, and optional seccomp/capability-bounded execution.

## Next Product Improvements

- Improve reviewer onboarding from real feedback on the alpha package and demo flow.
- Add guided host-readiness remediation from `warder doctor` output.
- Improve snapshot and guarded-revert UX on hosts without Btrfs support.
- Expand command examples for more local agent tools as reviewers request them.
- Add clearer reviewer-facing diagnostics for live journal gaps on unprivileged or containerized hosts.
- Preserve the narrow Rust-command IPC boundary as desktop review flows evolve.

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
- Public-key receipt signing or external receipt attestations after local HMAC signing remains stable.
- Seccomp/capability-bound execution after the current Landlock/cgroup invariants are tested.

## Non-Goals

Warder should not become a general AI governance platform, cloud scanner, model evaluator, RAG system, browser automation suite, or broad application-security scanner.
