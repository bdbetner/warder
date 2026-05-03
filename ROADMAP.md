# Roadmap

Warder is currently a Linux supervised-session safety tool for local agent sessions launched through Warder. The CLI, receipt model, protected zones, desktop app, release artifacts, pre-exec cgroup tagging, seccomp escape-syscall filter, Landlock write denial, experimental read denial, and expanded journals exist. The v1.0 public beta should remain scoped to explicit supervised sessions, not a claim of always-on global sandboxing.

## Current Reviewer Feedback Focus

- Keep release docs, reviewer guide, and package smoke tests aligned with the next public beta tag.
- Collect reviewer feedback through the GitHub issue templates and turn accepted findings into focused tasks.
- Keep README, install, release, and security docs aligned with the real implementation before each public beta or release tag.
- Keep receipt, dry-run, and GUI output impossible to confuse with stronger enforcement than Warder currently provides.
- Keep degraded protections obvious before and after launch.
- Continue validating release artifacts, checksums, and local receipt-key behavior.
- Make the first-run story concrete enough to prove Warder's value in under three minutes.

## Security Hardening Backlog

These review-driven items are implemented and should remain protected by tests:

- Validate snapshot ids before any snapshot-root path construction or restore planning.
- Harden local SQLite state with restrictive permissions, WAL/busy-timeout behavior, and safer migration identifier handling.
- Use random session ids for local receipt/session identifiers.
- Unify path canonicalization and traversal handling across config validation, policy decisions, and Landlock enforcement planning.
- Keep pre-exec cgroup tagging covered for Warder-launched sessions.
- Warn clearly when `network.allowed_destinations` is configured, because destination policy is not enforced in the current public beta.
- Use stable user-scoped XDG state paths by default instead of per-working-directory `.warder` paths.
- Cover symlink/traversal paths, snapshot restore inputs, concurrent DB access, degraded hosts, and journal blind spots with focused tests.

Remaining hardening should focus on global always-on supervision design, broader live-journal compatibility evidence on privileged hosts, public-key receipt transparency, and capability-bounded execution beyond the current seccomp filter.

## Product Proof Path

The first Linux proof path is implemented and should remain protected by tests and smoke scripts:

- `warder demo attack-pack` shows a protected write attempt, protected read status, workspace edit, network attempt, receipt, and journal output from an installed CLI.
- `warder test-host` and `warder verify-host` run local probes and label each control as `proven working`, `configured/planned`, `degraded`, or `unsupported`.
- `warder setup codex|claude|openclaw --workspace <path> --protect-secrets` generates first-run policies from known agent presets. Goose remains out of the near-term setup surface until there is specific reviewer demand.
- `warder codex|claude|openclaw -- [agent args]` provides short launch aliases over the existing supervised `run --launch` path.
- [Protection Matrix](docs/protection-matrix.md) covers common Linux hosts, filesystems, containerized runs, and OpenClaw-specific degraded states.

Remaining product-proof work should focus on reviewer feedback from these flows, clearer remediation guidance, and stronger release artifact signing only after key custody and user verification docs are clear.

## Next Product Improvements

- Improve reviewer onboarding from real feedback on the public beta package and demo flow.
- Split the monolithic CLI implementation into focused modules before adding more command surface.
- Add guided host-readiness remediation from `warder doctor` output.
- Improve snapshot and guarded-revert UX on hosts without Btrfs support.
- Expand command examples for more local agent tools as reviewers request them.
- Add clearer reviewer-facing diagnostics for live journal gaps on unprivileged or containerized hosts.
- Preserve the narrow Rust-command IPC boundary as desktop review flows evolve.

## Enforcement And Observability

- Keep Landlock write denial the primary local enforcement story.
- Keep pre-exec cgroup tagging and process-tree attribution covered by tests.
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
- Public-key receipt transparency after local HMAC/external-key signing remains stable.
- Capability-bound execution after the current Landlock/cgroup/seccomp invariants are tested.

## Non-Goals

Warder should not become a general AI governance platform, cloud scanner, model evaluator, RAG system, browser automation suite, or broad application-security scanner.
