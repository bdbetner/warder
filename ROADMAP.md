# Roadmap

Warder is currently an alpha Linux safety tool for local agent sessions. The CLI, receipt model, protected zones, desktop app, release artifacts, and core Linux enforcement path exist. Future work should make those paths easier to trust before expanding into broader agent-security features.

## Current Alpha Focus

- Make the first-run experience clearer in the CLI and desktop app.
- Keep README, install, release, and security docs aligned with the real implementation.
- Improve protected-zone templates for common secrets and personal data.
- Make receipts easier to scan after a session.
- Keep degraded protections obvious before and after launch.
- Continue validating release artifacts, checksums, and attestations.

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
- Add stronger warnings when running inside containers or other environments that hide process trees or host paths.
- Consider additional snapshot backends only after the Btrfs path remains stable.

## Later Candidates

These features fit Warder only if they strengthen supervised local execution, policy previews, receipts, or recovery:

- Command allow/deny policy for commands launched through `warder run`.
- Dependency-change awareness in receipts without becoming a full vulnerability scanner.
- MCP and external-tool inventory for supervised sessions.
- Optional daemon-backed observation for long-running workflows.
- Destination-aware network policy after live egress logging is reliable enough.

## Non-Goals

Warder should not become a general AI governance platform, cloud scanner, model evaluator, RAG system, browser automation suite, or broad application-security scanner.
