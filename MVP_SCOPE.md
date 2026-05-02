# Alpha Scope

Warder's current public beta is a Linux tool a user can install and test quickly: declare protected zones, run a local agent command through Warder, inspect a readable receipt afterward, see what protections degraded, and recover with snapshots where supported.

## Included

- CLI workflow for supervised sessions.
- Native Linux desktop companion for setup, launch, and review.
- Commands for `init`, `explain`, `dry-run`, `run`, `receipt`, `verify-receipts`, `receipt-key`, `journal`, `snapshot`, `revert`, `doctor`, `profiles`, and `status`.
- TOML and YAML config.
- Transparent local profiles for common agent commands.
- Protected zones with explicit path policy.
- Agent identity and cgroup tagging.
- Tool-agnostic supervised sessions launched through `warder run`.
- Persisted session records with lifecycle state, policy state, and degraded reasons.
- Human-readable and JSON session receipts.
- Local HMAC receipt signing and verification with private key-file checks.
- Session review covering command, protected zones, file activity, degraded enforcement, snapshot state, and recovery options.
- Landlock-backed write denial where supported.
- inotify watches for protected paths.
- Optional eBPF file and network observation where built and permitted.
- Live Btrfs snapshot creation and guarded Btrfs restore for missing target paths.
- Network egress journal storage/readback and receipt summaries for persisted events.
- SQLite metadata for config state, sessions, snapshots, and journals.
- `.deb`, RPM, AppImage, checksum, and release-manifest artifacts for public beta releases.

## Optional Or Experimental

- `start` and `stop` daemon commands for experiments with long-running coordination.
- Daemon-backed policy summaries and host capability probes.
- Advanced eBPF collection paths on privileged hosts.

## Excluded

- Cloud connectors.
- Browser control.
- Email/calendar automation.
- Plugin marketplace.
- Hosted service.
- Vector search.
- AI model calls.
- Broad AI governance.
- Required daemon for the basic `warder run` workflow.
- Hidden profile behavior that cannot be explained before launch.
- First-class Docker or container-runtime enforcement.
- Claims of perfect containment across every Linux kernel and filesystem.

## Later Candidates

- Container-aware execution for Docker/OpenClaw-style management flows, starting as explicit degraded mode unless Warder can verify the needed host protections.
- Richer receipt exports and diff reviews that summarize what a supervised session changed, contacted, blocked, and can revert.
- Dependency-change summaries from package-manager commands or dependency-file diffs.
- Simple command/tool allow, deny, and approval policy for commands launched through `warder run`.
- Secret-path default templates for common local credential stores, kept as explicit protected-zone policy rather than broad content scanning.
- MCP/tool-surface inventory for supervised sessions, limited to local capability labeling and receipt context rather than a plugin marketplace.
