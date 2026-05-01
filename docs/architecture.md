# Architecture

Warder is a Linux-first CLI and desktop app with small Rust crates for policy, state, enforcement, snapshots, and journaling. The basic supervised-session path does not require a background daemon.

## Components

- `crates/cli`: command-line app.
- `apps/desktop`: native Linux desktop app.
- `crates/config`: config loading and validation.
- `crates/core`: shared domain types.
- `crates/db`: SQLite metadata and session state.
- `crates/enforcement`: cgroup, Landlock, and inotify integration.
- `crates/gui-support`: GUI-safe defaults and config helpers.
- `crates/journal`: file and network journal normalization, persistence, and readback.
- `crates/policy`: protected-zone policy decisions.
- `crates/snapshot`: Btrfs snapshot and guarded revert support.
- `crates/daemon`: optional runtime skeleton for future long-running coordination.

The daemon crate is experimental. It can model start/status/stop state and host capability ticks, but it does not orchestrate normal supervised sessions, cgroups, Landlock, snapshots, or journals.

Do not treat `warder start` as an always-on enforcement mode. The current production path is the CLI-supervised `warder run` flow.

## Session Flow

1. User declares protected zones in config.
2. User starts an agent through `warder run ...`.
3. Warder creates a session record.
4. Warder prepares pre-launch controls such as snapshots and Landlock setup.
5. Warder creates a snapshot when policy requires it.
6. Warder applies Landlock restrictions before launching the agent.
7. Warder tags the launched process with a session/agent cgroup where possible.
8. Warder watches protected paths with inotify.
9. Warder records file and network activity where supported.
10. Warder writes a readable session timeline.
11. User can inspect the journal or revert a supported snapshot.

The current cgroup tag is applied after process spawn. That is a known attribution race for journals and process-tree accounting. Landlock setup uses the child setup path, but receipts still need to report cgroup timing and tagging failures as coverage risks.

## Degraded Mode

Warder must explicitly report when a feature is unavailable. Missing Landlock, unsupported filesystems, unavailable eBPF permissions, or cgroup failures are product states, not hidden implementation details.
