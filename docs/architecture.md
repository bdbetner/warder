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
6. Warder creates the per-session cgroup where configured.
7. Warder moves the child into that cgroup, installs the supervised seccomp filter, and applies Landlock in the child setup path before `exec`.
8. Warder watches protected paths with inotify.
9. Warder records file and network activity where supported.
10. Warder writes a readable session timeline.
11. User can inspect the journal or revert a supported snapshot.

The current launcher closes the prior post-spawn cgroup tagging race for Warder-launched sessions by moving the child into the session cgroup in the `pre_exec` setup path before user code runs. This does not contain direct processes launched outside Warder, and cgroup setup failures still have to be reported as coverage risks.

## Degraded Mode

Warder must explicitly report when a feature is unavailable. Missing Landlock, unsupported filesystems, unavailable eBPF permissions, or cgroup failures are product states, not hidden implementation details.
