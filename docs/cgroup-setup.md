# Cgroup Setup

Warder uses cgroup v2 tagging to keep supervised agent process trees identifiable. The default probe expects a cgroup v2 root at `/sys/fs/cgroup`.

## Live Check

The normal workspace test suite does not mutate the host cgroup tree. To test live tagging explicitly, run:

```bash
cargo test -p warder-enforcement live_cgroup_v2_tag_current_process_when_writable -- --ignored --nocapture
```

The test uses `/sys/fs/cgroup` by default. To test a delegated writable cgroup root instead:

```bash
WARDER_LIVE_CGROUP_ROOT=/sys/fs/cgroup/warder-dev \
  cargo test -p warder-enforcement live_cgroup_v2_tag_current_process_when_writable -- --ignored --nocapture
```

## Expected States

- `Tagged`: Warder can create `warder/<session-id>` below the selected cgroup root and write the target PID to `cgroup.procs`.
- `Unsupported`: cgroup v2 is missing, the selected root does not contain `cgroup.procs`, or the current user cannot create session cgroups there.

On this workstation, `/sys/fs/cgroup` is present but not writable by the current session, so the live test reports permission-denied tagging as unsupported rather than failing the regular test suite.

## Delegation Notes

For development, use a dedicated writable cgroup subtree rather than the global root. The setup mechanism can be systemd delegation, a temporary root-owned helper, or another explicit admin step, but Warder should report degraded mode unless it can verify the selected root is writable and cgroup v2-compatible.

## Pre-Exec Tagging Strategy

CLI and desktop launches create the per-session cgroup before spawning the child. The child setup path then writes `0` to that session cgroup's `cgroup.procs` before `exec`, installs Warder's supervised seccomp filter, and applies Landlock where available. That closes the previous post-spawn attribution window for Warder-launched commands.

This still is not a global sandbox. Delegation answers "can Warder write the cgroup tree"; it does not force unrelated direct processes into Warder. Future privileged/global modes may use `clone3(CLONE_INTO_CGROUP)` or a narrower helper where that gives better kernel-level guarantees.

## systemd Delegated Scope Example

On a systemd host, create a delegated user-owned scope and use that scope's cgroup path as Warder's cgroup root:

```bash
systemd-run --user --scope --property=Delegate=yes --same-dir sleep infinity
```

Find the delegated scope:

```bash
systemctl --user status --no-pager 'run-*.scope'
```

The cgroup path is usually under:

```text
/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice/<scope-name>.scope
```

Then run the live tagging check against that delegated root:

```bash
WARDER_LIVE_CGROUP_ROOT="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice/<scope-name>.scope" \
  cargo test -p warder-enforcement live_cgroup_v2_tag_current_process_when_writable -- --ignored --nocapture
```

Use the same root for supervised runs:

```bash
warder run \
  --config examples/protected-zones/readonly-research.toml \
  --cgroup-root "/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice/<scope-name>.scope" \
  --launch \
    --accept-degraded \
  --agent local \
  -- sh -c 'true'
```

If the delegated scope path is not writable or lacks `cgroup.procs`, Warder must treat cgroup tagging as unsupported/degraded instead of silently running an untagged session.

For configs with `cgroups = "required"`, `warder run --launch` refuses to start unless `--cgroup-root` is provided and looks like cgroup v2. For configs with `cgroups = "best-effort"`, launch without a usable `--cgroup-root` requires `--accept-degraded`; the receipt records cgroup tagging as degraded and includes the skipped-tagging reason. For configs with `cgroups = "disabled"`, launch records cgroup tagging as not requested.
