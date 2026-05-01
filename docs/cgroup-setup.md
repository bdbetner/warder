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

## Pre-Spawn Tagging Strategy

Current CLI launches apply Landlock in the child setup path before `exec`, but cgroup tagging is applied immediately after `spawn` by writing the child PID to `cgroup.procs`. Receipts intentionally call this `tagged post-spawn` and record a degraded attribution reason because very early process accounting can be incomplete.

The practical implementation options are:

- Keep the current post-spawn write for the portable CLI path and make the receipt language explicit. This is the current behavior.
- Use a delegated writable cgroup root so unprivileged Warder sessions can create per-session cgroups without broad host privileges. This improves reliability but does not remove the post-spawn window by itself.
- Add a Linux-specific launcher/helper that creates the child directly inside the target cgroup, preferably with `clone3(CLONE_INTO_CGROUP)` where available. This is the right direction for true pre-spawn attribution, but it should be isolated behind a small launcher boundary because it changes process creation, error handling, and kernel compatibility.

Do not present delegated cgroup setup as equivalent to pre-spawn placement. Delegation answers "can Warder write the cgroup tree"; `clone3(CLONE_INTO_CGROUP)` or an equivalent helper answers "was the process born in the session cgroup."

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
  --agent local \
  -- sh -c 'true'
```

If the delegated scope path is not writable or lacks `cgroup.procs`, Warder must treat cgroup tagging as unsupported/degraded instead of silently running an untagged session.

For configs with `cgroups = "required"`, `warder run --launch` refuses to start unless `--cgroup-root` is provided and looks like cgroup v2. For configs with `cgroups = "best-effort"`, launch can proceed without a usable `--cgroup-root`, but the receipt records cgroup tagging as degraded and includes the skipped-tagging reason. For configs with `cgroups = "disabled"`, launch records cgroup tagging as not requested.
