# Prototype Demo

This demo exercises Warder's CLI-first path without requiring a real delegated cgroup tree or snapshot backend. It uses throwaway paths under `/tmp/warder-demo` or `WARDER_DEMO_ROOT`.

For the lowest-friction smoke path, use:

```bash
scripts/quickstart-demo.sh
```

That quickstart writes a throwaway config under `/tmp/warder-quickstart` or `WARDER_QUICKSTART_ROOT`, does not require `--cgroup-root`, disables live network/eBPF journaling for a cleaner first run, and records cgroup tagging as degraded because the config marks cgroups as best-effort. `examples/prototype/quickstart.toml` and `examples/prototype/quickstart.yaml` keep the same policy shape in checked-in form for config-format tests.

To run the whole smoke path:

```bash
scripts/prototype-demo.sh
```

The script writes a throwaway config under the selected demo root so custom `WARDER_DEMO_ROOT` runs protect and watch the same directory the command writes to. `examples/prototype/local-demo.toml` keeps the checked-in default policy shape for docs and config-format tests.

## Setup

```bash
rm -rf /tmp/warder-demo
mkdir -p /tmp/warder-demo/protected /tmp/warder-demo/cgroup
touch /tmp/warder-demo/cgroup/cgroup.procs
```

The `cgroup` directory is a local fake cgroup root for prototype smoke testing. It lets Warder exercise the tagging path without claiming real kernel cgroup enforcement.

## Preflight

```bash
cargo run -p warder-cli -- dry-run \
  --config examples/prototype/local-demo.toml \
  --agent local-shell \
  -- sh -c 'echo hello > /tmp/warder-demo/protected/hello.txt'
```

Expected shape:

- `launch: no command was run`
- `profile: local-script`
- `snapshot: not requested`

## Launch

```bash
cargo run -p warder-cli -- run \
  --config examples/prototype/local-demo.toml \
  --db /tmp/warder-demo/warder.sqlite3 \
  --cgroup-root /tmp/warder-demo/cgroup \
  --launch \
  --agent local-shell \
  -- sh -c 'echo hello > /tmp/warder-demo/protected/hello.txt'
```

Expected shape:

- A session id is printed.
- The command exits with code `0`.
- The receipt shows `status: completed`.
- File activity is visible in the receipt or journal.

## Inspect

Use the printed session id:

```bash
cargo run -p warder-cli -- receipt \
  --db /tmp/warder-demo/warder.sqlite3 \
  --session <session-id>

cargo run -p warder-cli -- journal \
  --db /tmp/warder-demo/warder.sqlite3 \
  --session <session-id> \
  --file
```

Use `--all` instead of `--file` when you want one readback that includes both file and persisted network journal events.

## Current Limits

- The fake cgroup root is only for local smoke testing. Real cgroup enforcement still needs a delegated cgroup v2 root.
- Landlock is disabled in this demo config so the protected file write is observable instead of blocked.
- Snapshots are disabled in this demo config so the smoke path does not require a Btrfs test volume. Btrfs snapshot creation and guarded missing-target restore are wired for supported hosts through `--snapshot-root`.
