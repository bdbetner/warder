# Landlock Demo

This demo checks Warder's required-Landlock path with throwaway directories. On hosts with usable Landlock support, the supervised command should fail to write inside the protected zone. On hosts without usable Landlock support, Warder should fail closed before launching the command.

Run it with:

```bash
scripts/landlock-demo.sh
```

The script creates:

- `/tmp/warder-landlock-demo/protected` or `WARDER_LANDLOCK_DEMO_ROOT/protected` as the protected zone.
- `/var/tmp/warder-landlock-demo-writable` or `WARDER_LANDLOCK_WRITABLE_ROOT` as the unrelated writable root Landlock needs.
- A throwaway config under the selected demo root so custom paths match the protected policy.
- A fake cgroup root for local smoke testing.
- `warder.sqlite3` under the selected demo root as the session database.

## Expected Results

If Landlock is available:

- `dry-run` reports `landlock: will apply`.
- `run --launch` starts a tagged session.
- The protected write command exits nonzero.
- The receipt shows `status: failed` and `landlock: applied`.
- The protected file is not created.

If Landlock is unavailable:

- `run --launch` exits before starting the command.
- The error says required Landlock cannot be applied.
- The protected file is not created.

## Limits

- The fake cgroup root is only for local smoke testing. Real process containment still needs a delegated cgroup v2 root.
- Landlock only proves write-denial behavior for the supervised child process after `pre_exec` setup. It does not restrict the Warder parent process.
- This demo does not exercise snapshots or live eBPF journaling.
