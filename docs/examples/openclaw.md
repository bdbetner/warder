# Run OpenClaw Through Warder

Use this when OpenClaw should run as a supervised local command instead of receiving raw filesystem access outside Warder.

## Run

```bash
warder run --config warder.toml --launch --accept-degraded --agent openclaw -- openclaw ...
```

## What Warder Provides

- protected-zone policy
- agent/session labeling
- cgroup tagging where available
- Landlock write denial where available
- snapshot setup where supported
- file and network journals
- a session receipt

No OpenClaw plugin API is required for this path.

Containerized OpenClaw runs may hide process trees, cgroups, mounts, or network activity from Warder. Treat those sessions as degraded unless Warder verifies the relevant host protections.
