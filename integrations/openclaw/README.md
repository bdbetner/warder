# OpenClaw Integration

Warder can supervise OpenClaw the same way it supervises any other local agent command: launch it through `warder run` with a named agent label and explicit protected-zone config.

```bash
warder run --config <path> --launch --agent openclaw -- openclaw ...
```

That gives the session Warder's normal protections where the host supports them:

- protected-zone policy
- agent/session labeling
- cgroup tagging
- Landlock enforcement where supported
- snapshot setup where supported
- file and network journals

No OpenClaw plugin API is required for the current path. Warder now treats OpenClaw as a transparent profile family:

- `openclaw-cli`: generic OpenClaw command supervision
- `openclaw-gateway`: Gateway/control-plane supervision
- `openclaw-agent`: one supervised OpenClaw agent command

The profiles do not grant special trust. They only improve preflight text, setup templates, degraded-coverage warnings, and receipt review actions.

## Recommended Flows

Preview the profile templates:

```bash
warder profiles --format json
```

Generate a starter config:

```bash
warder init \
  --profile openclaw-agent \
  --agent-command openclaw \
  --protected-path /absolute/path/to/protect \
  --print
```

Dry-run a one-shot agent command:

```bash
warder dry-run \
  --config examples/openclaw/agent-message.toml \
  --agent openclaw \
  -- openclaw agent --message "check this workspace"
```

Supervise a Gateway command:

```bash
warder run \
  --config examples/openclaw/gateway.toml \
  --launch \
  --agent openclaw \
  -- openclaw gateway
```

Run the integration smoke path:

```bash
scripts/openclaw-integration-smoke.sh
```

If `openclaw` is not installed, the smoke script uses a temporary stub so Warder's OpenClaw profile, preflight, receipt, and journal behavior can still be validated.

## Security Fit

OpenClaw owns app-level policy: Gateway auth, channel pairing, tool allow/deny rules, elevated exec gates, and OpenClaw sandbox mode/scope.

Warder owns the outer Linux host record: cgroup identity where available, Landlock protected-zone enforcement where supported, file and network journals, snapshot posture, and receipts that say which protections degraded.

When available, Warder dry-runs call:

```bash
openclaw security audit --json
openclaw sandbox explain --json
```

Those checks are optional. Missing or unparseable OpenClaw output degrades Warder's OpenClaw preflight, but does not block ordinary command supervision.

Current OpenClaw `sandbox explain --json` output reports the effective sandbox mode, scope, workspace access, tool policy, elevated gates, and fix-it guidance. Warder consumes those fields directly and also accepts backend/runtime hints if OpenClaw exposes them later.

Containerized or remote OpenClaw tool runtimes may hide process trees, cgroups, mounts, or network activity from Warder. Treat those sessions as degraded when OpenClaw audit findings or future sandbox metadata show Docker, SSH, OpenShell, host networking, Docker socket binds, or broad host bind mounts.

## Service Fit

OpenClaw's own onboarding can install a user service for the Gateway. Warder should not rewrite that service automatically.

For a Warder-supervised Gateway service, use a separate user unit or explicit wrapper command that launches:

```bash
warder run --config <path> --launch --agent openclaw -- openclaw gateway
```

That preserves a Warder session receipt for the Gateway process. If OpenClaw tool execution moves into Docker, SSH, OpenShell, or another runtime outside the launched host process tree, the receipt should still be read as host-Gateway coverage plus degraded or separately verified tool-runtime coverage.
