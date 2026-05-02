# Run OpenClaw Through Warder

Use this when OpenClaw should run as a supervised local command instead of receiving raw filesystem access outside Warder.

For the full guidance, including current OpenClaw release-note implications, see [OpenClaw Support](../openclaw-support.md).

Warder does not replace OpenClaw's own gateway, channel, tool, sandbox, or elevated-exec policy. It adds the host-side session record around the OpenClaw process: protected zones, cgroup identity where available, Landlock enforcement where supported, file/network journals, snapshots where supported, and a receipt.

## Choose A Profile

Warder includes three transparent OpenClaw profiles:

- `openclaw-cli`: generic OpenClaw command supervision.
- `openclaw-gateway`: Gateway/control-plane supervision.
- `openclaw-agent`: one supervised `openclaw agent --message ...` run.

The profile does not grant extra trust. It only improves starter configs, preflight text, degraded-coverage warnings, and receipt review actions.

Preview the templates:

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

## One-Shot Agent Run

Dry-run first:

```bash
warder dry-run \
  --config examples/openclaw/agent-message.toml \
  --agent openclaw \
  -- openclaw agent --message "check this workspace"
```

Then launch:

```bash
warder run \
  --config examples/openclaw/agent-message.toml \
  --launch \
  --accept-degraded \
  --agent openclaw \
  -- openclaw agent --message "check this workspace"
```

## Gateway Run

OpenClaw's own onboarding may install a user service for the Gateway. Warder does not rewrite that service automatically.

For a Warder-supervised Gateway process, launch a separate wrapper or user unit that runs:

```bash
warder run \
  --config examples/openclaw/gateway.toml \
  --launch \
  --accept-degraded \
  --agent openclaw \
  -- openclaw gateway
```

That receipt covers the launched Gateway host process. Tool execution that OpenClaw moves into Docker, SSH, OpenShell, or another runtime outside that process tree should be read as degraded unless Warder can verify the relevant host visibility.

## Preflight And Receipts

For OpenClaw profiles, Warder tries these read-only OpenClaw checks when the binary is available:

```bash
openclaw security audit --json
openclaw sandbox explain --json
```

Missing or unparseable output degrades the OpenClaw preflight, but it does not block ordinary Warder supervision.

Receipts for OpenClaw sessions include review actions to run:

```bash
openclaw security audit --deep
openclaw sandbox explain --json
```

## Smoke Test

```bash
scripts/openclaw-integration-smoke.sh
```

If `openclaw` is not installed, the smoke script uses a temporary stub so the Warder profile, preflight, launch, receipt, and journal flow can still be validated.

## Limits

No OpenClaw plugin API is required for this path. Warder supervises the process it launches. Direct OpenClaw launches, already-running services, and containerized or remote tool runtimes are outside Warder's host-session guarantee unless they are explicitly launched through Warder and the required host protections are verified.
