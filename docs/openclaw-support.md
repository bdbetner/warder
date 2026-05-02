# OpenClaw Support

Use this guide when you want OpenClaw to keep its normal Gateway, agents, channels, memory, plugins, and sandbox behavior while Warder adds a Linux host-side supervised-session record around the OpenClaw process.

Warder does not replace OpenClaw policy. OpenClaw still owns Gateway auth, channel routing, tool allow/deny rules, elevated-exec gates, memory, plugins, and sandbox backends. Warder owns the outer process launch: protected zones, cgroup identity where available, Landlock enforcement where supported, optional snapshots, file/network journals, and receipts.

## Current OpenClaw Context

This guide was reviewed against OpenClaw `v2026.4.29`, released April 30, 2026.

The latest OpenClaw release reinforces the split of responsibilities:

- OpenClaw keeps moving quickly in Gateway, messaging, memory, provider/model, plugin, and channel behavior.
- OpenClaw added more security and operations work, including OpenGrep scanning, sharper GHSA triage policy, safer exec/pairing/owner-scope handling, Docker/onboarding automation, and trusted-proxy web-fetch changes.
- OpenClaw changed restricted profile behavior so configured `tools.exec` and `tools.fs` sections no longer implicitly widen `messaging` or `minimal`; users must opt in with explicit `alsoAllow` entries when they want those tools under restricted profiles.
- OpenClaw's own security guide continues to frame OpenClaw as a trusted personal-assistant gateway, not a hostile multi-tenant isolation boundary.

That means the best Warder integration is not a plugin or config rewrite. It is a clear outer session boundary around OpenClaw launches, plus receipts that tell you when OpenClaw sandboxing or host support moved work outside Warder's verified visibility.

## Best Default Setup

Use OpenClaw's own onboarding first:

```bash
openclaw onboard
openclaw security audit --deep
openclaw sandbox explain --json
```

Then run the OpenClaw action through Warder:

```bash
warder dry-run \
  --config examples/openclaw/agent-message.toml \
  --agent openclaw \
  -- openclaw agent --message "check this workspace"

warder run \
  --config examples/openclaw/agent-message.toml \
  --launch \
  --accept-degraded \
  --agent openclaw \
  -- openclaw agent --message "check this workspace"
```

Use `--accept-degraded` only after reading the launch readiness output. Omit it when you want Warder to refuse runs with incomplete host protection.

For stricter sessions, use Warder's strict launch path with an external receipt key:

```bash
warder receipt-key init --output ~/.config/warder/receipt-key

warder run \
  --config examples/openclaw/agent-message.toml \
  --launch \
  --require-enforcement \
  --receipt-key ~/.config/warder/receipt-key \
  --agent openclaw \
  -- openclaw agent --message "check this workspace"
```

Strict mode is the right default for sensitive local work when the host supports the required protections.

## Choose The Right Warder Profile

Warder includes three transparent OpenClaw profiles:

| Profile | Use it for | Typical command |
| --- | --- | --- |
| `openclaw-agent` | One supervised agent turn | `openclaw agent --message "..."` |
| `openclaw-gateway` | A Gateway process launched through Warder | `openclaw gateway` |
| `openclaw-cli` | Setup, diagnostics, messaging, or other OpenClaw CLI commands | `openclaw security audit --deep` |

Profiles do not grant trust. They improve templates, preflight wording, degraded-coverage labels, and receipt review actions.

Preview profile templates:

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

## Recommended Protected Zones

Start by protecting host material OpenClaw should not mutate during ordinary project work:

- `~/.ssh`
- `~/.gnupg`
- cloud credentials under `~/.aws`, `~/.config/gcloud`, or Kubernetes config
- private notes and documents
- project roots that should be read-only or snapshot-backed
- `~/.openclaw` when you want to observe or snapshot OpenClaw state changes

Do not block writes to `~/.openclaw` for the main Gateway until you understand what OpenClaw needs to update. For Gateway supervision, start with journaling and snapshots, then tighten write policy only after dry-runs and receipts confirm the workflow.

## OpenClaw Gateway

OpenClaw may install and manage its own user service for the Gateway. Warder does not rewrite that service automatically.

If you want a Warder receipt for the Gateway process, launch a separate Warder-supervised Gateway:

```bash
warder run \
  --config examples/openclaw/gateway.toml \
  --launch \
  --accept-degraded \
  --agent openclaw \
  -- openclaw gateway
```

That receipt covers the Gateway process Warder launched. It does not automatically cover a separate OpenClaw service that was already running outside Warder.

## Sandbox And Container Reality

OpenClaw sandboxing may use Docker, SSH, or OpenShell runtimes. OpenClaw's `sandbox explain` command reports effective sandbox mode, scope, workspace access, tool policy, elevated gates, and fix-it config keys. `sandbox list` reports runtime backend details such as Docker or OpenShell.

Warder treats containerized or remote OpenClaw work as degraded unless the relevant host visibility is verified. The practical rule is:

- Warder can constrain and observe the OpenClaw process it launches.
- OpenClaw may move tool execution into a Docker, SSH, or OpenShell runtime.
- Work inside that runtime may hide process trees, cgroups, mounts, or network activity from Warder.
- Receipts should be read as host-launch coverage plus explicit degraded/runtime warnings.

When you change OpenClaw sandbox config, recreate OpenClaw sandboxes before relying on the new policy:

```bash
openclaw sandbox explain --json
openclaw sandbox list
openclaw sandbox recreate --all
```

## Receipts And Review Loop

After every meaningful OpenClaw run:

```bash
warder receipt --db .warder/warder.db --session <session-id>
warder journal --db .warder/warder.db --session <session-id> --all
openclaw security audit --deep
openclaw sandbox explain --json
```

Use the Warder receipt to answer:

- Did Warder launch this OpenClaw process?
- Which protected zones were active?
- Were cgroups, Landlock, snapshots, and journals active or degraded?
- Did OpenClaw audit or sandbox preflight warn about broad tool, Gateway, hook, plugin, or sandbox exposure?
- Is the receipt strong enough for the work, or should the run be repeated under stricter host support?

Use OpenClaw's audit and sandbox commands to answer:

- Who can reach the Gateway or bot?
- Which channels and groups can trigger tool use?
- Which tools can run, and where?
- Is elevated exec enabled?
- Are sandbox settings active for the intended agent/session?

## When To Use Warder With OpenClaw

Use Warder when OpenClaw is touching a real local workspace, private notes, credentials-adjacent config, or a project where you want a receipt before and after the run.

Good fits:

- one-shot `openclaw agent --message` project work
- a supervised Gateway process for a review window
- OpenClaw diagnostics or maintenance that might mutate local state
- testing OpenClaw plugin, model, or sandbox changes against protected directories

Poor fits:

- an already-running Gateway service that Warder did not launch
- hostile multi-tenant OpenClaw deployments on one shared host
- relying on Warder to make permissive OpenClaw tool policy safe by itself
- expecting Warder to enforce network allowlists in the current public beta

## Quick Smoke Test

```bash
scripts/openclaw-integration-smoke.sh
```

If `openclaw` is installed, the smoke path uses it. If not, the script creates a temporary stub and still verifies Warder's profile, preflight, launch, receipt, and journal flow.

## Upstream References

- OpenClaw release notes: https://github.com/openclaw/openclaw/releases/tag/v2026.4.29
- OpenClaw security guide: https://github.com/openclaw/openclaw/blob/v2026.4.29/docs/gateway/security/index.md
- OpenClaw security CLI: https://github.com/openclaw/openclaw/blob/v2026.4.29/docs/cli/security.md
- OpenClaw sandboxing: https://github.com/openclaw/openclaw/blob/v2026.4.29/docs/gateway/sandboxing.md
- OpenClaw sandbox CLI: https://github.com/openclaw/openclaw/blob/v2026.4.29/docs/cli/sandbox.md
