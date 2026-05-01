# FAQ

## Does Warder replace an agent's built-in sandbox?

No. Warder is a separate local supervision layer. Agent-specific sandboxes can still be useful, but Warder records its own policy, host support, degraded protections, and session receipt so users have one comparable record across tools.

## Does Warder protect commands launched outside Warder?

No. Warder only supervises commands launched through `warder run`.

## What happens if Landlock is unavailable?

Warder reports degraded or blocked enforcement depending on policy. It should not claim write denial when the host cannot provide it.

Use `warder run --require-enforcement` when a session must not launch unless protected write blocking can be applied.

## Can Warder stop network access?

Not in the current alpha. Warder can record network observations where configured and supported, but network journaling is visibility, not complete network enforcement.

## Is the desktop app required?

No. The CLI is the primary path. The desktop app makes setup, launch, and receipt review easier.

## Does a quiet receipt mean nothing happened?

No. A quiet receipt means Warder did not observe matching activity with the configured coverage. Receipts should always be read together with active and degraded protection status.

## Can Warder guarantee safe permissive mode?

No. Warder reduces risk by adding explicit policy, host-backed controls where available, and receipts. Unsupported hosts, unsupervised commands, event loss, misconfiguration, and malware can still create risk.

## Where should I start?

Run `scripts/quickstart-demo.sh` from a source checkout, then read [Protected Zones](protected-zones.md) and [Security Model](security-model.md).
