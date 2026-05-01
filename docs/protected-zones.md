# Protected Zones

A protected zone is a named set of local paths plus rules for agent sessions.

Use protected zones for files that an unattended or permissive agent should not freely change.

## Common Zones

- `credentials`: SSH keys, GPG keys, cloud credentials, kube config, `.env` files, and wallet files.
- `personal-notes`: private notes or documents that should not be changed by a session.
- `project-readonly`: a source repository an agent can inspect but should not edit.
- `snapshot-project`: a repository or workspace that should be snapshotted before risky edits.
- `system-config`: shell, editor, desktop, or service config that should not be changed casually.

## Policy Questions

For each zone, decide:

- Which paths belong in the zone?
- Which agent labels may run while the zone is active?
- Should writes be denied?
- Should a snapshot be required before launch?
- Which writable roots are allowed?
- Should file activity be journaled?
- Should network activity be journaled or gated?
- Which degraded protections are acceptable?

## Practical Guidance

Start with a small number of high-value zones. Protect credentials first, then private notes, then important projects.

Keep readonly zones separate from workspaces where agents are expected to edit. That makes receipts easier to read and reduces accidental overlap between protected paths and writable roots.

Use `warder explain` before the first real run:

```bash
warder explain --config warder.toml
```

Then dry-run the specific agent command:

```bash
warder dry-run --config warder.toml --agent local-script -- sh -c 'true'
```

If Warder reports degraded enforcement, read the reason before trusting the session. Some degradation is expected on hosts without configured cgroups, supported filesystems, eBPF privileges, or Landlock support.

## Example

```toml
[network]
journal = true

[[zones]]
id = "credentials"
paths = ["/home/alex/.ssh", "/home/alex/.aws"]
write_policy = "deny"
snapshot = "disabled"

[[zones]]
id = "project"
paths = ["/home/alex/projects/important-app"]
write_policy = "deny"
snapshot = "best-effort"
```

Prefer `warder init` for new configs, then edit the generated file for your real paths:

```bash
warder init --output warder.toml --profile local-script --agent-command sh --protected-path /absolute/path/to/protect
```
