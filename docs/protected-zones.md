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
- Should reads be denied with the experimental Landlock read-blocking mode?
- Should a snapshot be required before launch?
- Which writable roots are allowed?
- Which readable roots are allowed if read blocking is enabled?
- Should file activity be journaled?
- Should network activity be journaled or gated?
- Which degraded protections are acceptable?

## Practical Guidance

Start with a small number of high-value zones. Protect credentials first, then private notes, then important projects.

Keep readonly zones separate from workspaces where agents are expected to edit. That makes receipts easier to read and reduces accidental overlap between protected paths and writable roots.

Read blocking is opt-in and stricter than write blocking. If a zone uses `read_deny = true` or `read_policy = "deny"`, define `enforcement.readable_roots` as the exact directories the agent must still read, and keep those roots disjoint from the read-denied zone. Warder rejects overlapping readable roots and parent/child protected-zone overlaps when read denial is active because Landlock allow rules are additive. Read denial is experimental and may break agents that need runtime, shell, model, or dependency files outside the readable-root allowlist.

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

[enforcement]
writable_roots = ["/tmp"]

[[zones]]
id = "credentials"
paths = ["/home/alex/.ssh", "/home/alex/.aws"]
write_policy = "deny"
# Experimental. Requires enforcement.readable_roots to include every path the
# agent must still read, and may break some agents.
read_deny = false
snapshot = "disabled"

[[zones]]
id = "project"
paths = ["/home/alex/projects/important-app"]
write_policy = "deny"
snapshot = "best-effort"
```

Read-blocking example:

```toml
[enforcement]
readable_roots = ["/usr", "/bin", "/lib", "/lib64", "/tmp", "/home/alex/projects/agent-work"]
writable_roots = ["/tmp", "/home/alex/projects/agent-work"]

[[zones]]
id = "credentials"
name = "Credentials"
paths = ["/home/alex/.ssh"]
read_policy = "deny"
write_policy = "deny"
snapshot = "disabled"
```

Prefer `warder init` for new configs, then edit the generated file for your real paths:

```bash
warder init --output warder.toml --profile local-script --agent-command sh --protected-path /absolute/path/to/protect
```
