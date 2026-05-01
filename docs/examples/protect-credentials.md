# Protect Credentials While Running an Agent

Use this when an agent should work in a project but should not freely modify credential folders.

## Example Zones

```toml
[enforcement]
landlock = "best-effort"
cgroups = "best-effort"
writable-roots = ["/home/alex/projects/my-app", "/tmp", "/var/tmp"]

[network]
journal = true

[[zones]]
id = "credentials"
name = "Credentials"
paths = [
  "/home/alex/.ssh",
  "/home/alex/.gnupg",
  "/home/alex/.aws",
  "/home/alex/.kube",
]
write_policy = "deny"
snapshot = "disabled"

[[agents]]
id = "coding-agent"
label = "Coding Agent"
command = "codex"
profile = "codex-cli"
```

## Run

```bash
warder explain --config warder.toml
warder dry-run --config warder.toml --agent coding-agent -- codex
warder run --config warder.toml --launch --agent coding-agent -- codex
```

## Review

```bash
warder receipt --db .warder/warder.db --session <session-id>
warder journal --db .warder/warder.db --session <session-id> --all
```

If Landlock or cgroup support is degraded, treat the session as lower-trust and address the host setup before running sensitive work.
