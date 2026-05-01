# Run Risky Project Edits With Snapshots

Use this when an agent may edit an important project and you want a recovery point first.

Snapshot support currently targets Btrfs subvolumes. Required snapshot policy should fail closed when the needed snapshot backend or `--snapshot-root` is unavailable.

## Example Zone

```toml
[enforcement]
landlock = "best-effort"
cgroups = "best-effort"
writable-roots = ["/home/alex/projects/important-app", "/tmp", "/var/tmp"]

[network]
journal = true

[[zones]]
id = "important-app"
name = "Important App"
paths = ["/home/alex/projects/important-app"]
write_policy = "deny"
snapshot = "required"

[[agents]]
id = "coding-agent"
label = "Coding Agent"
command = "codex"
profile = "codex-cli"
```

## Run

```bash
warder dry-run --config warder.toml --agent coding-agent -- codex
warder run \
  --config warder.toml \
  --launch \
  --agent coding-agent \
  --snapshot-root /path/to/snapshot-root \
  -- codex
```

## Preview a Revert

```bash
warder revert --snapshot <snapshot-id> --snapshot-root /path/to/snapshot-root --preview
```

Warder guarded revert refuses to overwrite existing protected roots. Read the receipt and preview output before restoring anything.
