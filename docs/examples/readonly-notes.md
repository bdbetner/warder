# Give an Agent Read-Only Access to Notes

Use this when an agent may inspect notes but should not edit them.

## Example Zone

```toml
[enforcement]
landlock = "best-effort"
cgroups = "best-effort"
writable-roots = ["/tmp", "/var/tmp"]

[network]
journal = false

[[zones]]
id = "personal-notes"
name = "Personal Notes"
paths = ["/home/alex/notes"]
write_policy = "deny"
snapshot = "disabled"

[[agents]]
id = "local-shell"
label = "Local Shell"
command = "sh"
profile = "local-script"
```

## Run

```bash
warder dry-run --config warder.toml --agent local-shell -- sh -c 'ls /home/alex/notes'
warder run --config warder.toml --launch --agent local-shell -- sh -c 'ls /home/alex/notes'
```

## Review

```bash
warder receipt --session <session-id>
warder journal --session <session-id> --file
```

This pattern is for local read-only inspection. Do not use it as a promise that sensitive note contents cannot be copied elsewhere.
