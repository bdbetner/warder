# Desktop Security

The desktop app is a local control surface for the CLI-first Warder flow. It should not become a second, broader permission surface.

## IPC Boundary

The Tauri config must keep a non-null content security policy. The current policy allows local app resources, inline styles required by the bundled frontend, Tauri IPC, and the local Vite dev server during development. It denies object embedding, external frames, remote HTTPS content, and unsafe script evaluation.

The Tauri capability file is intentionally narrow:

- one local window: `main`
- `core:default` only
- no filesystem, shell, dialog, HTTP, updater, or opener plugin permissions

The frontend calls app-specific Rust commands for setup, dry-run, launch, receipts, journals, recent sessions, profile templates, and host readiness. Those commands validate paths, session ids, agent ids, command length, and argument size before touching files or launching a supervised process.

## Review Rule

Any future desktop feature that adds a Tauri plugin permission must document:

- why the existing Rust command boundary is not enough
- which window receives the permission
- what path, URL, or command scope is allowed
- which regression test covers the new boundary

Prefer adding a narrow Rust command with explicit validation over granting broad frontend plugin access.
