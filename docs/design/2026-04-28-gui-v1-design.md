# Warder GUI v1 Design

## Goal

Add a simple native Linux GUI for Warder that helps users configure protected zones, review conservative system and credential protection defaults, launch Warder-supervised sessions, and inspect session receipts and journals.

The GUI is a policy manager, session launcher, and log viewer. It is not an always-on background guard and must not imply whole-machine protection for processes that were not launched through Warder.

## Product Shape

- Build a native Linux desktop app with Tauri so the UI can stay lightweight while reusing Warder's Rust code and existing CLI behavior.
- First launch opens a setup wizard.
- After setup, the app opens to a dashboard.
- The dashboard and settings view include a clear action to run the setup wizard again.
- The GUI launches commands through Warder's supervised run path rather than running agent commands directly.
- The GUI exposes the equivalent CLI command for transparency and debugging.

## First-Run Wizard

The wizard should guide a user through four decisions:

1. Agent profile: pick a transparent setup template, starting with the conservative `codex-cli` default when available.
2. Protected folders: review template and system recommendations, then add or remove user-selected folders or paths before saving.
3. Logging: keep network journal and receipt behavior visible without implying live eBPF coverage when the host reports degraded support.
4. Test run: dry-run the selected policy and optionally launch a harmless protected test command.

The wizard should save a normal Warder config file and avoid creating missing protected paths. If a recommended path does not exist, show it as skipped or unavailable. Reapplying a template should only add missing recommended paths; it should not overwrite paths the user already selected, deselected, or edited.

## Protection Defaults

Default recommendations should be conservative and explain why each path is included.

Sensitive user paths can default to read and write protection when present:

- `~/.ssh`
- `~/.gnupg`
- `~/.config/gh`
- `~/.config/op`
- `~/.aws`
- `~/.azure`
- `~/.kube`
- `~/.docker`
- `~/.local/share/keyrings`

Vital OS paths should default to write protection only:

- `/etc`
- `/boot`
- `/usr`
- `/bin`
- `/sbin`
- `/lib`
- `/lib64`

Read protection for system paths should be advanced and off by default because blocking reads from OS, library, or config paths can prevent normal commands from starting.

## Dashboard

The dashboard should show:

- Current protection status: number of protected zones, recommended defaults enabled or skipped, and whether host support is enforced, degraded, unavailable, or not requested.
- Recent sessions: latest Warder runs with status, command, profile, and warning badges.
- Primary actions: run setup wizard, edit protected zones, dry-run command, start protected session, and view receipts/logs.

The dashboard should use Warder's existing receipt language and preserve honest degraded-mode wording.

Readiness labels must match the CLI and receipt model:

- `strong`: required controls for the session were available and no degraded coverage was recorded.
- `degraded`: the session can run, but at least one requested or best-effort protection is incomplete.
- `blocked`: the requested policy cannot safely launch on this host or with the supplied roots.

## Protected-Zone Editor

The editor should support:

- Add folder/path.
- Remove folder/path.
- Rename or label a zone.
- Toggle write protection.
- Toggle read protection only as an advanced option.
- Show whether the path exists.
- Show whether a selected path overlaps another protected path or a writable root.

The UI should call these "protected zones" or "protected paths," not "safe zones," to match the existing project model and avoid implying blanket safety.

## Session Launcher

The launcher should support:

- Command entry for a local agent or shell command.
- Optional profile selection or transparent inferred profile display.
- Dry-run before launch.
- Launch protected session through Warder.
- Copy equivalent CLI command.
- Show launch blockers and degraded warnings before execution.

The app should not bypass Warder's CLI/library validation. If a config would fail closed in the CLI, it should fail closed in the GUI too.

## Receipts And Logs

Receipts are the primary log view. The GUI should organize logs by session first, with file and network journal details inside each session.

The session detail view should show:

- Receipt status and command.
- Protected zones involved.
- Landlock, cgroup, snapshot, file journal, and network journal status.
- Degraded or unavailable protections.
- File activity rollups and raw event details.
- Network journal details when available.
- Recovery and review actions already produced by Warder.
- Export or copy options for text and JSON receipts.

SQLite remains the source of truth for Warder metadata. Text and JSON exports are user-facing outputs, not the primary storage model.

## Wording Rules

The GUI must be explicit that protection applies to Warder-launched sessions.

Use wording like:

- "Protected for Warder-launched sessions."
- "Write protection enforced."
- "Read protection enabled for this path."
- "Protection degraded on this host."
- "Unavailable: this kernel or policy does not support the requested control."
- "Blocked: this policy cannot launch until the missing control is fixed."

Avoid wording like:

- "This folder cannot be touched."
- "Your system is protected."
- "Always-on protection."
- "Safe zone" as the primary product term.

## Technical Notes

- Add the GUI under `apps/desktop`, matching the existing ignored build-output paths.
- Prefer reusing Warder's existing Rust crates for config validation, policy explanation, dry-run output, session launch, receipt rendering, and journal readback.
- Keep the daemon optional. The v1 GUI should work without requiring a running daemon.
- Do not add cloud, browser, chatbot, RAG, MCP, or always-on monitoring scope in this pass.
- Keep the first implementation narrow enough to verify with unit tests plus a manual app smoke path.

## Validation Plan

- Unit-test config generation for selected protected paths and recommended defaults.
- Unit-test read/write default behavior so sensitive user paths and system paths do not drift.
- Unit-test receipt/journal loading from an explicit SQLite DB.
- Verify the GUI can perform setup, save config, dry-run a command, run a harmless protected session, and show the resulting receipt.
- Run the existing CLI verification set after wiring the GUI-facing calls.

## Open Risks

- Host support varies. Landlock, cgroups, Btrfs snapshots, and eBPF journaling must continue to report degraded or unavailable states honestly.
- Read protection can break commands. Keep broad read blocking advanced and off by default for system paths.
- A GUI can make the product feel always-on. The design and labels must keep the session-scoped model clear.
- Privileged or system-wide protection is out of scope for v1.
