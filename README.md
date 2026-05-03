<p align="center">
  <img src="docs/assets/warder-logo.svg" alt="Warder logo: protected sessions for local agent work" width="560">
</p>

[![CI](https://github.com/betnbd/warder/actions/workflows/ci.yml/badge.svg)](https://github.com/betnbd/warder/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/betnbd/warder?include_prereleases&label=release)](https://github.com/betnbd/warder/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-111827.svg)](#current-status)

Run local AI agents with protected paths, receipts, and recovery.

Warder wraps Codex CLI, Claude Code, OpenClaw, and local scripts so you can see what was protected, what degraded, what changed, and what can be reverted.

Warder v1.0 is scoped to processes launched through `warder run` or the desktop launcher. Global always-on supervision, meaning host-wide protection for processes launched outside Warder, is planned for v1.1.

The first goal is practical: keep permissive local agent workflows fast while making personal data, credentials, important projects, and core system paths harder to damage. Warder is not a general endpoint security product or a host-wide sandbox.

## Start Here

- New user: read [Quick Start](#quick-start), then [Protected Zones](docs/protected-zones.md).
- Installing a release build: read [Install Notes](docs/install.md), [Linux Compatibility](docs/linux-compatibility.md), and [Release Trust Model](docs/release-trust.md).
- Reviewing Warder: read [Reviewer Feedback Guide](docs/reviewer-feedback.md).
- Evaluating the safety model: read [Security Model](docs/security-model.md) and [Threat Model](THREAT_MODEL.md).
- Checking host coverage: run `warder test-host`, then read [Protection Matrix](docs/protection-matrix.md).
- Running OpenClaw: read [OpenClaw Support](docs/openclaw-support.md).
- Looking for the project direction: read [Product Overview](PRODUCT_SPEC.md), [Vision](docs/vision.md), and [Roadmap](ROADMAP.md).
- Looking for common scenarios: read [Examples](docs/examples/README.md) and [FAQ](docs/FAQ.md).

## Why Warder v1

Warder is a tool-agnostic supervision layer for explicit local agent sessions. It is for Linux users who want one policy and one receipt model across agent tools, without depending on each agent app to describe host-side risk the same way.

It gives you real host-side guardrails without forcing every workflow into a container, remote VM, or separate development account:

- **Pre-exec supervised setup**: Warder-launched commands are assigned to a session cgroup, covered by seccomp deny-list hardening, and locked down with Landlock before the target command is executed, where the host supports those features.
- **Protected zones and Btrfs snapshots**: Declare sensitive directories, block protected writes with Landlock where available, snapshot supported Btrfs roots before risky sessions, and revert from recorded snapshots when needed.
- **Readable journals**: Warder records protected-zone file activity with inotify and can add optional eBPF/procfs network and file-observation data where built, permitted, and supported by the kernel.
- **Tamper-evident receipts**: Session receipts record the command, policy, active protections, degraded protections, journal coverage, snapshot state, and local hash-chain integrity. Strict launches require an external receipt key and can be checked with `warder verify-receipts`.
- **Desktop-first review path**: The Tauri desktop app provides setup, launch-readiness review, doctor output, receipt review, and a persistent reminder that Warder supervises only Warder-launched sessions.

Warder is explicitly not a full host-wide sandbox. It only supervises processes launched through `warder run` or the desktop launcher. Direct launches, background services, IDE extensions, and malware running outside Warder are unsupervised.

For the v1.0 public beta, Warder is production-oriented for explicit supervised sessions, but global always-on supervision is planned for v1.1. For maximum safety today, run agents exclusively through Warder with strict mode, external receipt keys, and existing host defenses such as firewall, AppArmor, or SELinux policy where those already fit your environment.

## Why Use It

Local AI agents often run with the same permissions as you. That is convenient, but it also means an agent can modify files, touch credentials, or make network calls unless something outside the agent draws a boundary.

Warder gives you one tool-agnostic place to define that boundary and review the result.

- Protect folders such as projects, notes, SSH keys, cloud credentials, or `.env` files.
- Run Codex CLI, Claude Code, OpenClaw, local scripts, or another command under the same policy model.
- Preview a session before launch with `explain` and `dry-run`.
- Deny writes to protected paths where Linux Landlock is available.
- Snapshot supported Btrfs roots before risky sessions.
- Review a plain-language receipt and file/network journal after the run.
- See degraded protections called out instead of hidden.

## Current Status

Warder is a Linux tool with a working CLI and native desktop app.

The CLI can initialize config, dry-run a policy, launch a supervised command, persist session receipts, record observed file activity, read back network-journal data, and report degraded enforcement. Landlock write denial, cgroup tagging, inotify file journaling, Btrfs snapshots, guarded Btrfs revert, and optional live eBPF network collection are implemented where the host supports them.

It is not an always-on system guard. Warder only supervises processes launched via `warder run` or the desktop launcher. Direct launches or processes started by malware are completely unsupervised.

## Known Limits

- Warder only supervises processes launched via `warder run` or the desktop launcher. Direct launches or processes started by malware are completely unsupervised.
- Host support matters: missing Landlock, cgroups, Btrfs, or eBPF permissions can reduce protection.
- Protected reads are not blocked by default. Experimental Landlock read blocking is available only with explicit `read_deny = true` or `read_policy = "deny"` plus disjoint `enforcement.readable_roots`, and it may break some agents.
- Current network journaling is visibility, not complete network enforcement.
- Local receipts and journals are useful accountability records, not tamper-proof forensics.
- Release packages are checksummed and attested where available, but they are not package-manager signed.

## Quick Start

From a source checkout, run the lowest-friction smoke test:

```bash
scripts/quickstart-demo.sh
```

The demo creates a throwaway protected folder under `/tmp/warder-quickstart`, launches a supervised shell command, then prints the receipt and file journal. It intentionally skips delegated cgroup setup, so you should see one degraded protection reason while still seeing observed protected-zone activity.

For a more realistic product proof, run:

```bash
warder demo attack-pack
```

The attack-pack demo attempts a protected write, a protected read, a workspace edit, and a network connection, then prints the receipt and journal. It reports what this host actually blocked, observed, or degraded. Source checkouts can also run `scripts/attack-pack-demo.sh`; track the remaining proof-path work in [Product Proof Path](docs/product-proof-path.md).

Verify host controls directly:

```bash
warder test-host
warder test-host --format json
```

`test-host` labels each control as `proven working`, `configured/planned`, `degraded`, or `unsupported`. Use it when you need evidence beyond a planning-only `doctor` report.

Create your first agent profile from a safe preset:

```bash
warder setup codex --workspace . --protect-secrets --print
warder setup claude --workspace . --protect-secrets
warder setup openclaw --workspace . --protect-secrets
```

`warder setup` generates a reviewable policy for the selected agent, the current workspace, and common secret folders such as SSH, cloud, GitHub CLI, and Kubernetes credentials. Codex CLI, Claude Code, and OpenClaw are the first supported setup choices; use `warder init` for local scripts or custom commands.

After reviewing the generated file, launch through the matching shortcut:

```bash
warder codex --accept-degraded -- --help
warder claude --accept-degraded -- --help
warder openclaw --accept-degraded -- --help
```

Shortcut commands are thin wrappers around `warder run --launch`; use the normal `warder run` command when you need a custom agent id or command.

Create a lower-level starter config:

```bash
warder init \
  --output warder.toml \
  --profile local-script \
  --agent-command sh \
  --protected-path /absolute/path/to/protect

warder explain --config warder.toml
warder dry-run --config warder.toml --agent local-script -- sh -c 'true'
```

`warder init` refuses to overwrite an existing file unless `--force` is passed. Use `--print` to preview generated config without writing it.

Launch a supervised session:

```bash
warder run --config warder.toml --launch --accept-degraded --agent local-script -- sh -c 'echo test'
```

`--accept-degraded` is required when the launch readiness check finds incomplete protection, such as missing delegated cgroups, unavailable snapshots, or visibility-only eBPF journaling. Omit it when you want Warder to refuse degraded launches.

Keep Warder's database and receipt key outside protected zones and outside paths an agent can write. Warder refuses launches when `--db` or a strict-mode `--receipt-key` sits under a configured zone path or `enforcement.writable_roots` entry. Warder also refuses root-launched agents unless `--allow-root` is passed from a sudo environment that lets Warder drop the child back to the original non-root user.

Review the result:

```bash
warder receipt --db .warder/warder.db --session <session-id>
warder journal --db .warder/warder.db --session <session-id> --file
```

## Desktop App

The native Linux desktop app lives in `apps/desktop`. It helps create a Warder config, launch supervised sessions, and review receipts and journals.

The GUI requires at least one protected path before saving setup or launching. New setups default to strict write-block launch, and best-effort launch is an explicit toggle for reviewers who accept degraded protection on hosts without usable Landlock support. The GUI requires a fresh launch-readiness review before the run button is enabled, and the Rust launch command refuses desktop launches that do not carry that review acknowledgement.

Development launch:

```bash
cd apps/desktop
npm ci
npm run tauri -- dev
```

Release builds produce the CLI, GUI binary, `.deb`, RPM, AppImage, `SHA256SUMS`, and `release-manifest.json`. See [Install Notes](docs/install.md) and [Release Trust Model](docs/release-trust.md) before installing release packages.

## What Warder Protects

Warder works around protected zones: named groups of paths plus policy.

Common protected zones include:

- credential folders such as `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud`, and Kubernetes config
- private notes or personal documents
- projects that should be read-only to an agent
- repositories that should be snapshot-backed before a risky session
- config files that should not be changed by unattended commands

See [Protected Zones](docs/protected-zones.md) for examples and policy guidance.

## What To Expect From Receipts

A Warder receipt summarizes:

- the agent label and command that ran
- active and degraded protections
- protected-zone policy
- exit status
- observed file activity
- network-journal coverage and known limits
- snapshot and recovery state
- suggested review actions

Receipts are designed to stay useful even when some enforcement is degraded. If a kernel feature, filesystem feature, privilege, or explicit root is missing, Warder reports that directly.

![Sample Warder receipt](docs/assets/warder-receipt-sample.svg)

The text version of this example lives at [docs/examples/sample-receipt.txt](docs/examples/sample-receipt.txt).

## Examples

- [Protect credentials while running a coding agent](docs/examples/protect-credentials.md)
- [Give an agent read-only access to notes](docs/examples/readonly-notes.md)
- [Run risky project edits with snapshots](docs/examples/snapshot-project.md)
- [Run OpenClaw through Warder](docs/examples/openclaw.md)

## OpenClaw Support

OpenClaw is one of Warder's primary supported agent workflows. Warder does not replace OpenClaw's Gateway auth, channel routing, tool allow/deny rules, elevated-exec gates, memory, plugins, or sandbox backends. It adds an outer Linux supervised-session layer around the OpenClaw process that Warder launches.

Use Warder for OpenClaw when you want protected zones, host readiness checks, optional snapshots, file/network journals, and receipts around:

- `openclaw agent --message ...`
- `openclaw gateway`
- generic OpenClaw CLI commands that may touch local state

Start with [OpenClaw Support](docs/openclaw-support.md). The short example page remains at [Run OpenClaw through Warder](docs/examples/openclaw.md), and maintainer integration notes live at [integrations/openclaw](integrations/openclaw/README.md).

## Security Model

Warder does not depend on an agent choosing to behave. The project prefers host controls such as Landlock, cgroups, snapshots, file journals, and eBPF-backed observation where available.

Important limits:

- Warder only supervises processes launched via `warder run` or the desktop launcher. Direct launches or processes started by malware are completely unsupervised.
- Unsupported kernels and filesystems reduce enforcement.
- Current network visibility is limited, not complete socket forensics.
- Release packages are checksummed and attested where available, but they are not package-manager signed.
- No local safety tool can make arbitrary permissive execution risk-free.
- Global supervision, meaning an always-on mode for processes not launched through Warder, is planned for v1.1.

Read [Security Model](docs/security-model.md), [Threat Model](THREAT_MODEL.md), and [Permissions](docs/permissions.md) before relying on Warder for sensitive work.

## Common Commands

```text
warder init --protected-path <path> [--output <path>] [--profile <id>] [--agent-command <command>] [--force] [--print]
warder explain --config <path>
warder dry-run --config <path> --agent <id> -- <agent command>
warder run --config <path> --launch --agent <id> [--require-enforcement --receipt-key <path>] [--accept-degraded] [--cgroup-root <path>] [--snapshot-root <path>] -- <agent command>
warder receipt [--db <path>] --session <id> [--format text|json] [--signing-key-file <path>|--receipt-key <path>] [--verify-signature <hex>]
warder verify-receipts [--db <path>] [--external-key <path>|--receipt-key <path>]
warder receipt-key init [--output <path>] [--force]
warder journal [--db <path>] [--file|--network|--all] [--session <id>]
warder snapshot --config <path> --session <id> --snapshot-root <path>
warder revert --snapshot <id> --snapshot-root <path> [--preview | --db <path> --session <id>]
warder doctor
warder test-host [--format text|json]
warder profiles [--format text|json]
warder status
```

## Build From Source

```bash
cargo build --release -p warder-cli --bin warder
```

Full workspace validation:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/quickstart-demo.sh
scripts/profile-template-demo.sh
scripts/prototype-demo.sh
```

Desktop release build:

```bash
cd apps/desktop
npm ci
npm run build
npm test
npm run tauri -- build --bundles deb,rpm,appimage --ci
```

## Documentation

- [Documentation Guide](docs/README.md)
- [Vision](docs/vision.md)
- [Product Overview](PRODUCT_SPEC.md)
- [FAQ](docs/FAQ.md)
- [Examples](docs/examples/README.md)
- [Install Notes](docs/install.md)
- [Linux Compatibility](docs/linux-compatibility.md)
- [Protection Matrix](docs/protection-matrix.md)
- [How Warder Fits](docs/comparison.md)
- [Reviewer Feedback Guide](docs/reviewer-feedback.md)
- [Release Trust Model](docs/release-trust.md)
- [Release Readiness](docs/release-readiness.md)
- [Protected Zones](docs/protected-zones.md)
- [Security Model](docs/security-model.md)
- [Threat Model](THREAT_MODEL.md)
- [Permissions](docs/permissions.md)
- [Architecture](docs/architecture.md)
- [Receipts And Journals](docs/audit-log.md)
- [Prototype Demo](docs/prototype-demo.md)
- [MVP Scope](MVP_SCOPE.md)
- [Roadmap](ROADMAP.md)

## Repository Layout

- `crates/cli`: command-line app
- `crates/config`: config loading and validation
- `crates/policy`: protected-zone policy model
- `crates/enforcement`: Linux enforcement boundary
- `crates/snapshot`: snapshot and revert support
- `crates/journal`: file and network journal handling
- `crates/db`: SQLite persistence
- `apps/desktop`: native Linux desktop app
- `docs/`: user, security, architecture, install, and release notes

## License

MIT. See [LICENSE](LICENSE).
