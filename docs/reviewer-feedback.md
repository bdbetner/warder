# Reviewer Feedback Guide

This guide is for alpha reviewers evaluating Warder from release artifacts rather than a source checkout.

## Current Release

- Release: `v0.1.0-alpha.11`
- Release page: <https://github.com/betnbd/warder/releases/tag/v0.1.0-alpha.11>
- Platform target: Linux x86_64
- Recommended install path: `.deb` on Ubuntu/Debian or RPM on RPM-based distros

## What Warder Claims

Warder supervises commands launched through `warder run`, can deny protected writes with Linux Landlock where the host supports it, and records receipts that explain active and degraded coverage.

Warder does not claim read blocking, network blocking, complete socket forensics, receipts that cannot be altered by a local user or malware, or always-on protection for commands launched outside Warder.

## Reviewer Setup

Download and verify the release:

```bash
gh release download v0.1.0-alpha.11 --repo betnbd/warder --dir warder-linux-x86_64
cd warder-linux-x86_64
sha256sum --check SHA256SUMS
python3 -m json.tool release-manifest.json >/dev/null
```

Install on Ubuntu/Debian:

```bash
sudo apt install ./Warder_0.1.0_amd64.deb
warder --version
warder profiles --format json >/dev/null
```

## CLI Demo

Run a throwaway supervised session:

```bash
mkdir -p /tmp/warder-review-protected
warder init --print --profile local-script --agent-command sh --protected-path /tmp/warder-review-protected > /tmp/warder-review.toml
warder explain --config /tmp/warder-review.toml
warder dry-run --config /tmp/warder-review.toml --agent local-script -- sh -c 'true'
warder run --config /tmp/warder-review.toml --db /tmp/warder-review.sqlite3 --launch --accept-degraded --agent local-script -- sh -c 'printf demo > /tmp/warder-review-protected/demo.txt'
warder receipt --db /tmp/warder-review.sqlite3 --session <session-id>
warder journal --db /tmp/warder-review.sqlite3 --session <session-id> --file
```

On many alpha review hosts, Landlock, delegated cgroups, Btrfs snapshots, or eBPF support may be unavailable. That is acceptable only if Warder reports the degraded coverage plainly before or after launch.
CLI launches now refuse degraded pre-launch readiness unless the reviewer includes `--accept-degraded`; the demo command includes it so alpha hosts can still exercise receipt and journal review while seeing the degraded coverage in output.

## GUI Demo

Launch the installed desktop app:

```bash
warder-desktop
```

Check these flows:

- Setup requires at least one protected path.
- Custom protected paths can be added, edited, removed, and saved.
- Dry-run displays policy and degraded coverage before launch.
- Launch is disabled until launch readiness has been reviewed.
- Strict write-block mode refuses launch on hosts without required enforcement.
- Best-effort launch completes on a degraded host only after explicit degraded acknowledgement and records honest degraded coverage.
- Receipt tabs show summary, file activity, network activity, snapshot/recovery, degraded coverage, and raw receipt.
- Journal and receipt views handle missing or invalid sessions with readable errors.

## Feedback Questions

- Is the install and verification path clear enough to run without source-tree knowledge?
- Does `explain` or `dry-run` make it obvious what Warder will and will not enforce?
- Does the receipt make degraded coverage hard to miss?
- Are the GUI setup and command controls understandable for a non-expert Linux user?
- Are any docs or UI labels overstating read protection, network enforcement, receipt integrity, or always-on protection?
- Which missing feature would most improve trust: pre-spawn cgroup placement, stronger receipt attestation, seccomp/capability bounding, or network blocking?

## Cleanup

Remove the package on Ubuntu/Debian:

```bash
sudo apt remove warder
rm -rf /tmp/warder-review-protected /tmp/warder-review.toml /tmp/warder-review.sqlite3
```
