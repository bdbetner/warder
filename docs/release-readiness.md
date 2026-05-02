# Release Readiness

Use this page as the final gate before publishing a public beta release.

## Release Positioning

Warder should be published as a Linux supervised-session safety layer, not as broad security tooling.

Warder v1.0 is scoped to processes launched through `warder run` or the desktop launcher. Global always-on supervision, meaning host-wide protection for processes launched outside Warder, is planned for v1.1.

Defensible v1 promise:

> Warder supervises commands launched through `warder run` or the desktop launcher, can deny protected writes with Linux Landlock where available, can optionally apply experimental read-denial policies with an explicit readable-root allowlist, and records receipts that explain active and degraded coverage.

Do not claim:

- read blocking by default or without explicit `read_deny = true` or `read_policy = "deny"` plus disjoint `enforcement.readable_roots`;
- destination-aware network blocking;
- receipts that cannot be altered by a local user or malware;
- complete socket forensics;
- always-on protection for commands launched outside Warder; global supervision is planned for v1.1.

## Product Decisions

- Strict write-block launch is the default for new GUI setups. Best-effort launch remains available as an explicit reviewer choice for hosts that cannot apply protected write blocking.
- The GUI must require at least one protected path before saving setup or launching.
- The GUI must require launch-readiness review before enabling every launch.
- Receipts are both user-facing accountability evidence and developer diagnostics. They must separate enforced controls, observed activity, degraded coverage, and suggested next actions.
- AppImage is GUI-only. Release notes and install docs must pair it with the standalone `warder` CLI binary.
- The daemon remains experimental. Normal v1 demos and docs should use `warder run`, not daemon workflows.

## Reviewer Demo Path

Every reviewer should be able to run this path from installed artifacts:

```bash
mkdir -p /tmp/warder-review-protected
warder profiles --format json >/dev/null
warder init --print --profile local-script --agent-command sh --protected-path /tmp/warder-review-protected > /tmp/warder-review.toml
warder explain --config /tmp/warder-review.toml
warder dry-run --config /tmp/warder-review.toml --agent local-script -- sh -c 'true'
warder run --config /tmp/warder-review.toml --launch --accept-degraded --agent local-script -- sh -c 'printf demo > /tmp/warder-review-protected/demo.txt'
warder-desktop
```

Expected result on degraded hosts: the launch must be refused unless `--accept-degraded` is present; when accepted, the session may report degraded Landlock, cgroup, Btrfs, or eBPF coverage, but the receipt must say so plainly.

## Pull-Release Criteria

Pull or replace a release if any of these are found:

- protected writes are claimed as blocked when Landlock was not applied;
- `--require-enforcement` launches despite missing required write-blocking;
- GUI launch works with no protected path selected;
- receipts or docs imply default read blocking or network enforcement in v1;
- package smoke fails for `.deb`, RPM, or AppImage;
- checksum or manifest data does not match the uploaded artifacts;
- a local secret or private workflow artifact is published in the release.
