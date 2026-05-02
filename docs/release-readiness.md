# Release Readiness

Use this page as the final gate before publishing an alpha release.

## Release Positioning

Warder should be published as an alpha Linux supervised-session tool, not as broad security tooling.

Defensible v1 promise:

> Warder supervises commands launched through Warder, can deny protected writes with Linux Landlock where available, and records receipts that explain active and degraded coverage.

Do not claim:

- read blocking;
- destination-aware network blocking;
- receipts that cannot be altered by a local user or malware;
- complete socket forensics;
- always-on protection for commands launched outside Warder.

## Product Decisions

- Strict write-block launch is opt-in. It should stay visible in the CLI and GUI, but not default-on, because many review hosts will otherwise fail before users can learn the workflow.
- The GUI must require at least one protected path before saving setup or launching.
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
- receipts or docs imply read blocking or network enforcement in v1;
- package smoke fails for `.deb`, RPM, or AppImage;
- checksum or manifest data does not match the uploaded artifacts;
- a local secret or private workflow artifact is published in the release.
