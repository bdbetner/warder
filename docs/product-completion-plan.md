# Product Completion Plan

This is the completed alpha product checkpoint for `v0.1.0-alpha.11`: a Linux CLI-first supervised-session tool with a native desktop companion, honest receipts, installable release artifacts, and explicit limits.

## Alpha 11 Status

`v0.1.0-alpha.11` is published as a GitHub prerelease. The release was rehearsed from installed artifacts, including package verification, `.deb` install, CLI reviewer demo, installed desktop launch, AppImage launch, CI release gates, and downloaded-release checksum/package smoke verification.

## Final Alpha Definition

- `warder run` is the production path for supervised local agent sessions.
- The desktop app configures protected paths, runs dry-runs, launches supervised sessions, and reviews receipts/journals without broad frontend plugin permissions.
- Receipts distinguish enforced controls, observed activity, degraded coverage, recovery actions, and local HMAC signatures.
- Release artifacts are built by CI and include package smoke tests, checksums, manifest metadata, install docs, and trust docs.
- The daemon remains experimental unless it gains real IPC/session coordination with tests.

## Completed Release Gates

- Security docs and roadmap are aligned with the implemented hardening state.
- Tauri capabilities are explicit and narrow.
- Local receipt signing keys can be initialized, permission-checked, and reused.
- The daemon is deferred from the final alpha product surface.
- Product-readiness gates passed: full workspace tests, desktop build/test, package/release smoke through CI, public-doc claim scan, and installed-artifact reviewer demo.

## Reviewer Feedback Phase

Use [Reviewer Feedback Guide](reviewer-feedback.md) as the first-read path for external reviewers. Feedback should focus on whether the installed artifact flow is understandable, whether receipts make degraded protection obvious, whether the GUI matches CLI behavior, and whether the documented limits are clear enough for alpha users.

## Deferred From This Alpha

- Network blocking or destination enforcement.
- Tamper-proof or public-key forensic receipts.
- Complete socket/file coverage.
- Always-on host protection.
- Required daemon-backed enforcement.
- Container-runtime enforcement beyond explicit degraded-mode reporting.
