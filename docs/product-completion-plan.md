# Product Completion Plan

This is the proposed final-product path for the current alpha: a Linux CLI-first supervised-session tool with a native desktop companion, honest receipts, installable release artifacts, and explicit limits.

## Final Alpha Definition

- `warder run` is the production path for supervised local agent sessions.
- The desktop app configures protected paths, runs dry-runs, launches supervised sessions, and reviews receipts/journals without broad frontend plugin permissions.
- Receipts distinguish enforced controls, observed activity, degraded coverage, recovery actions, and local HMAC signatures.
- Release artifacts are built by CI and include package smoke tests, checksums, manifest metadata, install docs, and trust docs.
- The daemon remains experimental unless it gains real IPC/session coordination with tests.

## Remaining Execution Steps

1. Keep security docs and roadmap aligned with the implemented hardening state.
2. Keep Tauri capabilities explicit and narrow.
3. Provide first-class local receipt key initialization and permission checks.
4. Confirm the daemon is deferred from the final alpha product surface.
5. Run final product-readiness gates: full workspace tests, desktop build/test, package/release smoke through CI, and public-doc claim scan.

## Deferred From This Alpha

- Network blocking or destination enforcement.
- Tamper-proof or public-key forensic receipts.
- Complete socket/file coverage.
- Always-on host protection.
- Required daemon-backed enforcement.
- Container-runtime enforcement beyond explicit degraded-mode reporting.
