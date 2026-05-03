# Tests

Most focused tests live beside the Rust modules they exercise. Cross-crate integration tests can live here when a behavior needs the CLI, config, enforcement, snapshot, journal, and persistence layers together.

`final-sandbox-matrix.sh` is an opt-in live Linux check for hosts with Landlock and cgroup delegation. It launches a strict session with an external receipt key and experimental read denial, verifies dangerous namespace/mount syscalls are blocked from the supervised child, checks the prepared cgroup marker, and runs `warder verify-receipts --external-key`.

`adversarial-hardening.sh` is the lightweight automated escape-regression suite. It runs the targeted Rust tests for Landlock rule revalidation, seccomp denial coverage, root child privilege state, private state path placement, and desktop invoke scoping. Set `WARDER_RUN_LIVE_ESCAPE_TESTS=1` to append the live `final-sandbox-matrix.sh` check on a host with the required kernel support.
