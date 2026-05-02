# Tests

Most focused tests live beside the Rust modules they exercise. Cross-crate integration tests can live here when a behavior needs the CLI, config, enforcement, snapshot, journal, and persistence layers together.

`final-sandbox-matrix.sh` is an opt-in live Linux check for hosts with Landlock and cgroup delegation. It launches a strict session with an external receipt key and experimental read denial, verifies dangerous namespace/mount syscalls are blocked from the supervised child, checks the prepared cgroup marker, and runs `warder verify-receipts --external-key`.
