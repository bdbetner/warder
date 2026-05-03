#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "adversarial hardening: Landlock race regression"
cargo test -p warder-enforcement landlock_final_revalidation

echo "adversarial hardening: seccomp deny-list coverage"
cargo test -p warder-enforcement supervised_seccomp_filter_denies_namespace_and_mount_syscalls

echo "adversarial hardening: root child privilege state"
cargo test -p warder-cli child_privilege_hardening_sets_no_new_privs_and_non_dumpable

echo "adversarial hardening: state path private-parent and ancestor checks"
cargo test -p warder-cli run_state_paths_reject_agent_writable_database_and_receipt_key
cargo test -p warder-cli run_state_paths_require_private_state_directory
cargo test -p warder-cli run_state_paths_reject_group_writable_state_ancestors
cargo test -p warder-cli run_state_paths_reject_writable_ancestor_when_state_parent_is_missing

echo "adversarial hardening: desktop invoke allowlist"
cargo test -p warder-desktop desktop_invoke_handler_uses_explicit_command_allowlist

if [[ "${WARDER_RUN_LIVE_ESCAPE_TESTS:-0}" == "1" ]]; then
  cargo build -p warder-cli --bin warder
  tests/final-sandbox-matrix.sh
else
  echo "adversarial hardening: live escape matrix skipped; set WARDER_RUN_LIVE_ESCAPE_TESTS=1 on a Landlock/cgroup-capable host"
fi
