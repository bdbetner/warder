#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="${WARDER_DEMO_ROOT:-/tmp/warder-demo}"
DB_PATH="$DEMO_ROOT/warder.sqlite3"
CGROUP_ROOT="$DEMO_ROOT/cgroup"
PROTECTED_ROOT="$DEMO_ROOT/protected"
CONFIG_PATH="$DEMO_ROOT/local-demo.toml"

rm -rf "$DEMO_ROOT"
mkdir -p "$PROTECTED_ROOT" "$CGROUP_ROOT"
touch "$CGROUP_ROOT/cgroup.procs"

cat > "$CONFIG_PATH" <<EOF
[enforcement]
landlock = "disabled"
cgroups = "required"

[[zones]]
id = "demo-protected"
name = "Demo Protected Directory"
description = "A local throwaway directory for Warder's end-to-end prototype smoke test."
paths = ["$PROTECTED_ROOT"]
write_policy = "deny"
snapshot = "disabled"

[[agents]]
id = "local-shell"
label = "Local Shell"
command = "sh"
profile = "local-script"
EOF

cd "$ROOT_DIR"

cargo run -p warder-cli -- dry-run \
  --config "$CONFIG_PATH" \
  --agent local-shell \
  -- sh -c "echo hello > $PROTECTED_ROOT/hello.txt"

run_output="$(
  cargo run -p warder-cli -- run \
    --config "$CONFIG_PATH" \
    --db "$DB_PATH" \
    --cgroup-root "$CGROUP_ROOT" \
    --launch \
    --agent local-shell \
    -- sh -c "echo hello > $PROTECTED_ROOT/hello.txt"
)"
printf '%s\n' "$run_output"

session_id="$(printf '%s\n' "$run_output" | awk '/^session / { print $2; exit }')"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in demo run output" >&2
  exit 1
fi

receipt="$(
  cargo run -p warder-cli -- receipt \
    --db "$DB_PATH" \
    --session "$session_id"
)"
printf '%s\n' "$receipt"

if ! grep -q "status: completed" <<<"$receipt"; then
  echo "expected prototype receipt to mark the session completed" >&2
  exit 1
fi

if ! grep -Eq "file activity: [1-9][0-9]* event\\(s\\)" <<<"$receipt"; then
  echo "expected prototype receipt to report observed protected-zone file activity" >&2
  exit 1
fi

cargo run -p warder-cli -- journal \
  --db "$DB_PATH" \
  --session "$session_id" \
  --file
