#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="${WARDER_LANDLOCK_DEMO_ROOT:-/tmp/warder-landlock-demo}"
DB_PATH="$DEMO_ROOT/warder.sqlite3"
CGROUP_ROOT="$DEMO_ROOT/cgroup"
PROTECTED_ROOT="$DEMO_ROOT/protected"
WRITABLE_ROOT="${WARDER_LANDLOCK_WRITABLE_ROOT:-/var/tmp/warder-landlock-demo-writable}"
CONFIG_PATH="$DEMO_ROOT/landlock-demo.toml"

rm -rf "$DEMO_ROOT" "$WRITABLE_ROOT"
mkdir -p "$PROTECTED_ROOT" "$WRITABLE_ROOT" "$CGROUP_ROOT"
touch "$CGROUP_ROOT/cgroup.procs"

cat > "$CONFIG_PATH" <<EOF
[enforcement]
landlock = "required"
cgroups = "required"
writable-roots = ["$WRITABLE_ROOT"]

[[zones]]
id = "landlock-protected"
name = "Landlock Protected Directory"
description = "A throwaway directory used to prove required Landlock write denial when the host supports it."
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
  -- sh -c "printf denied > $PROTECTED_ROOT/blocked.txt"

set +e
run_output="$(
  cargo run -p warder-cli -- run \
    --config "$CONFIG_PATH" \
    --db "$DB_PATH" \
    --cgroup-root "$CGROUP_ROOT" \
    --launch \
    --accept-degraded \
    --agent local-shell \
    -- sh -c "printf denied > $PROTECTED_ROOT/blocked.txt" 2>&1
)"
run_status=$?
set -e

printf '%s\n' "$run_output"

if [[ "$run_status" -ne 0 ]]; then
  if grep -q "Landlock enforcement is required" <<<"$run_output"; then
    if [[ -e "$PROTECTED_ROOT/blocked.txt" ]]; then
      echo "protected write unexpectedly created $PROTECTED_ROOT/blocked.txt" >&2
      exit 1
    fi
    echo "required Landlock failed closed before launch"
    exit 0
  fi
  exit "$run_status"
fi

if [[ -e "$PROTECTED_ROOT/blocked.txt" ]]; then
  echo "protected write unexpectedly created $PROTECTED_ROOT/blocked.txt" >&2
  exit 1
fi

if grep -q "agent command exited with code 0" <<<"$run_output"; then
  echo "protected write command unexpectedly succeeded" >&2
  exit 1
fi

session_id="$(printf '%s\n' "$run_output" | awk '/^session / { print $2; exit }')"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in Landlock demo output" >&2
  exit 1
fi

receipt="$(
  cargo run -p warder-cli -- receipt \
    --db "$DB_PATH" \
    --session "$session_id"
)"
printf '%s\n' "$receipt"

if ! grep -q "status: failed" <<<"$receipt"; then
  echo "expected receipt to mark the denied write session failed" >&2
  exit 1
fi

if ! grep -q "landlock: applied" <<<"$receipt"; then
  echo "expected receipt to show applied Landlock enforcement" >&2
  exit 1
fi
