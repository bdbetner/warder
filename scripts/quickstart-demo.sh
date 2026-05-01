#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="${WARDER_QUICKSTART_ROOT:-/tmp/warder-quickstart}"
DB_PATH="$DEMO_ROOT/warder.sqlite3"
PROTECTED_ROOT="$DEMO_ROOT/protected"
CONFIG_PATH="$DEMO_ROOT/quickstart.toml"

rm -rf "$DEMO_ROOT"
mkdir -p "$PROTECTED_ROOT"

cat > "$CONFIG_PATH" <<EOF
[enforcement]
landlock = "disabled"
cgroups = "best-effort"

[network]
journal = false

[[zones]]
id = "quickstart-protected"
name = "Quickstart Protected Directory"
description = "A throwaway protected directory for trying Warder without delegated cgroup setup."
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
    --launch \
    --agent local-shell \
    -- sh -c "echo hello > $PROTECTED_ROOT/hello.txt"
)"
printf '%s\n' "$run_output"

session_id="$(printf '%s\n' "$run_output" | awk '/^session / { print $2; exit }')"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in quickstart output" >&2
  exit 1
fi

receipt="$(
  cargo run -p warder-cli -- receipt \
    --db "$DB_PATH" \
    --session "$session_id"
)"
printf '%s\n' "$receipt"

if ! grep -q "status: completed" <<<"$receipt"; then
  echo "expected quickstart receipt to mark the session completed" >&2
  exit 1
fi

if ! grep -q "cgroup: degraded: cgroup tagging skipped" <<<"$receipt"; then
  echo "expected quickstart receipt to report skipped best-effort cgroup tagging" >&2
  exit 1
fi

if ! grep -Eq "file activity: [1-9][0-9]* event\\(s\\)" <<<"$receipt"; then
  echo "expected quickstart receipt to report observed protected-zone file activity" >&2
  exit 1
fi

cargo run -p warder-cli -- journal \
  --db "$DB_PATH" \
  --session "$session_id" \
  --file
