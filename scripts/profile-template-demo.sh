#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="${WARDER_PROFILE_TEMPLATE_ROOT:-/tmp/warder-profile-template}"
DB_PATH="$DEMO_ROOT/warder.sqlite3"
PROTECTED_ROOT="$DEMO_ROOT/protected"
WRITABLE_ROOT="$DEMO_ROOT/workspace"
CONFIG_PATH="$DEMO_ROOT/profile-template.toml"

rm -rf "$DEMO_ROOT"
mkdir -p "$PROTECTED_ROOT" "$WRITABLE_ROOT"

cd "$ROOT_DIR"

profiles_text="$(cargo run -p warder-cli -- profiles)"
printf '%s\n' "$profiles_text"

if ! grep -q "template protected paths:" <<<"$profiles_text"; then
  echo "expected profiles output to include template protected paths" >&2
  exit 1
fi

profiles_json="$(cargo run -p warder-cli -- profiles --format json)"
if ! grep -q '"template"' <<<"$profiles_json"; then
  echo "expected profiles JSON to include setup templates" >&2
  exit 1
fi

cat > "$CONFIG_PATH" <<EOF
[enforcement]
landlock = "disabled"
cgroups = "best-effort"
writable-roots = ["$WRITABLE_ROOT"]

[network]
journal = true

[[zones]]
id = "template-protected"
name = "Profile Template Protected Directory"
description = "A generated protected directory from the profile-template smoke path."
paths = ["$PROTECTED_ROOT"]
write_policy = "deny"
snapshot = "best-effort"

[[agents]]
id = "codex-template-shell"
label = "Codex Template Shell"
command = "sh"
profile = "codex-cli"
EOF

if ! grep -q 'profile = "codex-cli"' "$CONFIG_PATH"; then
  echo "expected generated config to use the codex-cli profile" >&2
  exit 1
fi

cargo run -p warder-cli -- dry-run \
  --config "$CONFIG_PATH" \
  --agent codex-template-shell \
  -- sh -c "echo hello > $PROTECTED_ROOT/hello.txt"

run_output="$(
  cargo run -p warder-cli -- run \
    --config "$CONFIG_PATH" \
    --db "$DB_PATH" \
    --launch \
    --accept-degraded \
    --agent codex-template-shell \
    -- sh -c "echo hello > $PROTECTED_ROOT/hello.txt"
)"
printf '%s\n' "$run_output"

session_id="$(printf '%s\n' "$run_output" | awk '/^session / { print $2; exit }')"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in profile-template output" >&2
  exit 1
fi

receipt="$(
  cargo run -p warder-cli -- receipt \
    --db "$DB_PATH" \
    --session "$session_id"
)"
printf '%s\n' "$receipt"

if ! grep -q "status: completed" <<<"$receipt"; then
  echo "expected profile-template receipt to mark the session completed" >&2
  exit 1
fi

if ! grep -Eq "file activity: [1-9][0-9]* event\\(s\\)" <<<"$receipt"; then
  echo "expected profile-template receipt to report protected-zone file activity" >&2
  exit 1
fi

if ! grep -q "session readiness:" <<<"$receipt"; then
  echo "expected profile-template receipt to include readiness output" >&2
  exit 1
fi
