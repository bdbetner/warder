#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLOW_ROOT="${WARDER_CLI_FLOW_ROOT:-/tmp/warder-cli-flow}"
DB_PATH="$FLOW_ROOT/warder.sqlite3"
PROTECTED_ROOT="$FLOW_ROOT/protected path"
CONFIG_PATH="$FLOW_ROOT/generated.toml"
STRICT_CONFIG_PATH="$FLOW_ROOT/strict-disabled.toml"

if [[ -n "${WARDER_BIN:-}" ]]; then
  WARDER_CMD=("$WARDER_BIN")
else
  WARDER_CMD=(cargo run -q -p warder-cli --)
fi

run_warder() {
  "${WARDER_CMD[@]}" "$@"
}

rm -rf "$FLOW_ROOT"
mkdir -p "$PROTECTED_ROOT"

cd "$ROOT_DIR"

run_warder init \
  --print \
  --profile local-script \
  --protected-path "$PROTECTED_ROOT" \
  --agent-command "sh" > "$CONFIG_PATH"

if [[ ! -s "$CONFIG_PATH" ]]; then
  echo "expected init --print to write starter TOML to stdout" >&2
  exit 1
fi

explain_output="$(run_warder explain --config "$CONFIG_PATH")"
printf '%s\n' "$explain_output"
if ! grep -q "policy explanation" <<<"$explain_output"; then
  echo "expected explain output to include policy explanation" >&2
  exit 1
fi
if ! grep -q "agent: local-script" <<<"$explain_output"; then
  echo "expected explain output to include generated local-script agent" >&2
  exit 1
fi

dry_run_output="$(
  run_warder dry-run \
    --config "$CONFIG_PATH" \
    --agent local-script \
    -- sh -c "printf hello > '$PROTECTED_ROOT/hello.txt'"
)"
printf '%s\n' "$dry_run_output"
if ! grep -q "launch: no command was run" <<<"$dry_run_output"; then
  echo "expected dry-run output to confirm no command was run" >&2
  exit 1
fi
if [[ -e "$PROTECTED_ROOT/hello.txt" ]]; then
  echo "dry-run unexpectedly wrote into the protected path" >&2
  exit 1
fi

sed 's/landlock = "best-effort"/landlock = "disabled"/' "$CONFIG_PATH" > "$STRICT_CONFIG_PATH"

set +e
strict_output="$(
  run_warder run \
    --config "$STRICT_CONFIG_PATH" \
    --db "$DB_PATH.strict" \
    --launch \
    --require-enforcement \
    --agent local-script \
    -- sh -c "printf strict > '$PROTECTED_ROOT/strict.txt'" 2>&1
)"
strict_status=$?
set -e
printf '%s\n' "$strict_output"
if [[ $strict_status -eq 0 ]]; then
  echo "expected strict write-block launch to fail when Landlock is disabled" >&2
  exit 1
fi
if ! grep -q -- "--require-enforcement refused" <<<"$strict_output"; then
  echo "expected strict write-block launch to explain enforcement refusal" >&2
  exit 1
fi
if [[ -e "$PROTECTED_ROOT/strict.txt" ]]; then
  echo "strict write-block refusal unexpectedly launched the command" >&2
  exit 1
fi

run_output="$(
  run_warder run \
    --config "$CONFIG_PATH" \
    --db "$DB_PATH" \
    --launch \
    --agent local-script \
    -- sh -c "printf hello > '$PROTECTED_ROOT/launched.txt'"
)"
printf '%s\n' "$run_output"

session_id="$(printf '%s\n' "$run_output" | awk '/^session / { print $2; exit }')"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in CLI flow output" >&2
  exit 1
fi

receipt="$(run_warder receipt --db "$DB_PATH" --session "$session_id")"
printf '%s\n' "$receipt"
if ! grep -q "status: completed" <<<"$receipt"; then
  echo "expected CLI flow receipt to mark the session completed" >&2
  exit 1
fi
if ! grep -q "session readiness:" <<<"$receipt"; then
  echo "expected CLI flow receipt to include session readiness" >&2
  exit 1
fi
if ! grep -Eq "file activity: [1-9][0-9]* event\\(s\\)" <<<"$receipt"; then
  echo "expected CLI flow receipt to report protected-zone file activity" >&2
  exit 1
fi

receipt_json="$(run_warder receipt --db "$DB_PATH" --session "$session_id" --format json)"
printf '%s\n' "$receipt_json" | python3 -m json.tool >/dev/null
if ! grep -q "\"status\": \"completed\"" <<<"$receipt_json"; then
  echo "expected CLI flow JSON receipt to mark the session completed" >&2
  exit 1
fi

journal="$(run_warder journal --db "$DB_PATH" --session "$session_id" --all)"
printf '%s\n' "$journal"
if ! grep -q "file journal:" <<<"$journal"; then
  echo "expected CLI flow journal readback to include file journal section" >&2
  exit 1
fi
if ! grep -q "$PROTECTED_ROOT/launched.txt" <<<"$journal"; then
  echo "expected CLI flow journal to include protected write path" >&2
  exit 1
fi
