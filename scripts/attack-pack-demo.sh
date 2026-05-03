#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="${WARDER_ATTACK_PACK_ROOT:-/tmp/warder-attack-pack}"
DB_PATH="$DEMO_ROOT/warder.sqlite3"
CONFIG_PATH="$DEMO_ROOT/attack-pack.toml"
WORKSPACE_ROOT="$DEMO_ROOT/workspace"
PROTECTED_ROOT="$DEMO_ROOT/protected-secret"
NETWORK_URL="${WARDER_ATTACK_PACK_URL:-http://127.0.0.1:9}"

rm -rf "$DEMO_ROOT"
mkdir -p "$WORKSPACE_ROOT" "$PROTECTED_ROOT"
printf 'do-not-change\n' > "$PROTECTED_ROOT/secret.txt"

cat > "$CONFIG_PATH" <<EOF
[enforcement]
landlock = "best-effort"
cgroups = "best-effort"
writable-roots = ["$WORKSPACE_ROOT"]

[network]
journal = true

[[zones]]
id = "demo-secret"
name = "Demo Secret"
description = "Throwaway secret path for Warder's attack-pack demo."
paths = ["$PROTECTED_ROOT"]
write_policy = "deny"
# Read protection is intentionally off for the default demo. Warder should say
# that clearly in the receipt; enable read-deny in a separate strict host test.
read-deny = false
snapshot = "disabled"

[[agents]]
id = "attack-pack-shell"
label = "Attack Pack Shell"
command = "sh"
profile = "local-script"
EOF

cd "$ROOT_DIR"

echo "== Warder attack-pack demo =="
echo "workspace: $WORKSPACE_ROOT"
echo "protected: $PROTECTED_ROOT"
echo
echo "This demo attempts a protected write, a protected read, a workspace edit,"
echo "and a network connection. Warder should report what was blocked, observed,"
echo "or degraded on this host."
echo

cargo run -p warder-cli -- dry-run \
  --config "$CONFIG_PATH" \
  --agent attack-pack-shell \
  -- sh -c "true"

run_output="$(
  cargo run -p warder-cli -- run \
    --config "$CONFIG_PATH" \
    --db "$DB_PATH" \
    --launch \
    --accept-degraded \
    --agent attack-pack-shell \
    -- sh -c "\
      set +e
      printf changed > '$PROTECTED_ROOT/secret.txt'
      protected_write_status=\$?
      cat '$PROTECTED_ROOT/secret.txt' >/dev/null
      protected_read_status=\$?
      printf allowed > '$WORKSPACE_ROOT/allowed.txt'
      workspace_write_status=\$?
      if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 2 '$NETWORK_URL' >/dev/null 2>&1
        network_status=\$?
      else
        network_status=127
      fi
      printf 'protected_write=%s protected_read=%s workspace_write=%s network=%s\n' \
        \"\$protected_write_status\" \"\$protected_read_status\" \"\$workspace_write_status\" \"\$network_status\"
      exit 0"
)"
printf '%s\n' "$run_output"

session_id="$(printf '%s\n' "$run_output" | awk '/^session / { print $2; exit }')"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in attack-pack output" >&2
  exit 1
fi

receipt="$(
  cargo run -p warder-cli -- receipt \
    --db "$DB_PATH" \
    --session "$session_id"
)"
printf '%s\n' "$receipt"

if ! grep -q "status: completed" <<<"$receipt"; then
  echo "expected attack-pack receipt to mark the session completed" >&2
  exit 1
fi

if grep -q '^changed$' "$PROTECTED_ROOT/secret.txt"; then
  echo
  echo "result: protected write was not blocked on this host/config."
  echo "review the degraded protection section above before trusting enforcement."
else
  echo
  echo "result: protected write did not modify the secret file."
fi

if [[ -f "$WORKSPACE_ROOT/allowed.txt" ]]; then
  echo "result: workspace edit was allowed."
else
  echo "expected workspace edit to be allowed" >&2
  exit 1
fi

echo
cargo run -p warder-cli -- journal \
  --db "$DB_PATH" \
  --session "$session_id" \
  --all
