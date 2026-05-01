#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_ROOT="${WARDER_OPENCLAW_SMOKE_ROOT:-/tmp/warder-openclaw-smoke}"
DB_PATH="$DEMO_ROOT/warder.sqlite3"
PROTECTED_ROOT="$DEMO_ROOT/protected"
WORKSPACE_ROOT="$DEMO_ROOT/workspace"
CONFIG_PATH="$DEMO_ROOT/openclaw.toml"
STUB_DIR="$DEMO_ROOT/bin"

rm -rf "$DEMO_ROOT"
mkdir -p "$PROTECTED_ROOT" "$WORKSPACE_ROOT" "$STUB_DIR"

if command -v openclaw >/dev/null 2>&1; then
  OPENCLAW_BIN="$(command -v openclaw)"
  OPENCLAW_MODE="real"
else
  OPENCLAW_BIN="$STUB_DIR/openclaw"
  OPENCLAW_MODE="stub"
  cat > "$OPENCLAW_BIN" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  "security audit --json")
    printf '{"findings":[{"checkId":"gateway.bind_no_auth","severity":"critical"}]}\n'
    ;;
  "sandbox explain --json")
    printf '{"sandbox":{"mode":"all","backend":"docker","scope":"session","docker":{"network":"host","binds":["/var/run/docker.sock:/var/run/docker.sock"]}}}\n'
    ;;
  "--version")
    printf 'openclaw stub 0.0.0\n'
    ;;
  *)
    printf 'openclaw stub: %s\n' "$*"
    ;;
esac
EOF
  chmod +x "$OPENCLAW_BIN"
  export PATH="$STUB_DIR:$PATH"
fi

cat > "$CONFIG_PATH" <<EOF
[enforcement]
landlock = "disabled"
cgroups = "best-effort"
writable-roots = ["$WORKSPACE_ROOT"]

[network]
journal = true

[[zones]]
id = "openclaw-protected"
name = "OpenClaw Smoke Protected Directory"
description = "Throwaway protected directory for OpenClaw integration smoke validation."
paths = ["$PROTECTED_ROOT"]
write_policy = "deny"
snapshot = "disabled"

[[agents]]
id = "openclaw"
label = "OpenClaw"
command = "$OPENCLAW_BIN"
profile = "openclaw-agent"
EOF

cd "$ROOT_DIR"

profiles_json="$(cargo run -p warder-cli -- profiles --format json)"
if ! grep -q '"id": "openclaw-agent"' <<<"$profiles_json"; then
  echo "expected profile catalog to include openclaw-agent" >&2
  exit 1
fi

dry_run="$(
  cargo run -p warder-cli -- dry-run \
    --config "$CONFIG_PATH" \
    --agent openclaw \
    -- "$OPENCLAW_BIN" --version
)"
printf '%s\n' "$dry_run"

if ! grep -q "profile: openclaw-agent" <<<"$dry_run"; then
  echo "expected dry-run to use the openclaw-agent profile" >&2
  exit 1
fi

if ! grep -q "openclaw preflight:" <<<"$dry_run"; then
  echo "expected dry-run to include OpenClaw preflight output" >&2
  exit 1
fi

run_output="$(
  cargo run -p warder-cli -- run \
    --config "$CONFIG_PATH" \
    --db "$DB_PATH" \
    --launch \
    --agent openclaw \
    -- "$OPENCLAW_BIN" --version
)"
printf '%s\n' "$run_output"

session_id="$(printf '%s\n' "$run_output" | awk '/^session / { print $2; exit }')"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in OpenClaw smoke output" >&2
  exit 1
fi

receipt="$(
  cargo run -p warder-cli -- receipt \
    --db "$DB_PATH" \
    --session "$session_id"
)"
printf '%s\n' "$receipt"

if ! grep -q "profile: openclaw-agent" <<<"$receipt"; then
  echo "expected receipt to preserve the openclaw-agent profile" >&2
  exit 1
fi

if ! grep -q "Run OpenClaw security audit" <<<"$receipt"; then
  echo "expected receipt to include OpenClaw security audit action" >&2
  exit 1
fi

cargo run -p warder-cli -- journal \
  --db "$DB_PATH" \
  --session "$session_id" \
  --all

printf 'OpenClaw integration smoke completed using %s OpenClaw command: %s\n' "$OPENCLAW_MODE" "$OPENCLAW_BIN"
