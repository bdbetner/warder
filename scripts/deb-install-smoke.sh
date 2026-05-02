#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEB_PATH="${1:-}"
TEST_ROOT="${WARDER_DEB_INSTALL_SMOKE_ROOT:-/tmp/warder-deb-install-smoke}"
INSTALL_ROOT="$TEST_ROOT/root"
ADMIN_DIR="$TEST_ROOT/dpkg"
DPKG_LOG="$TEST_ROOT/dpkg.log"

if [[ -z "$DEB_PATH" ]]; then
  shopt -s nullglob
  debs=("$ROOT_DIR"/target/release/bundle/deb/*.deb)
  shopt -u nullglob
  if [[ ${#debs[@]} -ne 1 ]]; then
    echo "expected exactly one .deb under target/release/bundle/deb, found ${#debs[@]}" >&2
    exit 1
  fi
  DEB_PATH="${debs[0]}"
fi

if [[ ! -f "$DEB_PATH" ]]; then
  echo "missing .deb package: $DEB_PATH" >&2
  exit 1
fi

if ! command -v fakeroot >/dev/null 2>&1; then
  echo "fakeroot is required for rootless Debian install smoke" >&2
  exit 1
fi

rm -rf "$TEST_ROOT"
mkdir -p "$INSTALL_ROOT" "$ADMIN_DIR"

dpkg_root=(fakeroot dpkg --admindir="$ADMIN_DIR" --instdir="$INSTALL_ROOT" --log="$DPKG_LOG")

"${dpkg_root[@]}" --force-depends -i "$DEB_PATH"

test -x "$INSTALL_ROOT/usr/bin/warder"
test -x "$INSTALL_ROOT/usr/bin/warder-desktop"
test -f "$INSTALL_ROOT/usr/share/applications/Warder.desktop"
test -f "$INSTALL_ROOT/usr/share/icons/hicolor/32x32/apps/warder-desktop.png"

"$INSTALL_ROOT/usr/bin/warder" profiles --format json >/dev/null

SESSION_ROOT="$TEST_ROOT/session"
mkdir -p "$SESSION_ROOT/protected" "$SESSION_ROOT/writable"

"$INSTALL_ROOT/usr/bin/warder" init \
  --print \
  --profile local-script \
  --protected-path "$SESSION_ROOT/protected" \
  --agent-command sh > "$SESSION_ROOT/config.toml"

"$INSTALL_ROOT/usr/bin/warder" explain --config "$SESSION_ROOT/config.toml" >/dev/null
"$INSTALL_ROOT/usr/bin/warder" dry-run \
  --config "$SESSION_ROOT/config.toml" \
  --agent local-script \
  -- sh -c "printf dry-run > '$SESSION_ROOT/protected/should-not-exist.txt'" >/dev/null

if [[ -e "$SESSION_ROOT/protected/should-not-exist.txt" ]]; then
  echo "installed CLI dry-run unexpectedly wrote into the protected path" >&2
  exit 1
fi

(
  cd /tmp
  "$INSTALL_ROOT/usr/bin/warder" run \
    --config "$SESSION_ROOT/config.toml" \
    --db "$SESSION_ROOT/warder.sqlite3" \
    --launch \
    --accept-degraded \
    --agent local-script \
    -- sh -c "printf installed > '$SESSION_ROOT/protected/out.txt'"
  ) > "$SESSION_ROOT/run.out"

session_id="$(awk '/^session / { print $2; exit }' "$SESSION_ROOT/run.out")"
if [[ -z "$session_id" ]]; then
  echo "failed to find session id in installed CLI run output" >&2
  exit 1
fi

"$INSTALL_ROOT/usr/bin/warder" receipt \
  --db "$SESSION_ROOT/warder.sqlite3" \
  --session "$session_id" > "$SESSION_ROOT/receipt.txt"
"$INSTALL_ROOT/usr/bin/warder" receipt \
  --db "$SESSION_ROOT/warder.sqlite3" \
  --session "$session_id" \
  --format json | python3 -m json.tool >/dev/null
"$INSTALL_ROOT/usr/bin/warder" journal \
  --db "$SESSION_ROOT/warder.sqlite3" \
  --session "$session_id" \
  --all > "$SESSION_ROOT/journal.txt"

if ! grep -q "status: completed" "$SESSION_ROOT/receipt.txt"; then
  echo "expected installed CLI receipt to mark the session completed" >&2
  exit 1
fi

if ! grep -Eq "file activity: [1-9][0-9]* event\\(s\\)" "$SESSION_ROOT/receipt.txt"; then
  echo "expected installed CLI receipt to report protected-zone file activity" >&2
  exit 1
fi

if ! grep -q "$SESSION_ROOT/protected/out.txt" "$SESSION_ROOT/journal.txt"; then
  echo "expected installed CLI journal to include protected write path" >&2
  exit 1
fi

test -f "$SESSION_ROOT/protected/out.txt"

"${dpkg_root[@]}" --remove warder

if [[ -e "$INSTALL_ROOT/usr/bin/warder" || -e "$INSTALL_ROOT/usr/bin/warder-desktop" ]]; then
  echo "expected remove to delete Warder executables" >&2
  exit 1
fi
