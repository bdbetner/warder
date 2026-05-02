#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="${WARDER_RELEASE_ARTIFACT_TEST_ROOT:-/tmp/warder-release-artifact-smoke}"
TARGET_DIR="$TEST_ROOT/target/release"
ARTIFACT_DIR="$TEST_ROOT/artifacts"
DEB_DIR="$TARGET_DIR/bundle/deb"
APPIMAGE_DIR="$TARGET_DIR/bundle/appimage"
RPM_DIR="$TARGET_DIR/bundle/rpm"

rm -rf "$TEST_ROOT"
mkdir -p "$TARGET_DIR" "$DEB_DIR" "$APPIMAGE_DIR" "$RPM_DIR"

printf 'cli-binary\n' > "$TARGET_DIR/warder"
printf 'desktop-binary\n' > "$TARGET_DIR/warder-desktop"
printf 'deb-package\n' > "$DEB_DIR/Warder_1.0.0-beta.1_amd64.deb"
printf 'appimage-package\n' > "$APPIMAGE_DIR/Warder_1.0.0-beta.1_amd64.AppImage"
printf 'rpm-package\n' > "$RPM_DIR/Warder-1.0.0-beta.1-1.x86_64.rpm"
chmod +x "$TARGET_DIR/warder" "$TARGET_DIR/warder-desktop"
chmod +x "$APPIMAGE_DIR/Warder_1.0.0-beta.1_amd64.AppImage"

"$ROOT_DIR/scripts/collect-release-artifacts.sh" \
  --target-dir "$TARGET_DIR" \
  --output-dir "$ARTIFACT_DIR" \
  --deb-dir "$DEB_DIR" \
  --appimage-dir "$APPIMAGE_DIR" \
  --rpm-dir "$RPM_DIR" \
  --version 'v1.0.0-beta.1+"quoted"' \
  --commit 'abc123\def456'

test -x "$ARTIFACT_DIR/warder"
test -x "$ARTIFACT_DIR/warder-desktop"
test -f "$ARTIFACT_DIR/Warder_1.0.0-beta.1_amd64.deb"
test -x "$ARTIFACT_DIR/Warder_1.0.0-beta.1_amd64.AppImage"
test -f "$ARTIFACT_DIR/Warder-1.0.0-beta.1-1.x86_64.rpm"
test -f "$ARTIFACT_DIR/SHA256SUMS"
test -f "$ARTIFACT_DIR/release-manifest.json"

(
  cd "$ARTIFACT_DIR"
  sha256sum --check --status SHA256SUMS
)

if ! grep -q "  warder$" "$ARTIFACT_DIR/SHA256SUMS"; then
  echo "expected checksum entry for warder" >&2
  exit 1
fi

if ! grep -q "  warder-desktop$" "$ARTIFACT_DIR/SHA256SUMS"; then
  echo "expected checksum entry for warder-desktop" >&2
  exit 1
fi

if ! grep -q "  Warder_1.0.0-beta.1_amd64.deb$" "$ARTIFACT_DIR/SHA256SUMS"; then
  echo "expected checksum entry for Warder .deb package" >&2
  exit 1
fi

if ! grep -q "  Warder_1.0.0-beta.1_amd64.AppImage$" "$ARTIFACT_DIR/SHA256SUMS"; then
  echo "expected checksum entry for Warder AppImage package" >&2
  exit 1
fi

if ! grep -q "  Warder-1.0.0-beta.1-1.x86_64.rpm$" "$ARTIFACT_DIR/SHA256SUMS"; then
  echo "expected checksum entry for Warder RPM package" >&2
  exit 1
fi

if ! grep -q "  release-manifest.json$" "$ARTIFACT_DIR/SHA256SUMS"; then
  echo "expected checksum entry for release manifest" >&2
  exit 1
fi

python3 -m json.tool "$ARTIFACT_DIR/release-manifest.json" >/dev/null

python3 - "$ARTIFACT_DIR" <<'PY'
import hashlib
import json
import pathlib
import sys

artifact_dir = pathlib.Path(sys.argv[1])
manifest = json.loads((artifact_dir / "release-manifest.json").read_text())

expected_names = {
    "warder",
    "warder-desktop",
    "Warder_1.0.0-beta.1_amd64.deb",
    "Warder_1.0.0-beta.1_amd64.AppImage",
    "Warder-1.0.0-beta.1-1.x86_64.rpm",
}
entries = manifest.get("artifacts", [])
names = {entry.get("name") for entry in entries}
if names != expected_names:
    raise SystemExit(f"unexpected manifest artifact names: {sorted(names)}")

if manifest.get("schema_version") != 1:
    raise SystemExit("unexpected manifest schema version")

for entry in entries:
    name = entry["name"]
    if pathlib.PurePosixPath(name).is_absolute() or "/" in name:
        raise SystemExit(f"manifest artifact name must be a basename: {name}")
    data = (artifact_dir / name).read_bytes()
    checksum = hashlib.sha256(data).hexdigest()
    if entry.get("sha256") != checksum:
        raise SystemExit(f"manifest checksum mismatch for {name}")
    if entry.get("size_bytes") != len(data):
        raise SystemExit(f"manifest size mismatch for {name}")
PY

if ! grep -q '"target": "linux-x86_64"' "$ARTIFACT_DIR/release-manifest.json"; then
  echo "expected release manifest target" >&2
  exit 1
fi

for artifact in warder warder-desktop Warder_1.0.0-beta.1_amd64.deb Warder_1.0.0-beta.1_amd64.AppImage Warder-1.0.0-beta.1-1.x86_64.rpm; do
  if ! grep -q "\"name\": \"$artifact\"" "$ARTIFACT_DIR/release-manifest.json"; then
    echo "expected release manifest entry for $artifact" >&2
    exit 1
  fi
done
