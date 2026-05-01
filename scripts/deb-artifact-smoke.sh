#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEB_PATH="${1:-}"

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

contents="$(dpkg-deb -c "$DEB_PATH")"
control="$(dpkg-deb -I "$DEB_PATH")"

required_paths=(
  "usr/bin/warder"
  "usr/bin/warder-desktop"
  "usr/share/applications/Warder.desktop"
  "usr/share/icons/hicolor/32x32/apps/warder-desktop.png"
)

for path in "${required_paths[@]}"; do
  if ! grep -q " ${path}$" <<<"$contents"; then
    echo "expected package to contain $path" >&2
    exit 1
  fi
done

if ! grep -q "^ Package: warder$" <<<"$control"; then
  echo "expected Debian package name to be warder" >&2
  exit 1
fi

if ! grep -q "^ Description: Local safety controls for supervised agent sessions\\.$" <<<"$control"; then
  echo "expected Debian package description to be populated" >&2
  exit 1
fi
