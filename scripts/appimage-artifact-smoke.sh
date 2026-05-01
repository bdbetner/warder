#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPIMAGE_PATH="${1:-}"

if [[ -z "$APPIMAGE_PATH" ]]; then
  shopt -s nullglob
  appimages=("$ROOT_DIR"/target/release/bundle/appimage/*.AppImage)
  shopt -u nullglob
  if [[ ${#appimages[@]} -ne 1 ]]; then
    echo "expected exactly one AppImage under target/release/bundle/appimage, found ${#appimages[@]}" >&2
    exit 1
  fi
  APPIMAGE_PATH="${appimages[0]}"
fi

if [[ ! -f "$APPIMAGE_PATH" ]]; then
  echo "missing AppImage package: $APPIMAGE_PATH" >&2
  exit 1
fi

if [[ ! -x "$APPIMAGE_PATH" ]]; then
  echo "expected AppImage to be executable: $APPIMAGE_PATH" >&2
  exit 1
fi

magic="$(od -An -tx1 -N4 "$APPIMAGE_PATH" | tr -d ' \n')"
if [[ "$magic" != "7f454c46" ]]; then
  echo "expected AppImage to have an ELF header: $APPIMAGE_PATH" >&2
  exit 1
fi
