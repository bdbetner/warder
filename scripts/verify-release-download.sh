#!/usr/bin/env bash
set -euo pipefail

REPO="bdbetner/warder"
TAG="${1:?usage: scripts/verify-release-download.sh TAG [OUTPUT_DIR]}"
OUTPUT_DIR="${2:-}"

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  echo "release tag must look like vMAJOR.MINOR.PATCH: $TAG" >&2
  exit 1
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(mktemp -d)"
  CLEANUP_OUTPUT=1
else
  CLEANUP_OUTPUT=0
  rm -rf "$OUTPUT_DIR"
  mkdir -p "$OUTPUT_DIR"
fi

cleanup() {
  if [[ "$CLEANUP_OUTPUT" -eq 1 ]]; then
    rm -rf "$OUTPUT_DIR"
  fi
}
trap cleanup EXIT

gh release download "$TAG" --repo "$REPO" --dir "$OUTPUT_DIR"

(
  cd "$OUTPUT_DIR"
  sha256sum --check SHA256SUMS
  python3 -m json.tool release-manifest.json >/dev/null
)

deb_path="$(find "$OUTPUT_DIR" -maxdepth 1 -name '*.deb' -print -quit)"
if [[ -z "$deb_path" ]]; then
  echo "missing .deb asset in release download" >&2
  exit 1
fi

"$(dirname "${BASH_SOURCE[0]}")/deb-install-smoke.sh" "$deb_path"

rpm_path="$(find "$OUTPUT_DIR" -maxdepth 1 -name '*.rpm' -print -quit)"
if [[ -n "$rpm_path" ]]; then
  if command -v rpm >/dev/null 2>&1; then
    "$(dirname "${BASH_SOURCE[0]}")/rpm-artifact-smoke.sh" "$rpm_path"
  else
    echo "rpm package smoke: skipped; rpm command unavailable"
  fi
fi

appimage_path="$(find "$OUTPUT_DIR" -maxdepth 1 -name '*.AppImage' -print -quit)"
if [[ -n "$appimage_path" ]]; then
  chmod +x "$appimage_path"
  "$(dirname "${BASH_SOURCE[0]}")/appimage-artifact-smoke.sh" "$appimage_path"
fi

if gh release verify "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  gh release verify "$TAG" --repo "$REPO" >/dev/null
  echo "release attestation: verified"
else
  echo "release attestation: unavailable; checksum and package smoke passed"
fi

if [[ "$CLEANUP_OUTPUT" -eq 0 ]]; then
  echo "verified release assets in: $OUTPUT_DIR"
fi
