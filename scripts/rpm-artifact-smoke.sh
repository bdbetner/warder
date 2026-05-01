#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RPM_PATH="${1:-}"

if [[ -z "$RPM_PATH" ]]; then
  shopt -s nullglob
  rpms=("$ROOT_DIR"/target/release/bundle/rpm/*.rpm)
  shopt -u nullglob
  if [[ ${#rpms[@]} -ne 1 ]]; then
    echo "expected exactly one RPM under target/release/bundle/rpm, found ${#rpms[@]}" >&2
    exit 1
  fi
  RPM_PATH="${rpms[0]}"
fi

if [[ ! -f "$RPM_PATH" ]]; then
  echo "missing RPM package: $RPM_PATH" >&2
  exit 1
fi

if ! command -v rpm >/dev/null 2>&1; then
  echo "rpm is required for RPM package smoke" >&2
  exit 1
fi

RPM_DB="$(mktemp -d)"
trap 'rm -rf "$RPM_DB"' EXIT
rpm_query=(rpm --dbpath "$RPM_DB")

package_name="$("${rpm_query[@]}" -qp --queryformat '%{NAME}' "$RPM_PATH")"
summary="$("${rpm_query[@]}" -qp --queryformat '%{SUMMARY}' "$RPM_PATH")"
contents="$("${rpm_query[@]}" -qpl "$RPM_PATH")"

required_paths=(
  "/usr/bin/warder"
  "/usr/bin/warder-desktop"
  "/usr/share/applications/Warder.desktop"
  "/usr/share/icons/hicolor/32x32/apps/warder-desktop.png"
)

for path in "${required_paths[@]}"; do
  if ! grep -q "^${path}$" <<<"$contents"; then
    echo "expected RPM package to contain $path" >&2
    exit 1
  fi
done

if [[ "$package_name" != "warder" ]]; then
  echo "expected RPM package name to be warder, got $package_name" >&2
  exit 1
fi

if [[ "$summary" != "Local safety controls for supervised agent sessions." ]]; then
  echo "expected RPM package summary to be populated" >&2
  exit 1
fi
