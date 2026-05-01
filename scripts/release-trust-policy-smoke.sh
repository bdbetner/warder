#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

required_files=(
  "$ROOT_DIR/docs/release-trust.md"
  "$ROOT_DIR/docs/install.md"
  "$ROOT_DIR/.github/workflows/ci.yml"
  "$ROOT_DIR/scripts/write-release-notes.sh"
  "$ROOT_DIR/.github/workflows/release.yml"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "missing release trust policy input: $file" >&2
    exit 1
  fi
done

require_text() {
  local file="$1"
  local text="$2"

  if ! grep -Fq "$text" "$file"; then
    echo "missing required release trust policy text in $file: $text" >&2
    exit 1
  fi
}

require_text "$ROOT_DIR/docs/release-trust.md" "Package-manager signatures are not included in current alpha releases."
require_text "$ROOT_DIR/docs/release-trust.md" "Do not add long-lived package signing keys until key custody, rotation, and user verification docs are decided."
require_text "$ROOT_DIR/.github/workflows/release.yml" "github.repository_visibility == 'public'"
require_text "$ROOT_DIR/.github/workflows/ci.yml" "scripts/release-trust-policy-smoke.sh"
require_text "$ROOT_DIR/.github/workflows/release.yml" "scripts/release-trust-policy-smoke.sh"
require_text "$ROOT_DIR/docs/install.md" "release-trust.md"

fixture_dir="$(mktemp -d)"
notes_file="$(mktemp)"
trap 'rm -rf "$fixture_dir" "$notes_file"' EXIT

printf '{}\n' > "$fixture_dir/release-manifest.json"
printf '' > "$fixture_dir/SHA256SUMS"

"$ROOT_DIR/scripts/write-release-notes.sh" v0.1.0-alpha.99 "$fixture_dir" "$notes_file"

require_text "$notes_file" "Package-manager signatures are not included in this alpha release."
require_text "$notes_file" "GitHub artifact attestations are available only when the repository supports them."
