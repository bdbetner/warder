#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

public_files=(
  "$ROOT_DIR/README.md"
  "$ROOT_DIR/PRODUCT_SPEC.md"
  "$ROOT_DIR/MVP_SCOPE.md"
  "$ROOT_DIR/ROADMAP.md"
  "$ROOT_DIR/THREAT_MODEL.md"
  "$ROOT_DIR/docs"
)

require_text() {
  local file="$1"
  local text="$2"

  if ! grep -Fq "$text" "$file"; then
    echo "missing required public-limit text in $file: $text" >&2
    exit 1
  fi
}

reject_text() {
  local pattern="$1"

  if grep -RInP "$pattern" "${public_files[@]}"; then
    echo "public docs appear to overstate Warder's v1 guarantees: $pattern" >&2
    exit 1
  fi
}

require_text "$ROOT_DIR/README.md" "Warder only supervises processes launched via \`warder run\` or the desktop launcher."
require_text "$ROOT_DIR/README.md" "Current network journaling is visibility, not complete network enforcement."
require_text "$ROOT_DIR/README.md" "not tamper-proof forensics"
require_text "$ROOT_DIR/docs/security-model.md" "It cannot enforce \`network.allowed_destinations\` yet"
require_text "$ROOT_DIR/docs/security-model.md" "They are not the primary write-denial boundary"
require_text "$ROOT_DIR/THREAT_MODEL.md" "That is visibility, not network enforcement"

reject_text "is tamper[- ]proof"
reject_text "tamper[- ]proof receipts"
reject_text "network (blocking|blocker|enforcement) is implemented"
reject_text "provides complete socket forensics"
reject_text "is an always[- ]on (system )?guard"
reject_text "read (blocking|denial|lockout) is implemented"
