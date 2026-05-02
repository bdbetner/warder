#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR/apps/desktop"
npm test -- --run src/App.button-audit.test.tsx src/App.smoke.test.tsx src/command.test.ts

cd "$ROOT_DIR"
cargo test -p warder-desktop
