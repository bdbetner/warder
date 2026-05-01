#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${ROOT_DIR}/ebpf/warder_file_access.bpf.c"
OUT_DIR="${WARDER_EBPF_BUILD_DIR:-${ROOT_DIR}/target/ebpf}"
OBJECT="${OUT_DIR}/warder_file_access.bpf.o"
CLANG="${CLANG:-clang}"
ARCH="${WARDER_BPF_TARGET:-bpfel}"

if ! command -v "$CLANG" >/dev/null 2>&1; then
  echo "clang is required to build Warder's eBPF file journal object" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

"$CLANG" \
  -target "$ARCH" \
  -O2 \
  -g \
  -Wall \
  -Werror \
  -c "$SOURCE" \
  -o "$OBJECT"

printf '%s\n' "$OBJECT"
