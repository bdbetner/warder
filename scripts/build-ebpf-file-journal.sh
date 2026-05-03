#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${ROOT_DIR}/ebpf/warder_file_access.bpf.c"
OUT_DIR="${WARDER_EBPF_BUILD_DIR:-${ROOT_DIR}/target/ebpf}"
OBJECT="${OUT_DIR}/warder_file_access.bpf.o"
ARCH="${WARDER_BPF_TARGET:-bpfel}"

source "${ROOT_DIR}/scripts/ebpf-clang.sh"
CLANG_BIN="$(warder_select_bpf_clang)"

mkdir -p "$OUT_DIR"

"$CLANG_BIN" \
  -target "$ARCH" \
  -O2 \
  -g \
  -Wall \
  -Werror \
  -c "$SOURCE" \
  -o "$OBJECT"

printf '%s\n' "$OBJECT"
