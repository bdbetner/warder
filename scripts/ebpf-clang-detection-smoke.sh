#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/warder-ebpf-clang-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

bad_clang="${tmp_dir}/clang-swift-wrapper"
good_clang="${tmp_dir}/clang-system"

cat >"$bad_clang" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "Apple Swift version 6.0.0 (swiftlang-6.0.0)"
  exit 0
fi
exit 139
SH

cat >"$good_clang" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "Ubuntu clang version 18.1.3"
  exit 0
fi
exit 0
SH

chmod +x "$bad_clang" "$good_clang"

selected="$(
  WARDER_BPF_CLANG_CANDIDATES="${bad_clang} ${good_clang}" \
    bash -c 'source scripts/ebpf-clang.sh; warder_select_bpf_clang'
)"
if [[ "$selected" != "$good_clang" ]]; then
  echo "expected eBPF Clang selector to skip Swift wrapper and choose '$good_clang', got '$selected'" >&2
  exit 1
fi

if CLANG="$bad_clang" bash -c 'source scripts/ebpf-clang.sh; warder_select_bpf_clang' 2>"${tmp_dir}/explicit.err"; then
  echo "expected explicit Swift wrapper CLANG to be rejected" >&2
  exit 1
fi
if ! grep -Fq "Swift toolchain Clang wrapper" "${tmp_dir}/explicit.err"; then
  echo "expected explicit Swift wrapper rejection to explain the compiler problem" >&2
  cat "${tmp_dir}/explicit.err" >&2
  exit 1
fi

echo "eBPF Clang detection smoke passed"
