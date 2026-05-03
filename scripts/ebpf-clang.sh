#!/usr/bin/env bash

warder_clang_version() {
  local candidate="$1"
  "$candidate" --version 2>&1
}

warder_is_swift_clang() {
  local version="$1"
  grep -Eiq 'swift|swiftlang|swiftly' <<<"$version"
}

warder_select_bpf_clang() {
  if [[ -n "${CLANG:-}" ]]; then
    if ! command -v "$CLANG" >/dev/null 2>&1; then
      echo "CLANG='$CLANG' does not resolve to an executable compiler" >&2
      return 1
    fi
    local explicit_path
    explicit_path="$(command -v "$CLANG")"
    local explicit_version
    if ! explicit_version="$(warder_clang_version "$explicit_path")"; then
      if [[ "$explicit_path" == *swift* || "$explicit_path" == *swiftly* ]]; then
        echo "CLANG='$CLANG' appears to be the Swift toolchain Clang wrapper and failed --version; set CLANG=/usr/bin/clang for Warder's eBPF object build" >&2
        return 1
      fi
      echo "CLANG='$CLANG' failed to run --version; set CLANG=/usr/bin/clang or install a working Clang with BPF target support" >&2
      return 1
    fi
    if warder_is_swift_clang "$explicit_version"; then
      echo "CLANG='$CLANG' appears to be the Swift toolchain Clang wrapper; set CLANG=/usr/bin/clang for Warder's eBPF object build" >&2
      return 1
    fi
    printf '%s\n' "$explicit_path"
    return 0
  fi

  local candidates
  if [[ -n "${WARDER_BPF_CLANG_CANDIDATES:-}" ]]; then
    # shellcheck disable=SC2206
    candidates=(${WARDER_BPF_CLANG_CANDIDATES})
  else
    candidates=(/usr/bin/clang clang clang-20 clang-19 clang-18 clang-17 clang-16)
  fi

  local rejected_swift=""
  local candidate path version
  for candidate in "${candidates[@]}"; do
    if ! command -v "$candidate" >/dev/null 2>&1; then
      continue
    fi
    path="$(command -v "$candidate")"
    if ! version="$(warder_clang_version "$path")"; then
      if [[ "$path" == *swift* || "$path" == *swiftly* ]]; then
        rejected_swift="$path"
      fi
      continue
    fi
    if warder_is_swift_clang "$version"; then
      rejected_swift="$path"
      continue
    fi
    printf '%s\n' "$path"
    return 0
  done

  if [[ -n "$rejected_swift" ]]; then
    echo "only a Swift toolchain Clang wrapper was found at '$rejected_swift'; install system clang or set CLANG=/usr/bin/clang" >&2
  else
    echo "clang is required to build Warder's eBPF journal objects; install clang or set CLANG=/usr/bin/clang" >&2
  fi
  return 1
}
