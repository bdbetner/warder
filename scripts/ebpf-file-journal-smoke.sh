#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQUIRE_LIVE="${WARDER_REQUIRE_LIVE_EBPF:-0}"

cd "$ROOT_DIR"

ebpf_object="$(scripts/build-ebpf-file-journal.sh)"
echo "built eBPF file journal object: $ebpf_object"

cargo test -p warder-journal raw_ebpf_reader
cargo check -p warder-cli --features live-ebpf

doctor_output="$(cargo run -q -p warder-cli -- doctor)"
printf '%s\n' "$doctor_output"

if grep -Fq "live eBPF journals unavailable:" <<<"$doctor_output"; then
  if [[ "$REQUIRE_LIVE" == "1" ]]; then
    echo "live eBPF file-journal smoke requires eBPF, but doctor reported degraded coverage" >&2
    exit 1
  fi
  echo "live eBPF file-journal smoke: degraded host blocker reported"
  exit 0
fi

if [[ "$REQUIRE_LIVE" != "1" ]]; then
  echo "live eBPF file-journal smoke: object builds; set WARDER_REQUIRE_LIVE_EBPF=1 on a privileged host to require a real event"
  exit 0
fi

smoke_root="${WARDER_EBPF_SMOKE_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/warder-ebpf-smoke.XXXXXX")}"
protected_root="${smoke_root}/protected"
config_path="${smoke_root}/warder-ebpf-smoke.toml"
db_path="${smoke_root}/warder-ebpf-smoke.sqlite3"
mkdir -p "$protected_root"
printf 'seed\n' >"${protected_root}/input.txt"

cat >"$config_path" <<EOF_CONFIG
[enforcement]
landlock = "disabled"
cgroups = "disabled"

[network]
journal = true

[[zones]]
id = "ebpf-smoke"
name = "eBPF Smoke"
description = "Throwaway protected directory for live eBPF file-journal validation."
paths = ["${protected_root}"]
write_policy = "deny"
snapshot = "disabled"

[[agents]]
id = "local-shell"
label = "Local Shell"
command = "sh"
profile = "local-script"
EOF_CONFIG

run_output="$(
  WARDER_EBPF_FILE_OBJECT="${WARDER_EBPF_FILE_OBJECT:-$ebpf_object}" \
    cargo run -q -p warder-cli --features live-ebpf -- \
    run --config "$config_path" --db "$db_path" --agent local-shell --launch --accept-degraded -- \
    sh -c "cat '${protected_root}/input.txt' >/dev/null; printf live >> '${protected_root}/output.txt'"
)"
printf '%s\n' "$run_output"

session_id="$(awk '/^session: / { print $2; exit }' <<<"$run_output")"
if [[ -z "$session_id" ]]; then
  echo "live eBPF file-journal smoke: unable to find session id in run output" >&2
  exit 1
fi

journal_output="$(
  cargo run -q -p warder-cli -- journal --db "$db_path" --file --session "$session_id"
)"
printf '%s\n' "$journal_output"

if ! grep -Fq "via eBPF" <<<"$journal_output"; then
  echo "live eBPF file-journal smoke: no persisted eBPF file event was recorded" >&2
  exit 1
fi

if ! grep -Fq "$protected_root" <<<"$journal_output"; then
  echo "live eBPF file-journal smoke: eBPF events did not include the protected smoke root" >&2
  exit 1
fi

if grep -F "zone=unmatched" <<<"$journal_output" | grep -Fq "via eBPF"; then
  echo "live eBPF file-journal smoke: persisted unmatched eBPF noise" >&2
  exit 1
fi

echo "live eBPF file-journal smoke: recorded protected-path event via eBPF"
