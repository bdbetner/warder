#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQUIRE_LIVE="${WARDER_REQUIRE_LIVE_EBPF:-0}"

cd "$ROOT_DIR"

ebpf_file_object="$(scripts/build-ebpf-file-journal.sh)"
ebpf_network_object="$(scripts/build-ebpf-network-journal.sh)"
echo "built eBPF file journal object: $ebpf_file_object"
echo "built eBPF network journal object: $ebpf_network_object"

cargo test -p warder-journal ebpf_network
cargo test -p warder-journal live_ebpf_network
cargo check -p warder-cli --features live-ebpf

doctor_output="$(cargo run -q -p warder-cli -- doctor)"
printf '%s\n' "$doctor_output"

if grep -Fq "live eBPF journals unavailable:" <<<"$doctor_output"; then
  if [[ "$REQUIRE_LIVE" == "1" ]]; then
    echo "live eBPF network-journal smoke requires eBPF, but doctor reported degraded coverage" >&2
    exit 1
  fi
  echo "live eBPF network-journal smoke: degraded host blocker reported"
  exit 0
fi

if [[ "$REQUIRE_LIVE" != "1" ]]; then
  echo "live eBPF network-journal smoke: object builds; set WARDER_REQUIRE_LIVE_EBPF=1 on a privileged host to require a real event"
  exit 0
fi

smoke_root="${WARDER_EBPF_NETWORK_SMOKE_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/warder-ebpf-network-smoke.XXXXXX")}"
protected_root="${smoke_root}/protected"
config_path="${smoke_root}/warder-ebpf-network-smoke.toml"
db_path="${smoke_root}/warder-ebpf-network-smoke.sqlite3"
mkdir -p "$protected_root"

cat >"$config_path" <<EOF_CONFIG
[enforcement]
landlock = "disabled"
cgroups = "disabled"

[network]
journal = true

[[zones]]
id = "ebpf-network-smoke"
name = "eBPF Network Smoke"
description = "Throwaway protected directory for live eBPF network-journal validation."
paths = ["${protected_root}"]
write_policy = "deny"
snapshot = "disabled"

[[agents]]
id = "local-python"
label = "Local Python"
command = "python3"
profile = "local-script"
EOF_CONFIG

sendmmsg_source="${smoke_root}/sendmmsg-probe.c"
sendmmsg_probe="${smoke_root}/sendmmsg-probe"
probe_script="${smoke_root}/network-probe.sh"

cat >"$sendmmsg_source" <<'EOF_C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(11);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        close(fd);
        return 1;
    }

    char payload[] = "warder-sendmmsg";
    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = payload;
    iov.iov_len = sizeof(payload) - 1;

    struct mmsghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_hdr.msg_name = &addr;
    msg.msg_hdr.msg_namelen = sizeof(addr);
    msg.msg_hdr.msg_iov = &iov;
    msg.msg_hdr.msg_iovlen = 1;

    int sent = sendmmsg(fd, &msg, 1, 0);
    close(fd);
    return sent == 1 ? 0 : 1;
}
EOF_C

cc "$sendmmsg_source" -o "$sendmmsg_probe"

cat >"$probe_script" <<'EOF_PROBE'
#!/usr/bin/env bash
set -euo pipefail

python3 - <<'EOF_PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.05)
try:
    sock.connect(("127.0.0.1", 9))
except OSError:
    pass
finally:
    sock.close()

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    udp.sendto(b"warder-sendto", ("127.0.0.1", 9))
    udp.sendmsg([b"warder-sendmsg"], [], 0, ("127.0.0.1", 10))
finally:
    udp.close()
EOF_PY

"__SENDMMSG_PROBE__"
EOF_PROBE
sed -i "s#__SENDMMSG_PROBE__#${sendmmsg_probe}#" "$probe_script"
chmod +x "$probe_script"

run_output="$(
  WARDER_EBPF_FILE_OBJECT="${WARDER_EBPF_FILE_OBJECT:-$ebpf_file_object}" \
  WARDER_EBPF_NETWORK_OBJECT="${WARDER_EBPF_NETWORK_OBJECT:-$ebpf_network_object}" \
    cargo run -q -p warder-cli --features live-ebpf -- \
    run --config "$config_path" --db "$db_path" --agent local-python --launch --accept-degraded -- \
    bash "$probe_script"
)"
printf '%s\n' "$run_output"

session_id="$(awk '/^session: / { print $2; exit }' <<<"$run_output")"
if [[ -z "$session_id" ]]; then
  echo "live eBPF network-journal smoke: unable to find session id in run output" >&2
  exit 1
fi

journal_output="$(
  cargo run -q -p warder-cli -- journal --db "$db_path" --network --session "$session_id"
)"
printf '%s\n' "$journal_output"

if ! grep -Fq "via eBPF" <<<"$journal_output"; then
  echo "live eBPF network-journal smoke: no persisted eBPF network event was recorded" >&2
  exit 1
fi

if ! grep -Eq "ipv4:7f000001|127\\.0\\.0\\.1" <<<"$journal_output"; then
  echo "live eBPF network-journal smoke: network event did not include the loopback destination" >&2
  exit 1
fi

if ! grep -Fq "tcp observed via eBPF" <<<"$journal_output"; then
  echo "live eBPF network-journal smoke: no TCP connect event was recorded" >&2
  exit 1
fi

if ! grep -Fq "udp observed via eBPF" <<<"$journal_output"; then
  echo "live eBPF network-journal smoke: no UDP send event was recorded" >&2
  exit 1
fi

if ! grep -Eq "ipv4:7f000001:10|127\\.0\\.0\\.1:10" <<<"$journal_output"; then
  echo "live eBPF network-journal smoke: no UDP sendmsg event was recorded" >&2
  exit 1
fi

if ! grep -Eq "ipv4:7f000001:11|127\\.0\\.0\\.1:11" <<<"$journal_output"; then
  echo "live eBPF network-journal smoke: no UDP sendmmsg event was recorded" >&2
  exit 1
fi

echo "live eBPF network-journal smoke: recorded TCP connect plus UDP sendto/sendmsg/sendmmsg events via eBPF"
