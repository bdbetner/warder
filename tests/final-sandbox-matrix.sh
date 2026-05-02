#!/usr/bin/env bash
set -euo pipefail

WARDER_BIN="${WARDER_BIN:-target/debug/warder}"
if [[ ! -x "$WARDER_BIN" ]]; then
  echo "missing warder binary at $WARDER_BIN; run: cargo build -p warder-cli --bin warder" >&2
  exit 2
fi

if "$WARDER_BIN" doctor 2>/dev/null | grep -q "Landlock unavailable"; then
  echo "final sandbox matrix: skipped because this host cannot apply Landlock"
  exit 0
fi

root="$(mktemp -d "${TMPDIR:-/tmp}/warder-final-sandbox.XXXXXX")"
trap 'rm -rf "$root"' EXIT

protected="$root/protected"
runtime="$root/runtime"
cgroup_root="$root/cgroup"
mount_point="$runtime/mount"
key="$root/receipt.key"
db="$root/warder.sqlite3"
config="$root/warder.toml"
script="$runtime/agent.sh"
mkdir -p "$protected" "$runtime" "$cgroup_root" "$mount_point"
printf '0\n' >"$cgroup_root/cgroup.procs"
printf 'secret\n' >"$protected/secret.txt"

"$WARDER_BIN" receipt-key init --output "$key" --force >/dev/null
chmod 600 "$key"

cat >"$config" <<EOF
[enforcement]
landlock = "required"
cgroups = "best-effort"
writable-roots = ["$runtime"]
readable-roots = ["/bin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "$runtime"]

[network]
journal = false

[[zones]]
id = "protected"
name = "Protected"
paths = ["$protected"]
write-policy = "deny"
read-deny = true
snapshot = "disabled"

[[agents]]
id = "local"
label = "Local"
command = "sh"
EOF

cat >"$script" <<'EOF'
#!/usr/bin/env sh
set -eu

if cat "$WARDER_PROTECTED/secret.txt" >/dev/null 2>"$WARDER_RUNTIME/read.err"; then
  echo "read-deny did not block protected read" >&2
  exit 40
fi

if unshare -m true >/dev/null 2>"$WARDER_RUNTIME/unshare.err"; then
  echo "seccomp did not block unshare" >&2
  exit 41
fi

if mount -t tmpfs tmpfs "$WARDER_MOUNT" >/dev/null 2>"$WARDER_RUNTIME/mount.err"; then
  echo "seccomp did not block mount" >&2
  exit 42
fi
EOF
chmod 700 "$script"

set +e
WARDER_RUNTIME="$runtime" WARDER_PROTECTED="$protected" WARDER_MOUNT="$mount_point" \
  "$WARDER_BIN" run \
    --config "$config" \
    --db "$db" \
    --cgroup-root "$cgroup_root" \
    --launch \
    --require-enforcement \
    --receipt-key "$key" \
    --accept-degraded \
    --agent local \
    -- sh "$script"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  echo "strict read-deny sandbox launch failed on this host; inspect output above" >&2
  exit "$status"
fi

session_cgroup="$(find "$cgroup_root/warder" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [[ -z "$session_cgroup" || ! -f "$session_cgroup/cgroup.procs" ]]; then
  echo "session cgroup was not prepared before launch" >&2
  exit 43
fi
if ! grep -qx '0' "$session_cgroup/cgroup.procs"; then
  echo "session cgroup did not record pre-exec current-process tag" >&2
  exit 44
fi

"$WARDER_BIN" verify-receipts --db "$db" --external-key "$key" >/dev/null

echo "final sandbox matrix: ok"
