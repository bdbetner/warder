#!/usr/bin/env bash
set -euo pipefail

RELEASE_TAG="${1:?missing release tag}"
ARTIFACT_DIR="${2:-release-artifacts}"
OUTPUT_FILE="${3:-release-notes.md}"

if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  echo "release tag must look like vMAJOR.MINOR.PATCH: $RELEASE_TAG" >&2
  exit 1
fi

if [[ ! -d "$ARTIFACT_DIR" ]]; then
  echo "missing artifact directory: $ARTIFACT_DIR" >&2
  exit 1
fi

if [[ ! -f "$ARTIFACT_DIR/SHA256SUMS" ]]; then
  echo "missing SHA256SUMS in: $ARTIFACT_DIR" >&2
  exit 1
fi

if [[ ! -f "$ARTIFACT_DIR/release-manifest.json" ]]; then
  echo "missing release-manifest.json in: $ARTIFACT_DIR" >&2
  exit 1
fi

commit="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"

{
  printf '# Warder %s\n\n' "$RELEASE_TAG"
  printf 'Alpha Linux release for Warder. This release is intended for Linux package validation and early feedback.\n\n'
  printf '## Artifacts\n\n'
  printf -- '- `warder`: source-build CLI binary\n'
  printf -- '- `warder-desktop`: source-build native GUI binary\n'
  printf -- '- `Warder_*.deb`: Ubuntu/Debian package that installs both CLI and GUI\n'
  printf -- '- `Warder-*.rpm`: RPM package that installs both CLI and GUI\n'
  printf -- '- `Warder_*.AppImage`: portable GUI bundle; use the separate `warder` binary for CLI commands\n'
  printf -- '- `SHA256SUMS`: SHA-256 checksums for all release files, including the manifest\n'
  printf -- '- `release-manifest.json`: machine-readable artifact inventory with target, revision, names, kinds, sizes, and hashes\n\n'
  printf '## Verification\n\n'
  printf '```bash\n'
  printf 'sha256sum --check SHA256SUMS\n'
  printf 'python3 -m json.tool release-manifest.json >/dev/null\n'
  printf 'sudo apt install ./Warder_*.deb\n'
  printf 'sudo dnf install ./Warder-*.rpm\n'
  printf 'chmod +x ./Warder_*.AppImage\n'
  printf 'warder profiles --format json >/dev/null\n'
  printf '```\n\n'
  printf '## Reviewer Path\n\n'
  printf 'Use the reviewer guide for the installed-artifact CLI and GUI walkthrough:\n\n'
  printf 'https://github.com/betnbd/warder/blob/main/docs/reviewer-feedback.md\n\n'
  printf '## Scope\n\n'
  printf -- '- Complete installer targets: Ubuntu/Debian `.deb` and RPM.\n'
  printf -- '- AppImage is a portable GUI bundle paired with the separate CLI binary.\n'
  printf -- '- Package-manager signatures are not included in this alpha release.\n'
  printf -- '- GitHub artifact attestations are available only when the repository supports them.\n'
  printf -- '- `warder init` can write starter TOML or print it to stdout with `--print` for preview and shell redirection.\n'
  printf -- '- Live eBPF file journaling is opt-in and covers common path-based file syscalls, but not already-open file descriptor writes or writable memory maps; live network eBPF collection currently covers TCP `connect(2)` plus UDP `sendto(2)`/`sendmsg(2)`/`sendmmsg(2)` attempts when host privileges allow it, and supervised runs also snapshot connected sockets from procfs for the supervised process tree when readable.\n'
  printf -- '- Network journaling is accountability evidence, not complete socket forensics or network enforcement.\n'
  printf -- '- Warder still reports degraded protection honestly when host kernel support is unavailable or incomplete.\n\n'
  printf 'Commit: `%s`\n' "$commit"
} > "$OUTPUT_FILE"
