#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$ROOT_DIR/target/release"
OUTPUT_DIR="$ROOT_DIR/release-artifacts"
DEB_DIR=""
APPIMAGE_DIR=""
RPM_DIR=""
TARGET_LABEL="linux-x86_64"
VERSION=""
GIT_COMMIT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-dir)
      TARGET_DIR="${2:?missing value for --target-dir}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing value for --output-dir}"
      shift 2
      ;;
    --deb-dir)
      DEB_DIR="${2:?missing value for --deb-dir}"
      shift 2
      ;;
    --appimage-dir)
      APPIMAGE_DIR="${2:?missing value for --appimage-dir}"
      shift 2
      ;;
    --rpm-dir)
      RPM_DIR="${2:?missing value for --rpm-dir}"
      shift 2
      ;;
    --target-label)
      TARGET_LABEL="${2:?missing value for --target-label}"
      shift 2
      ;;
    --version)
      VERSION="${2:?missing value for --version}"
      shift 2
      ;;
    --commit)
      GIT_COMMIT="${2:?missing value for --commit}"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
usage: scripts/collect-release-artifacts.sh [--target-dir PATH] [--output-dir PATH] [--deb-dir PATH] [--appimage-dir PATH] [--rpm-dir PATH] [--target-label LABEL] [--version VERSION] [--commit SHA]

Copies Warder release binaries, plus optional Linux bundles, into one artifact
directory and writes SHA256SUMS plus release-manifest.json.
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

required_binaries=(warder warder-desktop)
checksum_files=("${required_binaries[@]}")

if [[ -z "$VERSION" ]]; then
  if VERSION="$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null)"; then
    :
  else
    VERSION="unknown"
  fi
fi

if [[ -z "$GIT_COMMIT" ]]; then
  if GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null)"; then
    :
  else
    GIT_COMMIT="unknown"
  fi
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

for binary in "${required_binaries[@]}"; do
  source_path="$TARGET_DIR/$binary"
  if [[ ! -x "$source_path" ]]; then
    echo "missing executable release binary: $source_path" >&2
    exit 1
  fi
  cp "$source_path" "$OUTPUT_DIR/$binary"
done

if [[ -n "$DEB_DIR" ]]; then
  if [[ ! -d "$DEB_DIR" ]]; then
    echo "missing .deb bundle directory: $DEB_DIR" >&2
    exit 1
  fi

  shopt -s nullglob
  deb_packages=("$DEB_DIR"/*.deb)
  shopt -u nullglob

  if [[ ${#deb_packages[@]} -eq 0 ]]; then
    echo "no .deb packages found in: $DEB_DIR" >&2
    exit 1
  fi

  for package in "${deb_packages[@]}"; do
    package_name="$(basename "$package")"
    cp "$package" "$OUTPUT_DIR/$package_name"
    checksum_files+=("$package_name")
  done
fi

if [[ -n "$APPIMAGE_DIR" ]]; then
  if [[ ! -d "$APPIMAGE_DIR" ]]; then
    echo "missing AppImage bundle directory: $APPIMAGE_DIR" >&2
    exit 1
  fi

  shopt -s nullglob
  appimages=("$APPIMAGE_DIR"/*.AppImage)
  shopt -u nullglob

  if [[ ${#appimages[@]} -eq 0 ]]; then
    echo "no AppImage bundles found in: $APPIMAGE_DIR" >&2
    exit 1
  fi

  for package in "${appimages[@]}"; do
    package_name="$(basename "$package")"
    cp "$package" "$OUTPUT_DIR/$package_name"
    chmod +x "$OUTPUT_DIR/$package_name"
    checksum_files+=("$package_name")
  done
fi

if [[ -n "$RPM_DIR" ]]; then
  if [[ ! -d "$RPM_DIR" ]]; then
    echo "missing RPM bundle directory: $RPM_DIR" >&2
    exit 1
  fi

  shopt -s nullglob
  rpm_packages=("$RPM_DIR"/*.rpm)
  shopt -u nullglob

  if [[ ${#rpm_packages[@]} -eq 0 ]]; then
    echo "no RPM packages found in: $RPM_DIR" >&2
    exit 1
  fi

  for package in "${rpm_packages[@]}"; do
    package_name="$(basename "$package")"
    cp "$package" "$OUTPUT_DIR/$package_name"
    checksum_files+=("$package_name")
  done
fi

artifact_kind() {
  case "$1" in
    warder)
      printf 'cli'
      ;;
    warder-desktop)
      printf 'gui'
      ;;
    *.deb)
      printf 'deb'
      ;;
    *.AppImage)
      printf 'appimage'
      ;;
    *.rpm)
      printf 'rpm'
      ;;
    *)
      printf 'artifact'
      ;;
  esac
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "product": "Warder",\n'
  printf '  "target": "%s",\n' "$(json_escape "$TARGET_LABEL")"
  printf '  "version": "%s",\n' "$(json_escape "$VERSION")"
  printf '  "git_commit": "%s",\n' "$(json_escape "$GIT_COMMIT")"
  printf '  "generated_by": "scripts/collect-release-artifacts.sh",\n'
  printf '  "artifacts": [\n'
  for index in "${!checksum_files[@]}"; do
    artifact="${checksum_files[$index]}"
    artifact_path="$OUTPUT_DIR/$artifact"
    checksum="$(sha256sum "$artifact_path" | awk '{print $1}')"
    size_bytes="$(wc -c < "$artifact_path" | tr -d ' ')"
    comma=","
    if [[ "$index" -eq $((${#checksum_files[@]} - 1)) ]]; then
      comma=""
    fi
    printf '    {"name": "%s", "kind": "%s", "sha256": "%s", "size_bytes": %s}%s\n' \
      "$(json_escape "$artifact")" \
      "$(json_escape "$(artifact_kind "$artifact")")" \
      "$checksum" \
      "$size_bytes" \
      "$comma"
  done
  printf '  ]\n'
  printf '}\n'
} > "$OUTPUT_DIR/release-manifest.json"

checksum_files+=(release-manifest.json)

(
  cd "$OUTPUT_DIR"
  sha256sum "${checksum_files[@]}" > SHA256SUMS
)
