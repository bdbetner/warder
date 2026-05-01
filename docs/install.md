# Install Notes

Warder alpha builds target Linux and ship through GitHub Releases. The release artifacts include:

- `warder`: CLI binary
- `warder-desktop`: native Linux GUI binary
- Ubuntu/Debian `.deb`
- RPM package
- portable GUI AppImage
- `SHA256SUMS`
- `release-manifest.json`

The `.deb` and RPM install both the CLI and GUI. The AppImage is GUI-only, so keep the separate `warder` binary nearby when using the portable artifact folder.

## Install From a GitHub Release

Download a tagged alpha release and verify it:

```bash
gh release download v0.1.0-alpha.10 --repo bdbetner/warder --dir warder-linux-x86_64
cd warder-linux-x86_64
sha256sum --check SHA256SUMS
python3 -m json.tool release-manifest.json >/dev/null
```

If artifact attestations are available for the release, verify them too:

```bash
gh attestation verify warder --repo bdbetner/warder
gh attestation verify warder-desktop --repo bdbetner/warder
gh attestation verify Warder_0.1.0_amd64.deb --repo bdbetner/warder
gh attestation verify Warder-0.1.0-1.x86_64.rpm --repo bdbetner/warder
gh attestation verify Warder_0.1.0_amd64.AppImage --repo bdbetner/warder
```

### Ubuntu/Debian Copy-Paste Flow

```bash
gh release download v0.1.0-alpha.10 --repo bdbetner/warder --dir warder-linux-x86_64
cd warder-linux-x86_64
sha256sum --check SHA256SUMS
python3 -m json.tool release-manifest.json >/dev/null
sudo apt install ./Warder_0.1.0_amd64.deb
warder profiles --format json >/dev/null
warder-desktop
```

### RPM Copy-Paste Flow

```bash
gh release download v0.1.0-alpha.10 --repo bdbetner/warder --dir warder-linux-x86_64
cd warder-linux-x86_64
sha256sum --check SHA256SUMS
python3 -m json.tool release-manifest.json >/dev/null
sudo dnf install ./Warder-0.1.0-1.x86_64.rpm
warder profiles --format json >/dev/null
warder-desktop
```

### AppImage Copy-Paste Flow

```bash
gh release download v0.1.0-alpha.10 --repo bdbetner/warder --dir warder-linux-x86_64
cd warder-linux-x86_64
sha256sum --check SHA256SUMS
python3 -m json.tool release-manifest.json >/dev/null
chmod +x ./Warder_0.1.0_amd64.AppImage
./Warder_0.1.0_amd64.AppImage
```

Remove the package on Ubuntu/Debian:

```bash
sudo apt remove warder
```

Package-manager signatures are not included in current alpha releases. The current trust model is documented in [Release Trust Model](release-trust.md): verify checksums, inspect the manifest, and verify GitHub artifact attestations when they exist.

## Build From Source

Install the desktop build prerequisites on Ubuntu/Debian:

```bash
sudo apt-get install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  patchelf \
  fakeroot \
  rpm
```

Build the CLI:

```bash
cargo build --release -p warder-cli --bin warder
```

Build the desktop app:

```bash
cd apps/desktop
npm ci
npm run build
npm test
npm run tauri -- build --bundles deb,rpm,appimage --ci
```

Collect and verify release artifacts:

```bash
cd ../..
scripts/collect-release-artifacts.sh --deb-dir target/release/bundle/deb --rpm-dir target/release/bundle/rpm --appimage-dir target/release/bundle/appimage
(cd release-artifacts && sha256sum --check SHA256SUMS && python3 -m json.tool release-manifest.json >/dev/null)
scripts/deb-artifact-smoke.sh
scripts/deb-install-smoke.sh
scripts/rpm-artifact-smoke.sh
scripts/appimage-artifact-smoke.sh
```

Expected output paths:

```text
target/release/warder
target/release/warder-desktop
target/release/bundle/deb/Warder_0.1.0_amd64.deb
target/release/bundle/rpm/Warder-0.1.0-1.x86_64.rpm
target/release/bundle/appimage/Warder_0.1.0_amd64.AppImage
release-artifacts/SHA256SUMS
release-artifacts/release-manifest.json
```

## Other Linux Desktops

Package names vary by distro. Install equivalents for:

- WebKitGTK 4.1 development headers
- GTK 3 development headers
- Ayatana AppIndicator development headers
- librsvg development headers
- `patchelf`
- Node 22 or newer
- stable Rust

Treat non-Ubuntu package names as unverified until Warder adds distro-specific CI or packaging.
