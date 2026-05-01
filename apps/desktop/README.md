# Warder Desktop

Warder Desktop is the native Linux GUI for configuring protected zones, launching supervised local agent sessions, and viewing receipts and journals.

The GUI is session-scoped. It configures and launches commands through Warder; it is not an always-on system guard for processes launched elsewhere.

## What It Does

- Creates a Warder config from guided defaults.
- Lets users review protected zones before launch.
- Launches Warder-supervised commands.
- Shows receipts and journal output after a session.
- Keeps degraded host support visible.

## Run Locally

```bash
cd apps/desktop
npm ci
npm run tauri -- dev
```

The first-run setup wizard loads transparent profile templates from the Warder CLI catalog. Applying or reapplying a template only adds missing recommended paths; it does not overwrite protected paths that the user already changed.

## Build Release Artifacts

The complete installer targets are Ubuntu/Debian `.deb` and RPM packages. CI also keeps the source-build CLI and GUI binaries plus a portable GUI AppImage in the same checksummed artifact folder.

Ubuntu/Debian desktop build prerequisites:

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

```bash
cargo build --release -p warder-cli --bin warder
cd apps/desktop
npm ci
npm run build
npm test
npm run tauri -- build --bundles deb,rpm,appimage --ci
cargo check -p warder-desktop
cd ../..
scripts/collect-release-artifacts.sh --deb-dir target/release/bundle/deb --rpm-dir target/release/bundle/rpm --appimage-dir target/release/bundle/appimage
scripts/deb-artifact-smoke.sh
scripts/deb-install-smoke.sh
scripts/rpm-artifact-smoke.sh
scripts/appimage-artifact-smoke.sh
```

The CLI release binary is written to `target/release/warder`, the GUI release binary is written to `target/release/warder-desktop`, and the packages are written under `target/release/bundle/`.

`scripts/collect-release-artifacts.sh` copies all packages alongside the CLI and GUI binaries in `release-artifacts/` and writes `SHA256SUMS`. The `.deb` and RPM packages install both `/usr/bin/warder` and `/usr/bin/warder-desktop`; the AppImage is a portable GUI bundle paired with the separate CLI binary.
