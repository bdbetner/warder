# Release Trust Model

Warder alpha releases use a GitHub Release artifact folder as the distribution
boundary. The current trust model is checksums, manifest metadata, package
content smoke checks, and GitHub artifact attestations when available.

Package-manager signatures are not included in current alpha releases.

Treat every release as an alpha review build until the installed-artifact demo in [Release Readiness](release-readiness.md) passes on a clean Linux machine.

## What To Verify

Before installing a release asset:

```bash
sha256sum --check SHA256SUMS
python3 -m json.tool release-manifest.json >/dev/null
```

`SHA256SUMS` covers every release file, including `release-manifest.json`. The
manifest records the release target, source revision, artifact names, artifact
kinds, sizes, and SHA-256 values.

When artifact attestations are available, verify the downloaded files with the
GitHub CLI:

```bash
gh attestation verify warder --repo betnbd/warder
gh attestation verify warder-desktop --repo betnbd/warder
gh attestation verify Warder_0.1.0_amd64.deb --repo betnbd/warder
gh attestation verify Warder-0.1.0-1.x86_64.rpm --repo betnbd/warder
gh attestation verify Warder_0.1.0_amd64.AppImage --repo betnbd/warder
```

Attestations are generated only when the release workflow has GitHub artifact
attestations enabled. Some alpha builds may only have checksum, manifest, and
package-smoke verification.

## Full Verification Flow

Use this flow before installing a downloaded alpha release:

```bash
gh release download v0.1.0-alpha.11 --repo betnbd/warder --dir warder-linux-x86_64
cd warder-linux-x86_64
sha256sum --check SHA256SUMS
python3 -m json.tool release-manifest.json >/dev/null
gh attestation verify warder --repo betnbd/warder
gh attestation verify warder-desktop --repo betnbd/warder
gh attestation verify Warder_0.1.0_amd64.deb --repo betnbd/warder
gh attestation verify Warder-0.1.0-1.x86_64.rpm --repo betnbd/warder
gh attestation verify Warder_0.1.0_amd64.AppImage --repo betnbd/warder
```

Then install the package for your system:

```bash
sudo apt install ./Warder_0.1.0_amd64.deb
```

or:

```bash
sudo dnf install ./Warder-0.1.0-1.x86_64.rpm
```

or run the portable GUI bundle:

```bash
chmod +x ./Warder_0.1.0_amd64.AppImage
./Warder_0.1.0_amd64.AppImage
```

## Package Signing Policy

Do not add long-lived package signing keys until key custody, rotation, and user verification docs are decided.

Raw `.deb` or RPM signatures without a stable key distribution story would make
the release look more mature than it is. For the current alpha channel, keep the
release process keyless and repeatable:

- CI and the release workflow build the CLI, GUI, `.deb`, RPM, and AppImage.
- CI and the release workflow verify checksum metadata and package contents.
- Public repositories produce keyless GitHub artifact attestations.
- Users verify checksums and attestations when available before installing.

Add package-manager signatures only after the project decides:

- who controls the signing identity;
- how signing keys are stored, rotated, and revoked;
- whether Warder operates Debian/RPM repositories or only GitHub Release files;
- how users are expected to fetch and verify the signing keys.
