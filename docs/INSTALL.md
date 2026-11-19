# Install SigSieve

SigSieve has **not been independently audited**. Read the
[security model](SECURITY_MODEL.md) and [known limitations](LIMITATIONS.md)
before forwarding an SSH agent. Keep ordinary SSH access available.

## Homebrew (macOS Apple Silicon)

```sh
brew install semihbugrasezer/sigsieve/sigsieve
sigsieve --version
```

Use the full name `semihbugrasezer/sigsieve/sigsieve`. According to
Homebrew 7's source (examined at 7.0.15: `trust.rb`, `cmd/install.rb`), a
full-name install then trusts this one formula, not the whole tap, and prints
`Trusted formula semihbugrasezer/sigsieve/sigsieve` only the first time the
formula is trusted. This is not a guarantee for every Homebrew version, and
the message was not captured from a 1.0.0 install log. The full-name install
is the tested install path: recorded for the alpha.4 formula
([alpha.4 evidence](../packaging/homebrew/README.md#test-evidence-for-alpha4-macos-arm64-homebrew-7012-2026-11-03))
and maintainer-reported for 1.0.0
([1.0.0 evidence](../packaging/homebrew/README.md#test-evidence-for-100-published-tap)).
Other paths, such as `brew tap` followed by a short-name install, are not
tested.

Check `sigsieve --version` after installation; the formula can advance
separately from GitHub release assets. Expected: `sigsieve 1.0.0`.

To upgrade, use the full name again, then check the version:

```sh
brew update && brew upgrade semihbugrasezer/sigsieve/sigsieve
sigsieve --version
```

An upgrade of the published tap from `v0.1.0-alpha.4` to `1.0.0` passed
(maintainer-reported; the exact command was not recorded). That a full-name
`brew upgrade` also trusts the formula is based on Homebrew's source
(`cmd/upgrade.rb`), not on a recorded run. See also
[Upgrading from alpha.4](#upgrading-from-alpha4).

Installation and upgrade need neither `sudo` nor changes to your SSH keys.
The formula installs only the binary: no service, configuration file, change
to `~/.ssh`, or change to your agent.
The formula builds from source and does not verify the binary build
provenance described below.
The formula is tested on macOS Apple Silicon only; Homebrew on Linux is not
tested. Uninstall with `brew uninstall sigsieve && brew untap semihbugrasezer/sigsieve`.

## Upgrading from alpha.4

With destination binding, only one signing attempt is permitted per verified
session and key (F-47). A failed or cancelled Touch ID prompt cannot be
retried on the same connection; open a new connection. This applies to
Homebrew and archive installs alike. See the
[CHANGELOG](https://github.com/semihbugrasezer/sigsieve/blob/71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35/CHANGELOG.md).

## Pinned prebuilt archive: v1.0.0

The verified binary below is the stable release
[**v1.0.0**](https://github.com/semihbugrasezer/sigsieve/releases/tag/v1.0.0),
built from immutable commit
`71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35`. Its release files cannot be
changed after publication (GitHub immutable release).
Do not substitute a newer `main` archive or an unverified Actions artifact.

## Supported downloads

| Host | Archive target | Notes |
|---|---|---|
| macOS Apple Silicon (arm64) | `aarch64-apple-darwin` | Native release verification maintainer-reported (see below); no signed/notarized macOS distribution is claimed |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | Built on Ubuntu 24.04, glibc 2.39 baseline; older distributions may need a source build |

Linux arm64 is tested in CI but has no prebuilt archive. Intel macOS and
Windows are not validated. OpenSSH 8.4+ is required; proxy-jump/relay sessions
require 8.7+.

A crates.io package is **not available**.

## Supported platforms

| | Status |
|---|---|
| macOS Apple Silicon (arm64) | Homebrew (source build) or attested prebuilt archive. No minimum macOS version is stated; recorded device tests ran on macOS 27.2 |
| Intel macOS | not validated |
| Linux x86_64 | attested prebuilt archive (glibc 2.39 baseline); older distributions: source build |
| Linux arm64 | source build (tested in CI, no prebuilt archive) |
| Homebrew on Linux | not tested |
| Windows | not validated |
| Rust (source build) | 1.88 or newer |
| OpenSSH client | 8.4+; 8.7+ for ProxyJump and relays |
| Destination binding | restricts the final destination host key only, not usernames or intermediate hops; destination must use an Ed25519 or ECDSA host key; forwarded hops need servers with `publickey-hostbound` (OpenSSH 8.9+); otherwise signing is refused |
| Secretive | recorded for one configuration: Secretive 4.0.0, one P-256 key, macOS 27.2 arm64, OpenSSH 10.5p1, with the alpha.4, rc.1 and 1.0.0 release binaries (1.0.0 maintainer-reported). Other versions, Intel Macs and the Homebrew-built binary are not verified ([records](SECRETIVE_INTEGRATION.md#recorded-real-device-results)) |
| macOS app | preview, source only: macOS 13+, Xcode 26+ ([macos-app/README.md](../macos-app/README.md)) |

Sources: this guide, [LIMITATIONS.md](LIMITATIONS.md) and
[SECRETIVE_INTEGRATION.md](SECRETIVE_INTEGRATION.md).

## Verify and install a published archive

Prerequisites: `gh` (GitHub CLI, authenticated if your setup requires it),
`tar`, `install`, and `shasum` (macOS) or `sha256sum` (Linux).
Use a recent GitHub CLI with `gh attestation verify` support for
`--signer-workflow`, `--source-ref`, `--source-digest`, and
`--deny-self-hosted-runners`. If a flag is unavailable, upgrade `gh`
rather than skipping provenance verification.

Run this in your terminal. It downloads only the matching release archive and
checksum to a temporary directory, **verifies the downloaded checksum and a
separately pinned SHA-256 digest as well as provenance before running the
binary**, and installs to `~/.local/bin` (not a system directory).

```sh
(
  set -eu
  repo=semihbugrasezer/sigsieve
  tag=v1.0.0
  commit=71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)
      target=aarch64-apple-darwin
      expected_sha=50fb2a0f1026e820ac369dbf8ddce48f8c0b3622a7dd4938879c4b725eec1142 ;;
    Linux/x86_64)
      target=x86_64-unknown-linux-gnu
      expected_sha=998b6a3e412468f065645a84d94c693adb4fb24eb08c36702ee81b9883f9da26 ;;
    *) echo "No verified binary for this OS/architecture; build from source." >&2; exit 1 ;;
  esac
  name="sigsieve-$tag-$target"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  cd "$work"
  gh release download "$tag" -R "$repo" \
    -p "$name.tar.gz" -p "$name.tar.gz.sha256"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$name.tar.gz.sha256"
    printf '%s  %s\n' "$expected_sha" "$name.tar.gz" | shasum -a 256 -c -
  else
    sha256sum -c "$name.tar.gz.sha256"
    printf '%s  %s\n' "$expected_sha" "$name.tar.gz" | sha256sum -c -
  fi
  gh attestation verify "$name.tar.gz" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "refs/tags/$tag" \
    --source-digest "$commit" \
    --deny-self-hosted-runners
  tar -tzf "$name.tar.gz"  # optional: inspect archive entries
  tar -xzf "$name.tar.gz"
  "$name/sigsieve" --version
  mkdir -p "$HOME/.local/bin"
  install -m 755 "$name/sigsieve" "$HOME/.local/bin/sigsieve"
  "$HOME/.local/bin/sigsieve" --version
)
```

Expected version: `sigsieve 1.0.0`. Add `~/.local/bin` to your
`PATH` if you want to run `sigsieve` without its full path.

The release archive also contains `LICENSE`, `THIRD_PARTY_LICENSES.txt`,
`README.md`, and `CHANGELOG.md`. The packaged Markdown links are pinned to
its source revision. Inspect these files before using the program.
macOS code signing or notarization is **not** claimed. If macOS blocks
execution, do not blindly disable Gatekeeper; use a source build or ask for help.

The published `v1.0.0` archives' and SBOMs' SHA-256 values are:

```text
50fb2a0f1026e820ac369dbf8ddce48f8c0b3622a7dd4938879c4b725eec1142  sigsieve-v1.0.0-aarch64-apple-darwin.tar.gz
f3944ee6019d8c8f55b791adf2d078088219a06d8250133dfa13301fff3d3d34  sigsieve-v1.0.0-aarch64-apple-darwin.cdx.json
998b6a3e412468f065645a84d94c693adb4fb24eb08c36702ee81b9883f9da26  sigsieve-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
bd90dde5f8a4b3428a51e393604e9babce04f2aac0897e9fd3545b21cbaae356  sigsieve-v1.0.0-x86_64-unknown-linux-gnu.cdx.json
```

Release evidence for `v1.0.0`: the
[release build](https://github.com/semihbugrasezer/sigsieve/actions/runs/42286504497)
(provenance and SBOM attestations) and the
[Linux x86_64 verification](https://github.com/semihbugrasezer/sigsieve/actions/runs/42291132708)
passed; the native macOS arm64 verification with `scripts/verify-release.sh`
is maintainer-reported. The full list is in the
[v1.0.0 release notes](https://github.com/semihbugrasezer/sigsieve/releases/tag/v1.0.0).
Earlier releases' evidence is in their release notes
([alpha.4](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.4),
[alpha.3](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.3),
[alpha.2](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.2)).

The hardcoded digest prevents accepting an archive and checksum that have both
changed since this guide was reviewed. Checksums alone do not prove build
origin. The provenance check
binds the archive to this repository's `release.yml`, immutable tag ref and
source digest, while denying self-hosted runners. See the
[release verification procedure](RELEASE_CHECKLIST.md).

Each `v1.0.0` archive has a CycloneDX SBOM sidecar
(`$name.cdx.json` and `.sha256`) with its own build provenance, and an SBOM
attestation for the archive. To verify those, or to verify on a machine
without network access by using downloaded attestation bundles, see
[VERIFY_OFFLINE.md](VERIFY_OFFLINE.md). The earlier `v0.1.0-alpha.2`
release has no SBOM, because it was published before SBOM sidecars existed.

## Install the tagged version from source

Use this path for Linux arm64, older glibc distributions, or to avoid
prebuilt downloads. Requires a working Rust toolchain (Rust 1.88 or newer;
the checkout pins 1.99.1) and OpenSSH. This installs **the release tag**, not the newer
`main` branch. It stops before building if the checked-out commit is not the
release commit:

```sh
(
  set -eu
  git clone https://github.com/semihbugrasezer/sigsieve.git
  cd sigsieve
  git checkout v1.0.0
  test "$(git rev-parse HEAD)" = 71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35
  cargo install --locked --path .
  "${CARGO_HOME:-$HOME/.cargo}/bin/sigsieve" --version
)
```

If you set `CARGO_INSTALL_ROOT` (or cargo's `install.root`), the binary is
installed under that directory instead; run its `bin/sigsieve --version`.
A source build is local compilation, not verification of the published
binary's provenance.

## First safe check and removal

Start with the README's [quick start](../README.md#quick-start) (OpenSSH
agent or Secretive); it explains what `doctor` and `connect --dry-run` do and
do not do. Verify the SSH destination's host key through a trusted channel
before a real connection.

SigSieve does not edit SSH configuration or your upstream agent. To remove a
prebuilt installation, stop any SigSieve sessions and delete only
`$HOME/.local/bin/sigsieve`; for a Cargo installation use
`cargo uninstall sigsieve`; for Homebrew see [above](#homebrew-macos-apple-silicon). See [cleanup and recovery](USAGE.md#uninstall-and-recovery).
