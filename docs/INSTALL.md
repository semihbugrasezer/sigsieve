# Install SigSieve v0.1.0-alpha.2

SigSieve is **experimental, unaudited security software**. Read the
[security model](SECURITY_MODEL.md) and [known limitations](LIMITATIONS.md)
before forwarding an SSH agent. Keep ordinary SSH access available.

The first verified binary pre-release is
[**v0.1.0-alpha.2**](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.2),
built from immutable commit
`fc7484be0371242f517b6628b0f7dcc3a9a12a29`.
Do not substitute a newer `main` archive or an unverified Actions artifact.

## Supported downloads

| Host | Archive target | Notes |
|---|---|---|
| macOS Apple Silicon (arm64) | `aarch64-apple-darwin` | Native release verification passed; no signed/notarized macOS distribution is claimed |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | Built on Ubuntu 24.04, glibc 2.39 baseline; older distributions may need a source build |

Linux arm64 is tested in CI but has no prebuilt archive. Intel macOS and
Windows are not validated. OpenSSH 8.4+ is required; proxy-jump/relay sessions
require 8.7+.

## Verify and install a published archive

Prerequisites: `gh` (GitHub CLI, authenticated if your setup requires it),
`tar`, `install`, and `shasum` (macOS) or `sha256sum` (Linux).
Use a recent GitHub CLI with `gh attestation verify` support for
`--signer-workflow`, `--source-ref`, `--source-digest`, and
`--deny-self-hosted-runners`. If a flag is unavailable, upgrade `gh`
rather than skipping provenance verification.

Run this in your terminal. It downloads only the matching release archive and
checksum to a temporary directory, **verifies checksum and provenance before
running the binary**, and installs to `~/.local/bin` (not a system directory).

```sh
(
  set -eu
  repo=semihbugrasezer/sigsieve
  tag=v0.1.0-alpha.2
  commit=fc7484be0371242f517b6628b0f7dcc3a9a12a29
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) target=aarch64-apple-darwin ;;
    Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
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
  else
    sha256sum -c "$name.tar.gz.sha256"
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
)
"$HOME/.local/bin/sigsieve" --version
```

Expected version: `sigsieve 0.1.0-alpha.2`. Add `~/.local/bin` to your
`PATH` if you want to run `sigsieve` without its full path.

The release archive also contains `LICENSE`, `THIRD_PARTY_LICENSES.txt`,
`README.md`, and `CHANGELOG.md`. The packaged Markdown links are pinned to
its source revision. Inspect these files before using the program.
macOS code signing or notarization is **not** claimed. If macOS blocks
execution, do not blindly disable Gatekeeper; use a source build or ask for help.

The published artifacts' SHA-256 values are:

```text
18ad494d029d9b207074f79778ed49099f8d0114575ad8554d44a9d0ca3c28ec  sigsieve-v0.1.0-alpha.2-aarch64-apple-darwin.tar.gz
b9dbe8f4d771cd2a054a238af5a7e400f99e8ed5a7977457ee77a06ec79b42c9  sigsieve-v0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz
```

Checksum matching alone does not prove build origin. The provenance check
binds the archive to this repository's `release.yml`, immutable tag ref and
source digest, while denying self-hosted runners. See the
[release verification procedure](RELEASE_CHECKLIST.md).

## Install the tagged version from source

Use this path for Linux arm64, older glibc distributions, or to avoid
prebuilt downloads. Requires a working Rust toolchain (the checkout pins
Rust 1.99.1) and OpenSSH. This installs **the release tag**, not the newer
`main` branch:

```sh
git clone https://github.com/semihbugrasezer/sigsieve.git
cd sigsieve
git checkout v0.1.0-alpha.2
test "$(git rev-parse HEAD)" = fc7484be0371242f517b6628b0f7dcc3a9a12a29
cargo install --locked --path .
"$HOME/.cargo/bin/sigsieve" --version
```

A source build is local compilation, not verification of the published
binary's provenance.

## First safe check and removal

Start with [identity filtering and a dry run](../README.md#first-safe-check-with-openssh-linux-or-macos)
or the [Secretive setup](../README.md#first-session-with-secretive-macos).
`doctor` does not request real-key signing; `connect --dry-run` does not
start a remote SSH session. Verify the SSH destination's host key through
a trusted channel before a real connection.

SigSieve does not edit SSH configuration or your upstream agent. To remove a
prebuilt installation, stop any SigSieve sessions and delete only
`$HOME/.local/bin/sigsieve`; for a Cargo installation use
`cargo uninstall sigsieve`. See [cleanup and recovery](USAGE.md#uninstall-and-recovery).
