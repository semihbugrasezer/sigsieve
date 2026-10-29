# Verify a release offline

SigSieve is experimental, unaudited software. These checks show that an
archive was built by this repository's `release.yml` for a given tag and
commit on a GitHub-hosted runner. They do not show that the code is secure.

Verification has two phases. On a machine with internet access you download
the artifacts, their attestation bundles and a Sigstore trusted root. Then,
on any machine, you verify all of it without network access. The commands
below use the flags of `gh attestation` as shown by `gh attestation verify
--help` in GitHub CLI 2.103. If your `gh` lacks a flag, upgrade it; do not
drop the flag.

## What a release contains

For each target (`aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`):

| File | Purpose |
|---|---|
| `sigsieve-TAG-TARGET.tar.gz` | The archive (deterministic; byte-identical to the release rehearsal). |
| `sigsieve-TAG-TARGET.tar.gz.sha256` | Its SHA-256 checksum. |
| `sigsieve-TAG-TARGET.cdx.json` | CycloneDX 1.5 JSON SBOM of the target's resolved Cargo dependencies. It is a sidecar file, not inside the archive. |
| `sigsieve-TAG-TARGET.cdx.json.sha256` | The SBOM's SHA-256 checksum. |

The release workflow records three attestations per target in GitHub and the
public Sigstore transparency log:

- build provenance (`https://slsa.dev/provenance/v1`) for the archive;
- build provenance for the SBOM file;
- an SBOM attestation (`https://cyclonedx.org/bom`) whose subject is the
  archive and whose predicate is that target's SBOM.

The SBOM file is tied to the release by its own build provenance. The
checks below confirm that a CycloneDX attestation exists for the archive;
they do not compare that attestation's predicate with the downloaded
`.cdx.json` byte for byte.

`v0.1.0-alpha.1` and `v0.1.0-alpha.2` were released before SBOMs existed.
They have only the archive, its checksum and its build provenance. For those
releases, skip every SBOM step below. A missing SBOM means "not present"; it
is not a passed check.

## 1. Online: download everything

```sh
repo=semihbugrasezer/sigsieve
tag=vX.Y.Z                       # the release tag you are verifying
target=x86_64-unknown-linux-gnu  # or aarch64-apple-darwin
name="sigsieve-$tag-$target"

gh release download "$tag" -R "$repo" \
  -p "$name.tar.gz" -p "$name.tar.gz.sha256" \
  -p "$name.cdx.json" -p "$name.cdx.json.sha256"

# Attestation bundles. Each file is named after the artifact's digest
# (sha256:<hex>.jsonl) and holds every attestation found for it.
gh attestation download "$name.tar.gz" --repo "$repo"
gh attestation download "$name.cdx.json" --repo "$repo"

# Sigstore trusted root (public-good and GitHub instances).
gh attestation trusted-root > trusted_root.jsonl

# Record the tag's commit now; you need it offline.
gh api "repos/$repo/commits/$tag" --jq .sha
```

Copy the files to the offline machine. Also take the commit SHA. For
`v0.1.0-alpha.2` it is `fc7484be0371242f517b6628b0f7dcc3a9a12a29`, as
published in [INSTALL.md](INSTALL.md).

## 2. Offline: checksums

```sh
shasum -a 256 -c "$name.tar.gz.sha256"     # Linux: sha256sum -c
shasum -a 256 -c "$name.cdx.json.sha256"
```

A checksum file comes from the same place as the archive, so a matching
checksum proves only that the download is intact. For alpha.2, also compare
the archive with the pinned digests in [INSTALL.md](INSTALL.md).

## 3. Offline: provenance and SBOM attestation

```sh
commit=<commit SHA from step 1>
a=$(shasum -a 256 "$name.tar.gz" | cut -d' ' -f1)
s=$(shasum -a 256 "$name.cdx.json" | cut -d' ' -f1)
verify() {
  gh attestation verify "$@" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "refs/tags/$tag" --source-digest "$commit" \
    --deny-self-hosted-runners --custom-trusted-root trusted_root.jsonl
}

# Archive: build provenance.
verify "$name.tar.gz" --bundle "sha256:$a.jsonl"
# SBOM file: build provenance (these exact SBOM bytes came from the release run).
verify "$name.cdx.json" --bundle "sha256:$s.jsonl"
# Archive: a CycloneDX SBOM attestation exists for it (predicate not compared with the file).
verify "$name.tar.gz" --bundle "sha256:$a.jsonl" --predicate-type https://cyclonedx.org/bom
```

Every command must exit 0.

Known limit, quoted from `gh attestation verify --help`: when attestations
are loaded with `--bundle`, the command "cannot detect whether the repository
or owner has since been renamed, or whether a different repository or owner
now uses that name". When you are back online, run the same commands without
`--bundle` and `--custom-trusted-root`. `gh` then fetches the attestations
from the GitHub API.

The trusted root expires as Sigstore keys rotate. Download it again shortly
before you verify, from a network you trust.

## Status of these instructions

- The checksum steps and the archive provenance step (with `--bundle` and
  `--custom-trusted-root`, no GitHub credentials and outbound HTTP blocked)
  were run successfully against the published `v0.1.0-alpha.2` macOS
  archive.
- The SBOM steps have not been run against a real release, because no
  release with SBOM attestations exists yet. They will first be exercised by
  the next tagged release; until then, treat them as untested.
- `cosign verify-blob-attestation` may also work with these bundles. It has
  not been tested here, so it is not documented.
