# Release checklist

A source preview is not production security assurance. Releases in the
`0.1.0-alpha.*` series are explicitly experimental. Do not describe them as
independently audited, free of vulnerabilities, or a replacement for normal
SSH host-key verification and recovery access.

## Required for an experimental release

- No unresolved known CRITICAL/HIGH finding in the Core release scope;
  security fixes include regression evidence in [FINDINGS.md](FINDINGS.md).
- F-42: the attest job binds each downloaded artifact to the job that
  uploaded it (artifact ID, zip digest, archive SHA-256) and checks zip
  entries before extracting. Hosted evidence will come from the release
  rehearsal's `verify` job on the pull request, which runs attest's checks
  unmodified on the rehearsal's artifacts; it must pass on the candidate.
  `bash scripts/test-attest-inputs.sh` (needs GNU find; `gfind` on macOS)
  must pass too. F-42 stays a next-tag blocker: for the first tag after the
  fix, check in the release run's attest log that the binding step passed
  and that its three downloads were by ID, before publishing; until one
  release run shows this, a green attest job is not evidence of archive
  origin.
- A full re-run of a release run likely fails the binding on duplicate
  artifact names (fails closed, R-2). Re-run only the attest job (not yet
  tried on a hosted run), or push a new tag.
- On the exact candidate: format, clippy with warnings denied, debug and
  release tests with `SIGSIEVE_REQUIRE_SSHD=1`, and a release build pass.
- Hosted CI passes on macOS and Linux, including real sshd tests, umask 0002,
  peer-uid rejection, corpus mutation, dependency advisories and license checks.
  A run on an earlier commit is not acceptance evidence.
- Scan the publication snapshot for credentials, private keys, personal
  infrastructure references, build outputs and unintended author metadata.
  The CI `secret-scan` job (pinned gitleaks, history reachable from HEAD plus
  the tree) is defense in depth next to GitHub secret scanning and push
  protection. It does not replace that review.
- The MIT license, third-party notices, protocol references, supported
  platforms and untested integrations are accurate in the published snapshot.
- GitHub private vulnerability reporting is enabled and `SECURITY.md` links
  to the working reporting channel.
- The release tag exactly matches `Cargo.toml`; the release workflow requires
  full CI before building and keeps OIDC attestation separate from compilation.
- Download the actual release archives, check their SHA256 sums and GitHub
  provenance, inspect license notices and execute at least the native binary.
- Open the packaged README and CHANGELOG: repository links must point to
  the exact source commit on GitHub. These online guides require internet
  access; the executable and bundled license notices remain local files.
- Publish release notes with the exact commit, CI links, supported platforms,
  checks performed and remaining limitations; mark alpha releases as pre-release.

## Candidate record: v0.1.0-alpha.3

Runtime code is unchanged from `v0.1.0-alpha.2` (test-only changes under
`src/`). Supported prebuilt targets stay macOS arm64 and Linux x86_64;
Linux arm64 is CI-tested but source-only; Intel macOS and Windows are not
validated. A gate is only ticked from evidence on the exact candidate SHA.

| Gate | Status |
|---|---|
| Version 0.1.0-alpha.3 in `Cargo.toml` and both lockfiles | Done on the release-preparation branch |
| Hosted CI on the exact candidate SHA, including `msrv (Rust 1.88)` | Pending |
| Release rehearsal (`workflow_dispatch`) on the exact candidate SHA, including the OIDC-free `verify` job | Pending |
| Coverage-guided fuzzing, 3,600 s per target, on the exact candidate SHA | Pending |
| Independent (internal, AI-assisted) security review of the release path | Pending; not an external audit |
| F-42: the tag's `attest` job log shows the binding step passed and all three downloads were by ID | Only possible after tagging; blocks publication |
| `scripts/verify-release.sh RUN_ID v0.1.0-alpha.3` on macOS arm64 and the **Verify release** workflow on Linux report `RESULT: PASS`, including SBOM sidecars and attestations | Only possible after tagging; blocks publication |
| README / INSTALL point at the new release only after it is published | Post-publication step |

## Remaining assurance work

These remain explicit limitations of the alpha, not passing tests:

- A professional independent security audit is required before claiming
  production-grade security assurance.
- One owner-assisted Secretive signing and destination-binding check passed
  with a real key and two localhost SSH servers for `v0.1.0-alpha.2`; full
  Touch ID prompt counts, other versions and external services remain
  unverified. Protocol tests alone do not prove those integrations.
- 1Password and physical FIDO keys need separate interoperability testing.
- `v0.1.0-alpha.2` has a recorded four-target 3,600 s-per-target campaign
  on exact release commit `fc7484b` ([TESTING.md](TESTING.md#release-candidate-evidence-2026-10-28)).
  For every future release candidate, rerun coverage-guided fuzzing on its
  exact SHA; a successful campaign is not an audit.
- See [LIMITATIONS.md](LIMITATIONS.md) for availability limits, supported
  host-key types, trust in the local client/configuration, and allowed-key misuse.
- Record external expert findings and three real-user trials using the
  [external validation protocol](EXTERNAL_VALIDATION.md). Preparation and
  internal AI-assisted review do not complete those checks.

## Publication procedure

1. Verify and commit the reviewed Core snapshot. Keep unpublished feature
   branches and their history outside the first public snapshot.
2. Push the reviewed source to the public repository and inspect its exact-SHA CI.
   Run the **Release rehearsal** workflow on that commit: it builds both
   targets as `release.yml` does, checks that packaging is byte-identical
   twice, that the binary embeds no runner paths and the archive contents,
   that the CycloneDX SBOM sidecar is byte-identical when generated twice
   and lists every dependency cargo resolves for the target,
   and smoke-tests the extracted binary with `doctor` against a real
   `ssh-agent`. Its `verify` job runs the attest job's binding and file
   checks (read from `release.yml`) on the rehearsal's artifacts and checks
   the build job names `verify-release.sh` expects. It creates no tag,
   release or attestation.
3. Tag the accepted candidate. `release.yml` gates, builds deterministic
   macOS arm64 and Linux x86_64 archives, writes a CycloneDX SBOM sidecar
   per archive (not inside it), creates checksums, records provenance for
   archives and SBOMs, and adds an SBOM attestation for each archive.
4. Verify the tag's release run with `scripts/verify-release.sh RUN_ID TAG`
   on macOS arm64, and with the **Verify release** workflow (same script,
   GitHub-hosted Ubuntu 24.04) for Linux x86_64. Each checks that the run is
   that tag's successful release build on GitHub-hosted runners, the
   checksums, `gh attestation verify` bound to this repository, `release.yml`,
   the tag and its commit (self-hosted runners denied), the exact archive
   contents and binary type, and smoke-tests the extracted release binary
   with `doctor`. For every tag after `v0.1.0-alpha.2` it also requires both
   SBOMs and verifies their checksums, their provenance and the archives'
   SBOM attestations; a missing SBOM fails. Both must report
   `RESULT: PASS`; `INCOMPLETE` is not a pass.
5. Create a GitHub pre-release and attach only those verified artifacts:
   both archives, both SBOMs and all four `.sha256` files. Link
   [VERIFY_OFFLINE.md](VERIFY_OFFLINE.md) in the release notes.
   Source installation must name the same immutable release tag.

The workflow does not automatically publish a release. Never rewrite an
already public release tag or force-push public history to repair a release;
issue a new version and explain the correction.
