# Release checklist

A source preview is not production security assurance. Releases in the
`0.1.0-alpha.*` series are explicitly experimental. Do not describe them as
independently audited, free of vulnerabilities, or a replacement for normal
SSH host-key verification and recovery access.

## Required for an experimental release

- No unresolved known CRITICAL/HIGH finding in the Core release scope;
  security fixes include regression evidence in [FINDINGS.md](FINDINGS.md).
- On the exact candidate: format, clippy with warnings denied, debug and
  release tests with `SIGSIEVE_REQUIRE_SSHD=1`, and a release build pass.
- Hosted CI passes on macOS and Linux, including real sshd tests, umask 0002,
  peer-uid rejection, corpus mutation, dependency advisories and license checks.
  A run on an earlier commit is not acceptance evidence.
- Scan the publication snapshot for credentials, private keys, personal
  infrastructure references, build outputs and unintended author metadata.
- The MIT license, third-party notices, protocol references, supported
  platforms and untested integrations are accurate in the published snapshot.
- GitHub private vulnerability reporting is enabled and `SECURITY.md` links
  to the working reporting channel.
- The release tag exactly matches `Cargo.toml`; the release workflow requires
  full CI before building and keeps OIDC attestation separate from compilation.
- Download the actual release archives, check their SHA256 sums and GitHub
  provenance, inspect license notices and execute at least the native binary.
- Publish release notes with the exact commit, CI links, supported platforms,
  checks performed and remaining limitations; mark alpha releases as pre-release.

## Remaining assurance work

These remain explicit limitations of the alpha, not passing tests:

- A professional independent security audit is required before claiming
  production-grade security assurance.
- Real Secretive signing, destination binding and user-presence observations
  require an owner-assisted device test; protocol tests do not prove them.
- 1Password and physical FIDO keys need separate interoperability testing.
- Coverage-guided fuzzing requires nightly and cargo-fuzz; the stable corpus
  pass is bounded mutation, not a coverage measurement.
- See [LIMITATIONS.md](LIMITATIONS.md) for availability limits, supported
  host-key types, trust in the local client/configuration, and allowed-key misuse.

## Publication procedure

1. Verify and commit the reviewed Core snapshot. Keep unpublished feature
   branches and their history outside the first public snapshot.
2. Push the reviewed source to the public repository and inspect its exact-SHA CI.
   Run the **Release rehearsal** workflow on that commit: it builds both
   targets as `release.yml` does, checks that packaging is byte-identical
   twice, that the binary embeds no runner paths and the archive contents,
   and smoke-tests the extracted binary with `doctor` against a real
   `ssh-agent`. It creates no tag, release or attestation.
3. Tag the accepted candidate. `release.yml` gates, builds deterministic
   macOS arm64 and Linux x86_64 archives, creates checksums and records provenance.
4. Download artifacts and verify checksums and `gh attestation verify` results.
   Inspect `LICENSE` and `THIRD_PARTY_LICENSES.txt`; smoke-test the native binary.
5. Create a GitHub pre-release and attach only those verified artifacts.
   Source installation must name the same immutable release tag.

The workflow does not automatically publish a release. Never rewrite an
already public release tag or force-push public history to repair a release;
issue a new version and explain the correction.
