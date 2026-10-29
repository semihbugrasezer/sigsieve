# Changelog

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Documentation

- Reconcile Secretive, fuzzing and published-build evidence with the exact
  `v0.1.0-alpha.2` release revision; retain device and prompt-observation limits.
- Keep the installed-binary version check inside the install recipe's failing
  subshell so an older installation cannot mask failed download/verification.
- Add an external expert review and three-user trial protocol with results
  explicitly pending; no executable behaviour changes.
- Prepare sourced review options and unsent expert/volunteer recruitment
  drafts; no reviewer, participant or paid engagement is confirmed.
- Add a five-minute quickstart with a throwaway agent and synthetic keys,
  a governance document, a roadmap execution plan and checklist, and design
  notes for username/path constraints and platform support (proposals only).
- Record the 2026-10-29 internal AI-assisted review of the alpha.2 source
  (no new actionable finding, five INFO observations); not an audit.
- Document offline verification of checksums, provenance and SBOM
  attestations (`docs/VERIFY_OFFLINE.md`).

### Release engineering

- CI runs a pinned, checksum-verified gitleaks 8.30.1 secret scan over the
  history reachable from HEAD and the tree. It is defense in depth next to
  GitHub secret scanning and push protection.
- Release builds write a CycloneDX 1.5 SBOM sidecar per target with pinned
  cargo-cyclonedx 0.5.9. The archives are unchanged. Each SBOM gets build
  provenance, each archive gets a CycloneDX SBOM attestation, and
  `scripts/verify-release.sh` requires and verifies these for future tags.
  `v0.1.0-alpha.2` has no SBOM, and the script reports it as NOT_PRESENT.
  The pull-request jobs (secret scan, rehearsal SBOM) ran on GitHub in
  PR #30; the tag-only release path has not run yet.

### Tests

- Real OpenSSH destination-binding negative matrix: plain `publickey` to an
  allowed destination refused, RSA destination host key refused even when
  allowed, an allowed forwarding hop does not authorize another final
  destination, agent forwarded through two hops, and `git commit -S` refused
  in binding mode (verified in filtering mode). Each was mutation-checked.
- Throwaway `gpg-agent --enable-ssh-support` as upstream: filtering, SSHSIG
  and RSA SHA-2 signing, SHA-1 refusal, mutations, and destination binding
  (skipped without GnuPG).
- Mock-upstream regression: a truncated sign response is never completed.

- Pin that session binds after an authentication bind, including forged
  ones, leave binding state and signing authorization unchanged.

## [0.1.0-alpha.2] - 2026-10-28 (experimental pre-release)

### Fixed

- Packaged README/CHANGELOG links now point to documentation at the build's
  immutable source commit instead of missing paths outside a checkout.
- RSA destination-binding self-checks in `doctor` and `connect` now use a
  valid SHA-2 signing flag. Previously the RSA/SHA-1 policy could reject the
  probe before it exercised binding enforcement, giving false assurance.

### Validation

- Release source `fc7484be0371242f517b6628b0f7dcc3a9a12a29` passed exact-SHA
  CI, a tag-free release rehearsal and a four-target coverage-guided fuzz
  campaign (3,600 s per target, 312,653,669 reported executions, no reported
  crash or sanitizer failure).
- The published tag build, provenance checks and native macOS arm64/Linux
  x86_64 release verification passed. One owner-assisted Secretive P-256
  check passed 9/9 against two localhost servers; other configurations and
  full Touch ID prompt counts remain unverified.
- These are recorded results, not an independent external audit. See the
  [release evidence](docs/TESTING.md#release-candidate-evidence-2026-10-28);
  earlier campaigns remain documented as historical evidence.

### Changed

- Updated `base64` to 0.23 and `signal-hook` to 0.4, and the pinned
  `actions/download-artifact` to v8.0.2.
- Added `scripts/verify-release.sh` and a manual **Verify release** workflow
  that check a tag's release run, provenance and native binaries before an
  archive is attached to a release.
- Made README a shorter product entry point with fair OpenSSH alternatives,
  explicit alpha/distribution status and separate review, test and device evidence.
- Moved operational examples, CLI reference, troubleshooting and recovery to
  `docs/USAGE.md`, including an explicit OpenSSH agent path and reversal of
  manual SSH configuration edits.
- Clarified first contributions, alpha support and dependency review; corrected
  stale logging/recovery evidence and unverified Secretive compatibility claims.

### Hardening since alpha.1

- Tightened SSH configuration scanning: LF-only text, ASCII keywords,
  unambiguous Include arguments and conservative locale-independent globs.
  Fixes CR-delimited Include commands missed by alpha.1's scan.
- Refused hostname canonicalization and state-dependent Match criteria so
  the real connection cannot activate configuration omitted by the probe.
- The alpha.1 build was cancelled before GitHub Release publication. Its
  historical source tag remains and is superseded.
- One cancellable deadline covers nonblocking upstream connection, FIFO queue
  wait and all request/reply bytes; a trickling agent cannot restart it.
- Bounded connection/request/signing budgets, four concurrent upstream
  exchanges, destination-bound duplicate-attempt suppression and aggregated logs.
- Rejected RSA signature flags on non-RSA keys and disabled host-key checking
  on destination/proxy hops. Checked socket ancestors as well as the leaf parent.
- Read the home directory byte-exactly, so a non-UTF-8 home no longer makes
  the ssh_config pre-scan skip the real `~/.ssh/config` (F-39).
- Refused legacy RSA/SHA-1 (`ssh-rsa`) signing. RSA sign requests must name
  exactly one of rsa-sha2-256/512, and upstream signatures must use the
  requested algorithm. **Compatibility change:** clients or servers that only
  accept `ssh-rsa` signatures (OpenSSH < 7.2) fail through SigSieve; there is
  no opt-out. RSA keys themselves keep working with SHA-2.
- Bounded each downstream reply by one write deadline; a slow reader can no
  longer hold a connection by draining a large reply a little at a time (F-40).

## [0.1.0-alpha.1] - 2026-10-26 (superseded source candidate)

First public experimental preview. Not independently audited; see
[limitations](docs/LIMITATIONS.md) before use.

### Added

- Default-deny SSH agent proxy with an explicit SHA256 identity allowlist.
  Authorized signing stays in the upstream agent; private keys are not loaded.
- Optional destination binding using verified OpenSSH session bindings and
  hostbound user authentication. Ed25519 and ECDSA P-256/384/521 host keys.
- `run`, `doctor`, `status` and `connect`, including connection-plan dry runs.
- Per-request authorization, strict bounded parsing, peer-uid checks,
  private sockets, bounded clients and inode-checked cleanup and recovery.
- Real OpenSSH end-to-end tests, hostile protocol clients, property tests,
  failure injection, resource checks and fuzz targets with committed seeds.
- Pinned toolchain and CI; a release workflow for checksummed archives with
  license notices and build provenance, gated by full CI and matching
  tag/package versions (never completed: the alpha.1 build was cancelled).
- Security/threat models, protocol references, compatibility documentation,
  contribution guidelines and private vulnerability reporting.

### Security hardening before publication

- Disabled connection sharing, port/socket forwarding and X11 forwarding in
  `connect`; verified the effective options and every proxy hop.
- Refused indirect ProxyCommands, local commands and `Match exec` before SSH
  runs, including quoted keywords and unusual Include path delimiters.
- Serialized stale-socket recovery to prevent concurrent recovery races.
- Permanently denied binding/signing on connections whose initial binding
  failed, preventing a later binding from erasing the forwarded-path context.
- Resolved the crypto-bigint advisory by updating RustCrypto dependencies;
  the release lockfiles use non-yanked crypto-bigint 0.7.9.
- Used RFC 9987 extension-failure responses for recognized failed extensions.
- Repaired the session-binding fuzz harness to exercise valid signatures and
  authorization, with a test requiring the valid seed to reach that path.

Guard, Trusted Actions, sudo/PAM configuration and privileged server changes
are outside this release. See [FINDINGS](docs/FINDINGS.md) for the historical
pre-publication review record and documented residual risks.
