# Changelog

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0-alpha.2] - unreleased candidate

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
- Pinned toolchain and CI; checksummed release archives with license notices
  and build provenance, gated by full CI and matching tag/package versions.
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
