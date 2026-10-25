# Changelog

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-10-26

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
- Resolved the crypto-bigint advisory by updating RustCrypto dependencies;
  the release lockfiles use non-yanked crypto-bigint 0.7.9.
- Used RFC 9987 extension-failure responses for recognized failed extensions.
- Repaired the session-binding fuzz harness to exercise valid signatures and
  authorization, with a test requiring the valid seed to reach that path.

Guard, Trusted Actions, sudo/PAM configuration and privileged server changes
are outside this release. See [FINDINGS](docs/FINDINGS.md) for the historical
pre-publication review record and documented residual risks.
