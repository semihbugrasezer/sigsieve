# Platform support evaluation

Status: **evaluation, no behaviour change.** Roadmap items P2-01 (Linux
aarch64 release), P2-02 (macOS Intel) and P2-06 (Windows). Current support is
stated in [INSTALL.md](../INSTALL.md): prebuilt archives for macOS arm64 and
Linux x86_64 only.

A platform is "supported" only when its full CI, including the real `sshd`
end-to-end tests, runs in the release gate, and its release archive has been
verified natively with `scripts/verify-release.sh`.

## P2-01: Linux aarch64 prebuilt archive

| Requirement | State |
|---|---|
| Full CI on native arm64 with real sshd | Met: `test (ubuntu-24.04-arm)` is a required check on `main` |
| Native build in `release.yml` | Not yet: the build matrix has two targets |
| Attest job | Asserts exactly two archives; it must change to three |
| `scripts/verify-release.sh` / **Verify release** workflow | `TARGETS`, the expected build job names, the binary-type check and host detection list only macOS arm64 and Linux x86_64; all four need the new target, plus a native arm64 verification job |
| `release-rehearsal.yml` | Rehearses two targets |

The change is mechanical. Add `ubuntu-24.04-arm` / `aarch64-unknown-linux-gnu`
to the build matrices in `release.yml` and `release-rehearsal.yml`, set the
attest count to 3, extend `scripts/verify-release.sh`, and add an arm
runner to `verify-release.yml`. It touches the release trust boundary, so it needs a
rehearsal run (requires a push) and a review by someone other than its
author. Recommended for the next alpha after the SBOM change (P0-06) lands,
so the two release-pipeline changes are not combined in one untested step.

## P2-02: macOS Intel (x86_64-apple-darwin)

Nothing in the code is architecture-specific (`src/socket.rs` uses the
same `getpeereid(3)` path on all macOS), but no Intel run has been
recorded. Requirements before claiming support:

1. A native Intel macOS environment for the full test suite with
   `SIGSIEVE_REQUIRE_SSHD=1`. Either a GitHub-hosted Intel macOS runner,
   whose current label and retirement date must be checked in GitHub's
   runner documentation at the time of the change, or maintainer-owned
   hardware recorded as owner-assisted evidence.
2. A release build and native `verify-release.sh` run for the Intel archive.
3. Secretive on Intel Macs requires a T2 Secure Enclave. That integration
   needs real hardware and is `BLOCKED_EXTERNAL`; protocol tests do not prove it.

Cross-compiling from arm64 without native execution is **not** sufficient
evidence and must not be presented as validation. Until then, Intel users
build from source (documented) at their own risk.

## P2-06: Windows

Not feasible without a substantial new platform layer. Recommendation: do
not pursue now.

- The security model depends on Unix-domain sockets in an owner-only
  directory plus a kernel peer-UID check (`getpeereid` / `SO_PEERCRED` in
  `src/socket.rs`). Windows OpenSSH's agent uses a named pipe
  (`\\.\pipe\openssh-ssh-agent`) with ACL-based access control. Equivalent
  guarantees would need new, separately reviewed `unsafe` Win32 code.
- `sigsieve connect` relies on OpenSSH client behaviour (`ssh -G`,
  `ForwardAgent=<path>`, ProxyCommand/LocalCommand verification). It would
  have to be revalidated against Win32-OpenSSH.
- The primary use case (Secretive) is macOS-only.

Windows users who need a filtered forwarded agent can run SigSieve inside
WSL2 against a Linux agent. That configuration is untested and
unsupported, and it should be documented as such only if users ask for it.
