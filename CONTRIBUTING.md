# Contributing to SigSieve

Thanks for your interest! SigSieve is security software, so the bar for
changes is correctness and evidence, not feature count.

## Ground rules

- Security issues: see [SECURITY.md](SECURITY.md). Report them privately.
- Every behaviour change needs a test. Every security fix needs a regression
  test that fails without the fix.
- Never weaken an assertion or silence a lint to make CI pass.
- Never commit real keys, fingerprints of real keys, hostnames or credentials.
  Tests use synthetic keys only.
- New agent operations or extensions are rejected by default. Supporting one
  requires a written rationale in `docs/SSH_COMPATIBILITY.md` and adversarial
  tests.
- `unsafe` is limited to `src/socket.rs` and needs a `SAFETY:` comment.
- Security changes need an entry in `docs/FINDINGS.md` (if a finding) and
  must keep `docs/SECURITY_MODEL.md` accurate. See `docs/TESTING.md`.
- Keep dependencies minimal. Explain any new crate in the PR.

## Development setup

```bash
git clone https://github.com/semihbugrasezer/sigsieve
cd sigsieve
cargo build
```

Quality gates (all must pass):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
SIGSIEVE_REQUIRE_SSHD=1 cargo test --all-targets --locked
SIGSIEVE_REQUIRE_SSHD=1 cargo test --release --locked
cargo build --release
SIGSIEVE_REQUIRE_SSHD=1 cargo test --test e2e_sshd   # fail instead of skip if sshd is unavailable
cargo audit && cargo deny check            # if installed
```

Tests never use your own agent. They set `SSH_AUTH_SOCK` explicitly and
generate throwaway keys in temporary directories. The `openssh` tests are
skipped if OpenSSH tools are not installed.

## Project layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Pull requests

- Keep PRs focused, and describe the security impact.
- `main` is protected: changes land only through pull requests, and the four
  CI checks (`supply-chain` and the macOS, Linux x86_64 and Linux arm64
  `test` jobs) must pass on a branch that is up to date with `main`.
- Update `CHANGELOG.md` in the topmost section that is not yet released.
- By contributing you agree that your work is licensed under the MIT license.

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).
