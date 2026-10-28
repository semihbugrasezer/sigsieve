# Contributing to SigSieve

Thanks for your interest! SigSieve is security software, so the bar for
changes is correctness and evidence, not feature count.

## Your first contribution

Documentation corrections, reproducible bug reports and synthetic regression
tests are useful first contributions. Pick a small problem from the
[issues](https://github.com/semihbugrasezer/sigsieve/issues), or describe the
problem before starting a larger change. For installation or usage help, see
[SUPPORT.md](SUPPORT.md) and use the **Usage question** issue template.
Security reports belong in the [private reporting channel](SECURITY.md).

Work on a branch in your fork and open a focused PR against `main`. Include
what changed, why, and the commands you actually ran. For documentation,
check the rendered Markdown, relative links and any changed CLI examples;
describe platform or device checks you could not perform. No private agent,
maintainer credentials or production host is needed for the automated suite.

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
cargo build --locked
./target/debug/sigsieve --help
```

The checkout selects Rust through `rust-toolchain.toml`. Real-SSH tests need
`ssh`, `ssh-agent`, `ssh-add`, `ssh-keygen`, `sshd` and `python3`; Linux CI
uses Ubuntu 24.04 with the OpenSSH client/server packages. See
[TESTING.md](docs/TESTING.md) for prerequisites and test layers.

Use `cargo test --locked --lib` for a quick local feedback loop. Before
requesting review, run the applicable checks below and state any you could
not run. The full hosted CI remains required for every PR, including docs.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
SIGSIEVE_REQUIRE_SSHD=1 cargo test --all-targets --locked
SIGSIEVE_REQUIRE_SSHD=1 cargo test --release --locked
cargo build --release --locked
cargo audit                               # if installed; required in CI
cargo audit --file fuzz/Cargo.lock
cargo deny check
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

## Versions and dependencies

Alpha releases are experimental; fixes target `main` and the next alpha.
Older prereleases have no promised backports or stable support window; see
[SECURITY.md](SECURITY.md). Record user-visible changes under `Unreleased`,
and move them into the candidate's notes when preparing a release. A source
tag or a prepared workflow is not a verified binary release. Publication
requires the [release checklist](docs/RELEASE_CHECKLIST.md) and maintainer approval.

Keep dependency maintenance focused: update both root and `fuzz/` lockfiles
when affected, explain the reason, and run advisory/license checks plus full
CI. GitHub Actions stay pinned to reviewed commit SHAs. Automated suggestions
receive the same review and never justify bypassing required checks.

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).
