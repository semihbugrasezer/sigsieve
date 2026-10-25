# Testing

All tests use synthetic, throwaway keys. They never use your own agent:
`SSH_AUTH_SOCK` is always set explicitly, ssh runs with `-F /dev/null` and
`IdentitiesOnly`, and every sshd is unprivileged, bound to 127.0.0.1 on free
ports, configured from a temporary directory.

## Layers

| Layer | Where | What |
|---|---|---|
| Unit | `src/*` `#[cfg(test)]` | parsers, fingerprints (golden values from `ssh-keygen -lf`), policy, binding rules, host-key signature verification for every supported type, forged/mutated bindings |
| Property | proptest in `src/*`, `tests/proxy.rs` | parsers never panic; arbitrary requests fail closed; arbitrary bind bodies never bind; arbitrary sign data never authorized; hostile client sequences (upstream only ever sees authorized traffic) |
| Mock-agent integration | `tests/proxy.rs`, `tests/socket.rs`, `tests/resources.rs` | hostile downstream client vs. SigSieve vs. mock agent with hostile modes (failure, garbage, hang, drop, oversized, wrong type); socket security; failure injection (agent restart, no retries, ~3200 short-lived connections, fd leak check, byte-by-byte frames, eviction) |
| CLI | `tests/cli.rs` | the real binary: config errors, signals and cleanup, doctor/status output privacy, `connect` with fake ssh (argument plan, refusal cases, crash and SIGTERM cleanup, dry run) |
| Real OpenSSH tools | `tests/openssh.rs` | real `ssh-agent`, `ssh-add`, `ssh-keygen -Y sign`, constrained keys, real `ssh` config precedence |
| Real OpenSSH E2E | `tests/e2e_sshd.rs` | `sigsieve connect` → `ssh` → throwaway `sshd`s: filtering, raw-protocol attackers in the remote session, second hop with `session-bind`, hidden-key hop refused, mutations, ControlMaster regression, destination binding (allowed host OK, other host refused, forged binds rejected) |
| Fuzzing (stable) | `tests/fuzz_corpus.rs` + `fuzz/seeds` | seed replay + bounded deterministic mutation through `src/fuzzing.rs` entry points |
| Fuzzing (cargo-fuzz) | `fuzz/` | coverage-guided targets: `requests`, `session_bind`, `key_blob`, `upstream_reply` |

The session-bind harness processes intact signed bodies as well as a framed
bind/bind/key/userauth sequence. A regression test requires the committed
sequence to reach successful authorization before mutation; empty destination
sets and trailing bytes must then deny it. Stable mutation is not coverage-guided.
| Benchmark | `tests/bench.rs` (ignored) | overhead vs. direct agent access |

## Running

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --release
cargo build --release

# Fail (instead of skip) if sshd E2E prerequisites are missing:
SIGSIEVE_REQUIRE_SSHD=1 cargo test --all-targets

# Longer stable fuzzing run:
SIGSIEVE_FUZZ_ITERS=50000 cargo test --release --test fuzz_corpus -- --nocapture

# Benchmark:
cargo test --release --test bench -- --ignored --nocapture

# Supply chain:
cargo audit
cargo deny check
```

E2E prerequisites: `ssh`, `sshd`, `ssh-agent`, `ssh-add`, `ssh-keygen`,
`python3` (raw-protocol attackers), and the ability to run `sshd -t`
unprivileged. Missing prerequisites → skip with a message, or failure with
`SIGSIEVE_REQUIRE_SSHD=1` (set in CI).

### Coverage-guided fuzzing

Requires a nightly toolchain and `cargo-fuzz` (not used by the project so
far):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/requests && cp seeds/requests/* corpus/requests/
cargo +nightly fuzz run requests corpus/requests -- -max_total_time=3600
# likewise: session_bind, key_blob, upstream_reply
```

`fuzz/corpus` (grown by fuzzing) and `fuzz/artifacts` are git-ignored; add
minimized crashers to `fuzz/seeds/<target>/` as regression seeds. Regenerate
the generated seeds with `cargo test --lib write_fuzz_seeds -- --ignored`.

Without nightly, the targets still build on stable
(`cargo build --release --manifest-path fuzz/Cargo.toml`) and can be run
**uninstrumented** (blind mutation from the seeds), which is what the project
has done so far.

## Historical results (pre-publication, 2026-10-24)

These measurements describe earlier local candidates, not release acceptance.
Current release validation belongs in the release notes and its exact-commit CI run.
Platform: macOS arm64, rustc 1.99.1, OpenSSH 10.3.

| Check | Result |
|---|---|
| `cargo test --all-targets` with `SIGSIEVE_REQUIRE_SSHD=1` (fresh clone) | 101 passed, 0 failed, 2 ignored (benchmark, seed generator) |
| `cargo test --release` | same counts |
| Stable fuzzing, 50 000 iterations/seed | ~800 000 inputs, no failure |
| libFuzzer, uninstrumented, 15 s per target | ~146 million executions, no crash |
| Mutation checks | destination check removed → E2E fails; bind signature check removed → E2E fails; session-id check removed → unit tests fail; ControlMaster fix removed → E2E fails; earlier: 5 proxy authorization mutants all killed |
| Release build reproducibility | identical SHA-256 for two builds in separate target dirs (with and without path remapping) |
| Benchmark (release, mock upstream) | per request +~36 µs vs. direct (incl. a fresh upstream connection); new connection + listing ~72 µs; ~41–45k signs/s with 8–32 clients; test-process RSS ~16 MiB; binary ~1.2 MB |

Linux x86_64 also passed an earlier private CI run. That does not validate
later source changes. The public CI matrix covers macOS and both Linux
architectures; inspect the run for the release commit, including its peer-uid
negative checks and real sshd tests.
