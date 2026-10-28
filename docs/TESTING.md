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
| Benchmark | `tests/bench.rs` (ignored) | overhead vs. direct agent access |

The session-bind harness processes intact signed bodies as well as a framed
bind/bind/key/userauth sequence. A regression test requires the committed
sequence to reach successful authorization before mutation; empty destination
sets and trailing bytes must then deny it. Stable mutation is not coverage-guided.

## Interpreting evidence

- **Code-reviewed:** internal AI-assisted review history is in
  [FINDINGS.md](FINDINGS.md); this is not an independent external audit.
- **Automatically tested:** use the exact commit's hosted CI, with tool
  prerequisites enforced. A configured workflow or a skipped test is not a pass.
- **Real OpenSSH tested:** real processes with throwaway keys and local
  servers, not proof of another agent's implementation or a hosted Git service.
- **Real Secretive tested:** only the dated, user-assisted observations in
  [SECRETIVE_INTEGRATION.md](SECRETIVE_INTEGRATION.md#recorded-real-device-results).
- **Fuzzed:** distinguish deterministic corpus mutation, uninstrumented
  libFuzzer execution and instrumented coverage-guided runs. Retain the run
  revision, toolchain, target, duration and crash results before extending claims.
- **Independently audited:** not done. Untested integrations remain untested
  even when they implement the same protocol.

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

The **Fuzz** GitHub Actions workflow (`.github/workflows/fuzz.yml`) runs all
four targets with libFuzzer and AddressSanitizer on a pinned nightly,
starting from `fuzz/seeds`. Start it from the Actions tab with a time budget
per target (300 s to 1 h); it also runs for 60 s on pull requests that change
`fuzz/`. A crash fails the job; the grown corpus and crash inputs are kept as
artifacts for 14 days, and the job summary records executions and new
coverage units. Locally it needs a nightly toolchain and `cargo-fuzz`:

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
used for its historical pre-publication libFuzzer runs below.

### Recorded coverage-guided smoke run

On 2026-10-27, [run 40501046044](https://github.com/semihbugrasezer/sigsieve/actions/runs/40501046044)
completed all four targets with a 60 s budget each, `nightly-2026-10-15`,
`cargo-fuzz 0.12.0`, libFuzzer and AddressSanitizer. Logs show loaded inline
coverage counters and PC tables. PR head:
`5a83811d8d413b10c1b3f3a6226cf66849fc2e74`; tested merge revision:
`380d68c612ccbadc380b3f046052dcc276c54ad2`.

| Target | Executions | Final libFuzzer `cov` | Result |
|---|---|---|---|
| `requests` | 469,159 | 1,676 | completed; no crash reported |
| `session_bind` | 282,221 | 2,154 | completed; no crash reported |
| `key_blob` | 1,624,379 | 491 | completed; no crash reported |
| `upstream_reply` | 2,774,089 | 103 | completed; no crash reported |

These counters are libFuzzer's reported coverage units, not a percentage of
program coverage. This is short smoke evidence for that revision, not a
sustained campaign, a result for later commits or proof of no vulnerabilities.

### Recorded one-hour campaign

On 2026-10-27, [run 40503563496](https://github.com/semihbugrasezer/sigsieve/actions/runs/40503563496)
ran each of the four targets for 3600 s on `main` at
`103e9f9aae0da1148d67b6e13882cb829add2fca`, with the same toolchain, sanitizer
and seeds as above. All four jobs finished successfully.

| Target | Executions | exec/s | Final `cov` / `ft` | Corpus | New units | Peak RSS | Result |
|---|---|---|---|---|---|---|---|
| `requests` | 5,072,940 | 1,408 | 1,699 / 7,001 | 604 entries | 2,792 | 505 MB | no crash reported |
| `session_bind` | 13,891,709 | 3,857 | 2,220 / 3,614 | 324 entries | 490 | 500 MB | no crash reported |
| `key_blob` | 78,451,123 | 21,785 | 646 / 719 | 171 entries | 738 | 503 MB | no crash reported |
| `upstream_reply` | 158,116,390 | 43,909 | 103 / 274 | 48 entries | 440 | 514 MB | no crash reported |

Coverage (`cov`) grew only slightly over the 60 s smoke run for each target
(for example 1,676 → 1,699 for `requests`), which suggests these targets are
close to saturating what their current entry points can reach; deeper
coverage needs new targets or richer seeds rather than longer runs. One hour
per target is a modest campaign for one revision, not proof of the absence
of vulnerabilities.

## Release-candidate evidence (2026-10-28)

The experimental [v0.1.0-alpha.2 pre-release](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.2)
is pinned to commit `fc7484be0371242f517b6628b0f7dcc3a9a12a29`
(not the later documentation-only `main` head).

- [CI](https://github.com/semihbugrasezer/sigsieve/actions/runs/40729859157):
  all four required jobs passed (supply-chain, macOS, Linux x86_64 and arm64).
- [Release rehearsal](https://github.com/semihbugrasezer/sigsieve/actions/runs/40730067585):
  macOS arm64 and Linux x86_64 passed.
- [Four-target fuzz run](https://github.com/semihbugrasezer/sigsieve/actions/runs/40730071966):
  3600 s per target; all jobs passed with no reported crash or sanitizer failure.
- [Real tag release build](https://github.com/semihbugrasezer/sigsieve/actions/runs/40743739260):
  packaging, SHA-256 checksums and provenance attestation passed.
- Release verifier: macOS arm64 native `RESULT: PASS` was recorded locally;
  [Linux x86_64 native `RESULT: PASS`](https://github.com/semihbugrasezer/sigsieve/actions/runs/40746332311)
  is recorded in the public workflow log.
- Owner-assisted Secretive P-256 localhost test returned 9/9 PASS, including
  an allowed signature, allowed hostbound authentication, forbidden host
  refusal and rejection of non-authentication signing. The owner reported
  no unexpected Touch ID requests during forbidden steps. This is one
  device/configuration and not an independent external audit.

| Target | Executions | Final `cov / ft` | Final corpus | New units | Result |
|---|---:|---|---:|---:|---|
| `requests` | 13,375,674 | 1,712 / 7,600 | 698 | 3,419 | no crash reported |
| `session_bind` | 10,255,713 | 2,214 / 3,618 | 320 | 522 | no crash reported |
| `key_blob` | 96,142,034 | 600 / 673 | 147 | 731 | no crash reported |
| `upstream_reply` | 192,880,248 | 103 / 274 | 47 | 416 | no crash reported |
| **Total** | **312,653,669** | — | — | — | **4 jobs successful** |

The libFuzzer counters are not a percentage of code coverage. A successful
campaign is not proof of the absence of vulnerabilities.

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
