# Implementation checklist

Source of truth for roadmap task status. Plan and ownership:
[ROADMAP_EXECUTION.md](ROADMAP_EXECUTION.md).

**States:** `VERIFIED` (exists and evidence checked) · `DONE` (implemented on
a branch, evidence recorded, review addressed; not yet merged unless stated) ·
`PARTIAL` · `IN_PROGRESS` · `TODO` · `BLOCKED` · `BLOCKED_EXTERNAL` (needs a
person, service, device or decision outside this repository).

A box is ticked only for `VERIFIED` or `DONE`. Branch work is not merged
until the maintainer approves its pull request. AI-assisted review is
internal evidence and never an independent audit.

Last updated: 2026-10-30, `main` @ `3a6c74c` (alpha.3 preparation merged; not tagged). Earlier baseline: `2edffc8`.

## Phase 0 — baseline and inventory

- [x] **P0-INV-1** Repository identity, branch, HEAD, release, PRs/issues — `VERIFIED`. Evidence: [ROADMAP_EXECUTION.md § Baseline](ROADMAP_EXECUTION.md#baseline-2026-10-29).
- [x] **P0-INV-2** Read README, SECURITY, CONTRIBUTING, CHANGELOG, Cargo.toml, deny.toml, docs — `VERIFIED`.
- [x] **P0-INV-3** CI workflows, release scripts, test targets inventoried — `VERIFIED`. Workflows: `ci.yml`, `fuzz.yml`, `release.yml`, `release-rehearsal.yml`, `verify-release.yml`; scripts: `package-release.py`, `test-package-release.py`, `third-party-notices.py`, `verify-release.sh`, `agent-integration-check.sh`.
- [x] **P0-INV-4** Baseline checks run locally — `VERIFIED` (see [Validation log](#validation-log)).
- [x] **P0-INV-5** Gap matrix — `VERIFIED`. [ROADMAP_EXECUTION.md § Gap matrix](ROADMAP_EXECUTION.md#gap-matrix).
- [x] **P0-INV-6** Tracker documents — `DONE` (this file and the plan).
- [x] **P0-INV-7** Isolated branches/worktrees and agent assignment — `DONE`. [Ownership](ROADMAP_EXECUTION.md#ownership-and-isolation).

## Phase P0 — security and trustworthiness

| ID | Task | Owner | Depends | Acceptance criteria | State | Evidence |
|---|---|---|---|---|---|---|
| P0-01 | Internal adversarial review with external-audit disclaimer | A | INV | Report cites file:line per finding, classifies CONFIRMED/SUSPECTED/OUT-OF-SCOPE, states it is not an independent audit | DONE (internal; not an audit) | Separate-context AI review of `src/` @ `fc7484be`: no new CRITICAL/HIGH/MEDIUM/LOW; 5 INFO recorded in [FINDINGS.md](FINDINGS.md#internal-review-of-v010-alpha2-source-2026-10-29) |
| P0-02 | Regression tests for confirmed findings before fixes | A→Lead | P0-01 | Each CONFIRMED finding has a failing-then-passing test and a FINDINGS.md entry | DONE (no actionable finding) | No CONFIRMED vulnerability to fix. Added `binding::tests::binds_after_authentication_bind_leave_state_unchanged`: it passes, and it fails when the `AlreadyBoundForAuth` check is removed (mutation-checked locally). A-1 hardening awaits a maintainer decision |
| P0-03 | Expand real OpenSSH E2E / destination-binding negative matrix | B | INV | New negative cases run under `SIGSIEVE_REQUIRE_SSHD=1`; no skips | DONE (merged in #32) | 7 new tests: plain publickey to an allowed destination refused; RSA host key fails closed even when allowed; a forwarding hop's key does not authorize another final host; two forwarding hops; `git commit -S` refused in binding mode; gpg-agent upstream with binding; truncated upstream sign response. Each was mutation-checked against its guard; the gpg-agent `ssh-rsa` sub-check has no gpg-only control (review B-1). Locally, 159 passed and 0 skipped (debug and release) |
| P0-04 | Other upstream agent implementations with synthetic identities | B | INV | Each agent listed as VERIFIED only when exercised | PARTIAL (merged in #32) | OpenSSH ssh-agent and GnuPG `gpg-agent` (2.5.24, macOS arm64, throwaway home) are VERIFIED. 1Password, KeePassXC, Bitwarden, ssh-tpm-agent and FIDO `sk-*` are NOT_TESTED; Secretive is limited to the owner-assisted record. See [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md) |
| P0-05 | CI secret scanning, safe for fork PRs | C | INV | Pinned + checksum-verified scanner, `pull_request` trigger, read-only token, redacted output, narrow allowlist | DONE (merged in #30; hosted secret-scan PASS) | gitleaks 8.30.1 is pinned with its SHA-256 checked; the scan configuration lives outside the checkout, inline allow comments are ignored, and any `.gitleaksignore` fails the job. Review D-2 took three rounds: the config fix (`8a6e630`), then a `.gitleaksignore` guard (`7bbbbed`), which the reviewer bypassed through SIGPIPE under pipefail, then a pipeline-free guard (`63214d6`). Every bypass was reproduced locally before its fix, and the final guard was exercised as written, including against 3000 decoys. Local scans: 0 findings in history and tree. No allowlist needed. Defense in depth next to native scanning and push protection |
| P0-06 | SBOM generation, validation, artifact association | C | INV | SBOM sidecar per target, attested in OIDC-only job, verified by `verify-release.sh`; archives stay byte-identical | PARTIAL (merged in #30; hosted rehearsal SBOM PASS; tag run NOT RUN) | CycloneDX 1.5 via cargo-cyclonedx 0.5.9 in a separate job. Generated locally twice with identical bytes, covering all `cargo tree` deps. Build provenance and an SBOM attestation are recorded per archive. The attest job takes artifacts by exact name and checks their contents (review D-1 fixed; 1 valid and 5 malicious local cases). F-42 (attest trusted artifacts by name) is tracked as P0-12. `verify-release.sh` PASSes on the published alpha.2 with `SBOM NOT_PRESENT`, and 7 stub cases fail closed. Offline verification is documented in `docs/VERIFY_OFFLINE.md` (bundle path tested offline for provenance) |
| P0-07 | Release checksums, source SHA, provenance, integrity | C | INV | Existing pipeline verified against v0.1.0-alpha.2 | VERIFIED | `release.yml` (separate `attest` job), `scripts/verify-release.sh`, `verify-release.yml`; recorded run in [TESTING.md](TESTING.md#release-candidate-evidence-2026-10-28) |
| P0-08 | Governance: branch protection, checks, roles, release authority | Lead | INV | Document matches live ruleset and release checklist | DONE (merged in #29) | [GOVERNANCE.md](../GOVERNANCE.md); ruleset read via GitHub API 2026-10-29 |
| P0-09 | External expert review package | Lead | INV | Architecture, threat model, tests, scope, limitations in one packet | VERIFIED | [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md), [EXTERNAL_REVIEW_OPTIONS.md](EXTERNAL_REVIEW_OPTIONS.md) (PRs #27, #28) |
| P0-10 | External review and real-device validation marked external | Lead | P0-09 | Recorded as not started, never as complete | VERIFIED | See [Blocked external](#blocked-external) |
| P0-13 | Declared MSRV verified in CI | Lead | P1-06 | Repository and packaged `.crate` build and test on the declared `rust-version` | DONE (merged in #34) | `msrv (Rust 1.88)` PASS at `084942b` (run 40974557168) and on `main` `3a6c74c` (run 40975896447): full suite with real sshd and gpg-agent, skips fail the job |
| P0-12 | F-42: bind attest inputs to their producing jobs | Release + A | P0-06 | Artifact ID, digest and run relationship verified; positive and negative tests; independent review; hosted evidence | PARTIAL (merged in #32 and #33; tag-run evidence pending; next-tag blocker) | `scripts/test-attest-inputs.sh` passes 50/50 (1 positive, 32 rejections, 3 byte-identical extractions, 1 regular-files check, 2 never-calls-`unzip` checks, 11 nothing-written checks). The lead ran five local mutations: symlink and regular-file checks removed (2 checks fail), extraction switched back to `unzip` (20 fail), one entry not extracted (5 fail), duplicate check removed (2 fail), size cap removed (2 fail). The independent review found D-1 (MEDIUM, suspected) and the LOW items D-2, F-42 and C-1, all fixed; the remaining items were INFO. The hosted rehearsal `verify` job, which runs attest's binding and extraction scripts on real artifacts without OIDC, passed with the C-1 code at `0291558` (run 40969823806) and at `084942b` (dispatched run 40974882778). The tag run (OIDC attestations) is NOT RUN |
| P0-11 | No high-risk regression, no weakened policy | A+Lead | all P0 | A reviews every security-relevant diff; full validation on the integrated tree | DONE (hosted CI green on the merged #29–#34; F-42 tag-run evidence pending) | Agent A reviewed the CI branch and each fix: MEDIUM D-1 (suspected) fixed in `8a6e630`; LOW D-2 fixed in `63214d6` after two re-reviews showed the earlier fixes were incomplete; D-3 reworded; D-4/D-5 INFO accepted; D-1b is open as F-42, a blocker for the next tag. Test-only `src` change: confirmed. Homebrew draft: no issue. Final reviewer confirmation: nothing blocks merge. Integrated tree passes the full local validation (below). No authorization policy was changed |

## Phase P1 — user experience and distribution

| ID | Task | Owner | Depends | Acceptance criteria | State | Evidence |
|---|---|---|---|---|---|---|
| P1-01 | Five-minute safe quickstart | D | P0 gates | Uses synthetic/demo agent, no real key or host needed, commands tested | DONE (branch) | [QUICKSTART.md](QUICKSTART.md); its code blocks were extracted and run verbatim with `bash -e` on macOS arm64 (exit 0, no leftover processes) |
| P1-02 | Doctor diagnostics and actionable errors | D | P0-01 | No sensitive data in output; tests for each new message | TODO | — |
| P1-03 | Interactive fingerprint selection | D+A | design + threat review | Written design approved before code | TODO (gated) | — |
| P1-04 | First-run setup wizard evaluation | D | P1-03 | Evaluation separates confirmed needs from speculation | TODO | — |
| P1-05 | Homebrew formula draft, checksum verification, packaging test | D | P0-07 | Formula built from verified artifacts; not published | PARTIAL (merged in #31; not published) | Source-tarball formula draft. The tag tarball was `diff -r` identical to `git archive` of the tag. Release archives passed SHA-256 and `gh attestation verify` (signer `release.yml`, source `fc7484be`, self-hosted runners denied). `ruby -c` passed. The `test do` expectations were checked against a same-source local build (exit 1 / exit 2, stdout strings). `brew audit`/`brew test` were NOT RUN because they need a tap. Publishing requires approval |
| P1-06 | crates.io readiness and blockers | D | — | `cargo package` result and blocker list recorded; not published | DONE (PR #31) | [CRATES_IO_READINESS.md](CRATES_IO_READINESS.md). Blockers 1–3 are resolved: the packaged crate's tests run in CI via `scripts/check-crate-package.sh`, and MSRV 1.88 is built and tested by the `msrv (Rust 1.88)` job. Blockers 4–7 are open. Recommendation: do not publish during alpha |
| P1-07 | README/INSTALL/USAGE/SECURITY_MODEL/LIMITATIONS/SSH_COMPATIBILITY accuracy | Lead+D | P0 | Each claim traced to code/tests | TODO | — |
| P1-08 | Contribution templates, good-first-issue guide, maintainer guidelines | Lead | — | Templates exist and match CONTRIBUTING | PARTIAL | Issue forms, PR template, [CONTRIBUTING.md](../CONTRIBUTING.md) "Your first contribution", [SUPPORT.md](../SUPPORT.md) exist; maintainer guideline now in GOVERNANCE.md |
| P1-09 | Three-user pilot protocol with consent and criteria | Lead | — | Protocol written; trials themselves external | VERIFIED (protocol) | [EXTERNAL_VALIDATION.md § trials](EXTERNAL_VALIDATION.md#three-real-user-installation-trials); trials BLOCKED_EXTERNAL |
| P1-10 | Draft issue descriptions for remaining work | Lead | trackers | No duplicates of existing issues (none open at baseline) | TODO | — |

## Phase P2 — platform coverage and advanced design

| ID | Task | Owner | Depends | Acceptance criteria | State | Evidence |
|---|---|---|---|---|---|---|
| P2-01 | Linux aarch64 prebuilt release evaluation | C | P0-06 | Decision recorded; native test evidence on arm runner | PARTIAL (evaluated; implementation after P0-06) | [design/PLATFORM_SUPPORT.md](design/PLATFORM_SUPPORT.md#p2-01-linux-aarch64-prebuilt-archive); `test (ubuntu-24.04-arm)` required check |
| P2-02 | macOS Intel validation requirements | Lead | — | Hardware/runner requirements documented | DONE (doc) | [design/PLATFORM_SUPPORT.md](design/PLATFORM_SUPPORT.md#p2-02-macos-intel-x86_64-apple-darwin); native run BLOCKED_EXTERNAL |
| P2-03 | Username-constraint design proposal | Lead+A | — | Invariants and adversarial tests specified; no code | PARTIAL (draft; awaiting adversarial design review) | [design/DESTINATION_CONSTRAINT_EXTENSIONS.md](design/DESTINATION_CONSTRAINT_EXTENSIONS.md#p2-03-username-constraints) |
| P2-04 | Path/intermediate-hop binding research vs OpenSSH | Lead+A | — | Research note; no implementation | PARTIAL (open questions need real OpenSSH traces) | [design/DESTINATION_CONSTRAINT_EXTENSIONS.md](design/DESTINATION_CONSTRAINT_EXTENSIONS.md#p2-04-path-and-intermediate-hop-constraints-research-only) |
| P2-05 | Performance and resource-exhaustion baselines | B | — | Measurable, repeatable baseline | PARTIAL | `tests/bench.rs` (ignored by default), [RESOURCE_LIMITS.md](RESOURCE_LIMITS.md) |
| P2-06 | Windows feasibility note | Lead | — | Document only | DONE (doc) | [design/PLATFORM_SUPPORT.md](design/PLATFORM_SUPPORT.md#p2-06-windows) |
| P2-07 | Community adoption/feedback plan without telemetry | Lead | — | Plan uses issues/discussions only | DONE (doc) | [ROADMAP_EXECUTION.md](ROADMAP_EXECUTION.md#community-feedback-plan-p2-07) |

## Blocked external

| Item | Why it cannot be completed here |
|---|---|
| Independent SSH/security review | Requires an independent human expert and maintainer-approved scope/cost |
| Three real-user installation trials | Requires recruited participants with informed consent |
| Real Secretive / Secure Enclave beyond the one owner-assisted check | Requires the maintainer's device and approval |
| 1Password, physical FIDO keys | Requires those products/devices |
| GitHub SSH, self-hosted GitLab, bastion deployments | Requires real accounts/hosts; status stays `NOT_TESTED` |
| macOS Intel native run | No Intel hardware or Intel runner in the matrix |
| CI behaviour of new workflows | Requires a maintainer-approved push; local work cannot prove hosted CI |

## Validation log

Local, macOS 27.0 arm64, rustc/cargo 1.99.1, OpenSSH 10.3p1, commit
`2edffc8`, 2026-10-29. Hosted CI for this commit is recorded by GitHub, not here.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS (exit 0) |
| `cargo check --locked --all-targets` | PASS |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | PASS (exit 0) |
| `SIGSIEVE_REQUIRE_SSHD=1 cargo test --all-targets --locked` | PASS (exit 0): 150 passed, 0 failed, 2 ignored by design (`bench`, `write_fuzz_seeds`), 0 skip messages |
| `SIGSIEVE_REQUIRE_SSHD=1 cargo test --release --locked` | PASS (exit 0): 150 passed, 0 failed, 2 ignored by design |
| `SIGSIEVE_FUZZ_ITERS=20000 cargo test --release --locked --test fuzz_corpus` | PASS (exit 0) |
| `gitleaks git --redact --log-opts=<public main>` (gitleaks 8.30.1) | PASS: 48 commits, no leaks |
| `gitleaks dir --redact .` | PASS: no leaks |
| `cargo audit`, `cargo deny check` | SKIPPED locally (tools not installed); enforced by the required `supply-chain` CI check |
| Workflow lint (actionlint 1.7.12, checksum-verified) | PASS (exit 0) on the integrated workflows |
| Integrated tree (`integration/roadmap-batch1`): fmt, check, clippy `-D warnings`, debug + release tests with `SIGSIEVE_REQUIRE_SSHD=1`, umask 0002 tests, fuzz corpus 20k, release build, packaging regression, `bash -n verify-release.sh`, `ruby -c` formula, gitleaks git/dir, `git diff --check` | PASS, every command exit 0. Tests: 151 passed, 0 failed, 2 ignored by design, 0 skip messages, in both debug and release |
| `scripts/verify-release.sh 40743739260 v0.1.0-alpha.2` (CI branch) | PASS: `SBOM NOT_PRESENT: pre-SBOM release`, native macOS doctor smoke test included |
| Hosted GitHub Actions for new or changed workflows | PASS on the merged PRs #29–#34 and on `main` `3a6c74c`; the tag-only release path is NOT RUN |
| Coverage-guided fuzzing (`cargo fuzz`) | Short PR runs of all four targets PASS on #34; the 3,600 s-per-target campaign for alpha.3 is pending on the final candidate SHA; last recorded campaign in [TESTING.md](TESTING.md#recorded-one-hour-campaign) |
