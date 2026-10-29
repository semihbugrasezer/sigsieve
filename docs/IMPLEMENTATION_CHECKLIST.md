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

Last updated: 2026-10-29, baseline `main` @ `2edffc8`.

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
| P0-03 | Expand real OpenSSH E2E / destination-binding negative matrix | B | INV | New negative cases run under `SIGSIEVE_REQUIRE_SSHD=1`; no skips | TODO (deferred: disk capacity) | Existing: `tests/e2e_sshd.rs`, `tests/openssh.rs` |
| P0-04 | Other upstream agent implementations with synthetic identities | B | INV | Each agent listed as VERIFIED only when exercised | TODO | Existing matrix: [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md) |
| P0-05 | CI secret scanning, safe for fork PRs | C | INV | Pinned + checksum-verified scanner, `pull_request` trigger, read-only token, redacted output, narrow allowlist | IN_PROGRESS | GitHub-native secret scanning + push protection already enabled |
| P0-06 | SBOM generation, validation, artifact association | C | INV | SBOM sidecar per target, attested in OIDC-only job, verified by `verify-release.sh`; archives stay byte-identical | IN_PROGRESS | — |
| P0-07 | Release checksums, source SHA, provenance, integrity | C | INV | Existing pipeline verified against v0.1.0-alpha.2 | VERIFIED | `release.yml` (separate `attest` job), `scripts/verify-release.sh`, `verify-release.yml`; recorded run in [TESTING.md](TESTING.md#release-candidate-evidence-2026-10-28) |
| P0-08 | Governance: branch protection, checks, roles, release authority | Lead | INV | Document matches live ruleset and release checklist | DONE (branch `roadmap/execution-tracker`) | [GOVERNANCE.md](../GOVERNANCE.md); ruleset read via GitHub API 2026-10-29 |
| P0-09 | External expert review package | Lead | INV | Architecture, threat model, tests, scope, limitations in one packet | VERIFIED | [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md), [EXTERNAL_REVIEW_OPTIONS.md](EXTERNAL_REVIEW_OPTIONS.md) (PRs #27, #28) |
| P0-10 | External review and real-device validation marked external | Lead | P0-09 | Recorded as not started, never as complete | VERIFIED | See [Blocked external](#blocked-external) |
| P0-11 | No high-risk regression, no weakened policy | A+Lead | all P0 | A reviews every security-relevant diff; full validation on the integrated tree | TODO | — |

## Phase P1 — user experience and distribution

| ID | Task | Owner | Depends | Acceptance criteria | State | Evidence |
|---|---|---|---|---|---|---|
| P1-01 | Five-minute safe quickstart | D | P0 gates | Uses synthetic/demo agent, no real key or host needed, commands tested | DONE (branch) | [QUICKSTART.md](QUICKSTART.md); its code blocks were extracted and run verbatim with `bash -e` on macOS arm64 (exit 0, no leftover processes) |
| P1-02 | Doctor diagnostics and actionable errors | D | P0-01 | No sensitive data in output; tests for each new message | TODO | — |
| P1-03 | Interactive fingerprint selection | D+A | design + threat review | Written design approved before code | TODO (gated) | — |
| P1-04 | First-run setup wizard evaluation | D | P1-03 | Evaluation separates confirmed needs from speculation | TODO | — |
| P1-05 | Homebrew formula draft, checksum verification, packaging test | D | P0-07 | Formula built from verified artifacts; not published | PARTIAL (branch `packaging/homebrew-crates-readiness`) | Source-tarball formula draft. The tag tarball was `diff -r` identical to `git archive` of the tag. Release archives passed SHA-256 and `gh attestation verify` (signer `release.yml`, source `fc7484be`, self-hosted runners denied). `ruby -c` passed. The `test do` expectations were checked against a same-source local build (exit 1 / exit 2, stdout strings). `brew audit`/`brew test` were NOT RUN because they need a tap. Publishing requires approval |
| P1-06 | crates.io readiness and blockers | D | — | `cargo package` result and blocker list recorded; not published | DONE (branch `packaging/homebrew-crates-readiness`) | `docs/CRATES_IO_READINESS.md`: `cargo package` 71 files and `publish --dry-run` both PASS. Tests cannot build from the packaged crate because `fuzz/seeds` is excluded. 7 blockers recorded; recommendation: do not publish during alpha |
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
| Workflow lint (actionlint) | PENDING (Agent C) |
| Bounded coverage-guided fuzzing (`cargo fuzz`) | SKIPPED this batch (nightly toolchain and disk); last recorded campaign in [TESTING.md](TESTING.md#recorded-one-hour-campaign) |
