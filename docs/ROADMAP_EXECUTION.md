# Roadmap execution plan

Working plan for moving SigSieve from an experimental alpha toward a
well-tested, verifiable and easy-to-install tool **without** overstating its
assurance. Task status lives in [IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md);
this file explains the baseline, the gap analysis, ownership and ordering.

SigSieve remains **experimental and not independently audited**. Nothing in
this plan, and no AI-assisted review performed under it, changes that.

## Baseline (2026-10-29)

| Item | Value |
|---|---|
| Repository | `github.com/semihbugrasezer/sigsieve` (public, MIT) |
| Baseline commit | `main` @ `2edffc8` (merge of PR #28) |
| Latest release | `v0.1.0-alpha.2` pre-release, source `fc7484be` (2026-10-28) |
| `src/`, `tests/`, `fuzz/`, `Cargo.lock` since `fc7484be` | unchanged (only `.github/ISSUE_TEMPLATE/usage_question.yml` and docs changed) |
| Open pull requests / issues | none / none |
| `main` protection | ruleset "main protection": PR required, 4 required checks, strict up-to-date, no force-push/deletion, no bypass, 0 required approvals |
| GitHub security settings | secret scanning: on; push protection: on; Dependabot security updates: on; non-provider patterns and validity checks: off |

## Gap matrix

"Prior report" is the recommendation list this plan was given; each row was
re-checked against the baseline commit.

| Recommendation | Actual state at baseline | Required action |
|---|---|---|
| Independent external review | Not started; scope packet and provider options exist ([EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md), [EXTERNAL_REVIEW_OPTIONS.md](EXTERNAL_REVIEW_OPTIONS.md)) | Maintainer decision and funding: **BLOCKED_EXTERNAL** |
| Broader compatibility evidence | OpenSSH 10.x macOS + Ubuntu 24.04 CI; one owner-assisted Secretive check; Git hosts not exercised ([SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md)) | Extend matrix where feasible (P0-03/P0-04); real devices/services **BLOCKED_EXTERNAL** |
| CI secret scanning | GitHub-native scanning + push protection enabled; no CI-level scanner | Add pinned gitleaks job as defense in depth (P0-05) |
| SBOM and attestations | Build provenance attested; no SBOM | CycloneDX sidecar per target + attestation + verification (P0-06) |
| Release governance | Ruleset + release checklist exist; no governance document | [GOVERNANCE.md](../GOVERNANCE.md) (P0-08) |
| Onboarding | README first safe check, INSTALL, USAGE, SUPPORT, issue forms exist | Verify accuracy; add only what is missing (P1-01, P1-07) |
| Homebrew | None; README states so | Unpublished draft formula from verified artifacts (P1-05) |
| Fingerprint selection UX | Manual `ssh-add -l` copy | Design review before any code (P1-03) |
| Linux aarch64 binary | CI-tested on `ubuntu-24.04-arm`; not a release target | Evaluate adding to release matrix (P2-01) |
| macOS Intel | Not validated; no hosted Intel runner in the matrix | Document requirements (P2-02) |
| User/path restrictions | Not supported; native OpenSSH constraints recommended where applicable | Design/research only, gated (P2-03/P2-04) |

## Ownership and isolation

Each implementation track uses its own branch and git worktree created from
the baseline commit. Branches are local until the maintainer approves a
push; no branch is merged automatically.

| Agent | Role | Branch | Owned files |
|---|---|---|---|
| Lead | Coordination, trackers, governance, integration | `roadmap/execution-tracker` | `docs/ROADMAP_EXECUTION.md`, `docs/IMPLEMENTATION_CHECKLIST.md`, `GOVERNANCE.md`, P2 design notes |
| A | Independent security & protocol reviewer (read-only) | none (report only) | Reviews `src/` and every security-relevant diff from C/D; never reviews its own code |
| B | SSH compatibility & tests | deferred | `tests/`, `docs/SSH_COMPATIBILITY.md` |
| C | Supply chain, CI & release | `ci/secret-scan-sbom` | `.github/workflows/*`, `.gitleaks.toml`, `scripts/verify-release.sh`, `scripts/package-release.py`, `docs/RELEASE_CHECKLIST.md`, offline verification doc |
| D | UX, packaging, OSS experience | `packaging/homebrew-crates-readiness` | `packaging/homebrew/*`, `docs/CRATES_IO_READINESS.md` |

Agent B is deferred in the first batch: the build host has under 10 GB of
free disk, and parallel real-sshd builds would exhaust it. Its tasks stay
TODO, not skipped.

## Ordering and gates

```text
Phase 0 inventory ──► P0-01 review (A) ──► P0-02 regressions for confirmed findings
                 ├──► P0-05/P0-06/P0-07 supply chain (C) ──► A reviews CI diff
                 ├──► P0-08 governance (Lead)
                 └──► P1-05/P1-06 packaging research (D)
P0-03/P0-04 compatibility (B) ── after disk/CI capacity allows
P1-03 interactive selection ── only after a written design passes threat-model review
P2-03/P2-04 user/path binding ── design only; implementation gated on external review
```

Rules: confirmed security regressions first; external review and real-user
trials can never be marked complete by an agent; any security-relevant
change needs a regression test, threat-model update and adversarial review
by a non-author; no release, package publication or settings change without
explicit maintainer approval.

## Integration

1. Each track reports branch, commits, diff summary, commands with exit
   codes, and unresolved risks.
2. Agent A reviews diffs touching protocol, binding, policy, sockets,
   upstream, credentials or CI trust boundaries.
3. The lead rebases reviewed branches onto current `main`, reruns the full
   local validation, and prepares one small pull request per track.
4. Pushes and pull requests are opened only after maintainer approval.
