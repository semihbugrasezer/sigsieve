# Governance

SigSieve is a single-maintainer, experimental open-source project. This
document states who decides what, which controls protect `main` and releases,
and what those controls do **not** provide. It describes the current state;
it is not a promise of future staffing.

## Roles

| Role | Who | Authority |
|---|---|---|
| Maintainer | The repository owner (`@semihbugrasezer`) | Merges pull requests, approves dependency updates, decides scope, tags and publishes releases, handles private vulnerability reports, changes repository settings. |
| Contributors | Anyone opening an issue or pull request | Propose changes. No merge or release rights. |
| Automated assistants | AI coding assistants and Dependabot used by the maintainer | Prepare branches, reviews and evidence. They never merge, tag, publish or change settings on their own, and their reviews are **internal** evidence, not independent review. |

There is currently no second human maintainer. A single maintainer is a
known governance risk (bus factor of one, no mandatory second approval);
see [Known gaps](#known-gaps).

## Protected `main`

`main` is protected by the repository ruleset "main protection" (active, no
bypass actors):

- deletion and non-fast-forward (force) pushes are blocked;
- changes land only through pull requests;
- required status checks, on a branch that is up to date with `main`:
  `supply-chain`, `test (macos-latest)`, `test (ubuntu-24.04)`,
  `test (ubuntu-24.04-arm)` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml));
- required approving reviews: **0** (one maintainer cannot approve their
  own pull request).

Changing the ruleset, the required checks or any other repository setting
is a maintainer decision and is recorded in the pull request or release
notes that motivated it.

## Change policy

- Every behaviour change needs a test; every security fix needs a regression
  test that fails without the fix ([CONTRIBUTING.md](CONTRIBUTING.md)).
- Security-relevant changes (agent protocol, keys, policy, destination
  binding, sockets, upstream connection, `connect` configuration checks, CI
  and release trust boundaries) additionally need: an entry in
  [docs/FINDINGS.md](docs/FINDINGS.md) when they fix a finding, an accurate
  [security model](docs/SECURITY_MODEL.md) and [threat model](docs/THREAT_MODEL.md),
  and an adversarial review by someone (or a separate-context review) that
  did not author the change. The review's nature is stated honestly in the
  pull request.
- Controls are never weakened to make CI pass. Destination-bound mode never
  falls back silently to identity-only filtering.
- No automatic merge. Dependabot pull requests receive the same review and
  required checks as any other change.

## Release authority

Only the maintainer tags and publishes releases. The process is
[docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md):

1. a tag that matches `Cargo.toml` triggers [`release.yml`](.github/workflows/release.yml),
   which reruns full CI, builds deterministic archives and attests build
   provenance in a separate job;
2. the workflow never creates a GitHub release or publishes a package;
3. the maintainer verifies the release run with `scripts/verify-release.sh`
   (macOS) and the **Verify release** workflow (Linux) and only then creates
   a pre-release with those artifacts.

Pull-request workflows run with read-only `contents` permission and cannot
publish anything. Public tags and history are never rewritten; a broken
release is corrected by a new version.

Version status: all `0.1.0-alpha.*` releases are experimental pre-releases.
Promotion beyond alpha requires, at minimum, the independent review and user
trials in [docs/EXTERNAL_VALIDATION.md](docs/EXTERNAL_VALIDATION.md) with
their findings resolved. Green automated tests alone never justify promotion.

## Security reports

Private vulnerability reporting is enabled; the process and response targets
are in [SECURITY.md](SECURITY.md). GitHub secret scanning and push protection
are enabled on the repository.

## Known gaps

- **No independent external audit.** Reviews so far are internal and
  AI-assisted ([docs/FINDINGS.md](docs/FINDINGS.md)).
- **Single maintainer.** No mandatory second-person review; no succession plan.
- **Platform evidence is limited** to the CI matrix and the recorded checks in
  [docs/TESTING.md](docs/TESTING.md).

Adding a maintainer or changing this document is done through a pull request.
