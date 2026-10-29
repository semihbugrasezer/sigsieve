# External review and user trials

Status: **not started**. No external expert or trial participants have been
selected. This is a protocol and reporting template, not completed validation.

Evaluate the published experimental `v0.1.0-alpha.2`, release source
`fc7484be0371242f517b6628b0f7dcc3a9a12a29`. Record the documentation revision
used separately: post-release documentation changes do not change the
published binary. Use the [installation guide](INSTALL.md) to verify checksum
and provenance before execution; record the resolved executable path and version.
Existing evidence is in [TESTING.md](TESTING.md#release-candidate-evidence-2026-10-28).

## Independent SSH/security review

The reviewer should have SSH-agent/protocol security experience and be
independent of implementation. Record their role, independence, scope, source
SHA, dates, methods and limitations. Separate-context AI-assisted review is
internal evidence and does not satisfy this review.

Give the reviewer the [threat model](THREAT_MODEL.md),
[security model](SECURITY_MODEL.md), [findings register](FINDINGS.md),
[compatibility matrix](SSH_COMPATIBILITY.md), [limits](LIMITATIONS.md) and
[resource limits](RESOURCE_LIMITS.md), plus the exact source revision.

Suggested review boundaries:

| Boundary | Code and tests | Questions to resolve |
|---|---|---|
| Untrusted agent messages | `src/protocol.rs`, `src/keys.rs`, `src/proxy.rs`, `tests/proxy.rs`, `fuzz/` | Can malformed data, a known hidden public key or unsupported operation bypass authorization? |
| Destination authorization | `src/binding.rs`, `src/policy.rs`, `tests/e2e_sshd.rs` | Are signatures bound to the approved host key and session? Do invalid bindings, unsupported algorithms and missing hostbound support refuse signing? |
| SSH configuration | `src/ssh.rs`, `src/sshconfig.rs`, `tests/cli.rs`, `tests/e2e_sshd.rs` | Can a proxy hop, command, Include or reused master expose the unfiltered agent? |
| Local resources and lifecycle | `src/socket.rs`, `src/upstream.rs`, `src/proxy/resources.rs`, `tests/socket.rs`, `tests/resources.rs` | Are socket ownership, deadlines, cancellation, budgets and cleanup enforced under adversarial requests? |
| Distribution | `scripts/package-release.py`, `scripts/verify-release.sh`, `.github/workflows/release.yml`, `docs/INSTALL.md` | Does verification bind the executed binary to the approved repository, tag, source and artifact digest? |

Use throwaway agents, keys and unprivileged test servers. Start from the
[documented test commands](TESTING.md); retain failures and skipped checks.
Do not use personal agents, production hosts or privileged credentials.

For each finding record: identifier, severity, source SHA and file/line,
reproduction, expected/observed result, impact, suggested minimum fix,
regression evidence, fixed SHA and reviewer retest result. Report vulnerabilities
through [SECURITY.md](../SECURITY.md), not public trial feedback. A finding is
closed only with a documented resolution; green CI alone is not that resolution.

Review outcome: **pending**. Reviewer, scope, findings, residual risks and
recommendation must be filled from the actual review. No audit or certification
claim follows from preparing this document.

## Three real-user installation trials

Recruit three people who did not implement SigSieve and have a genuine remote
development/build use case. Record their SSH experience. Prefer a mix of macOS
arm64 and Linux x86_64; three people do not establish platform-wide coverage.
Keep the trial to existing `doctor`, `connect --dry-run` and `connect` commands.

### Prepare each session

- Use a fresh OpenSSH test agent with two throwaway identities; one allowed,
  one hidden. Keep the participant's ordinary agent and credentials separate.
  A software-agent trial measures that configuration, not Secretive/FIDO support.
- Provide disposable, unprivileged SSH servers for the forwarding host and
  allowed/forbidden destinations. Install only the test public keys. Give the
  participant verified host-key fingerprints through a trusted channel and
  prepare known_hosts entries; use `StrictHostKeyChecking=yes`.
- For the optional Secretive/device trial, the owner creates a dedicated test
  identity and records device, OS and agent version. Do not ask them to share
  private keys or alter production identities. Record Touch ID observations
  per operation; do not infer user presence from a successful signature.
- Start a timer when the participant opens the installation guide. Let them
  follow it before coaching; record every intervention and confusing step.
- If isolated agents or verified test servers are unavailable, mark the
  affected tasks **not run**. Never replace them with production systems.

### Tasks and observations

| Task | Expected result | Record |
|---|---|---|
| Explain the use case | Participant distinguishes login identity selection from forwarded-agent filtering | Their explanation; whether SigSieve solves an existing problem |
| Install and verify | Download/source revision, checksum and provenance checks complete before executing a downloaded binary | OS/architecture, resolved path/version, elapsed time, errors, help needed |
| Select an upstream and one key | Explicit test socket and allowlisted fingerprint; ordinary agent unchanged | Steps, copy/paste work, misunderstandings |
| Run `doctor` | Local filtering checks succeed without requesting real-key signing | Result, errors and any unexpected prompt |
| Run `connect --dry-run` | Filtered forwarding and verified host configuration are shown; no remote session starts | Can the participant understand the plan? |
| Connect to the test forwarding host | Remote `ssh-add -l` lists only the allowed identity | Result, completion time and facilitator intervention |
| Check hidden-key refusal | Existing `scripts/agent-integration-check.sh` against the explicit test upstream refuses raw hidden-key signing | Result and unexpected prompts; this script alone does not test destination binding |
| Optional destination-bound session | Allowed test destination succeeds; forbidden destination, generic signing and unsupported hostbound authentication refuse signing | Exact command/scenario, server/client versions, outcome and prompts for each operation; **not run** if unavailable |
| Exit and recover | Session's proxy/socket cleaned up; ordinary SSH and the upstream test identity set unchanged | Cleanup and recovery observations |
| Assess usefulness | Participant identifies a repeat-use case or explains why none exists | Would they use it again? What would they otherwise use? |

Use the existing [usage guide](USAGE.md) and
[controlled agent check](SECRETIVE_INTEGRATION.md#automated-controlled-check).
Binding failure must never trigger an automatic retry in identity-only mode.
A separately planned identity-only trial is a different task; record its mode
explicitly. A denied operation is expected behaviour, not a reason to weaken
host verification or protocol checks.

Stop on an unexpected signature, hidden identity, prompt during a denied
operation or cleanup failure. Preserve minimal redacted evidence and report
it privately before continuing that scenario. End only test-owned processes;
remove only fixtures created for the session. The Secretive owner removes their
dedicated test identity if no longer needed.

### Trial record

For each participant retain: anonymous ID, date, OS/architecture, OpenSSH and
agent versions, release/source SHA, documentation revision, executable path,
mode and tasks attempted, elapsed installation/connection times, interventions,
redacted errors, prompt observations, outcome per task, usefulness and repeat-use
intent. Use **PASS**, **FAIL** or **NOT RUN** per task; explain every failure
and missing check. Do not publish raw fingerprints, hostnames, socket paths,
agent listings or connection plans from a participant's real environment.

| Participant | Configuration | Installation / first connection | Problems / repeat-use intent | Status |
|---|---|---|---|---|
| U1 | pending | pending | pending | not recruited |
| U2 | pending | pending | pending | not recruited |
| U3 | pending | pending | pending | not recruited |

Exit criteria: one scoped external expert report and three documented real-user
trials, including failures, missing checks and limitations. Turn observed issues
into focused work items; do not count simulated participants or existing owner
checks as these trials. Prioritize a small key-selection/command-preparation
helper only after the trials show where it is needed. Preserve fail-closed
behaviour and the existing authorization model.
