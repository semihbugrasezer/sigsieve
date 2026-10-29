# Security findings register

All reviews so far were performed by **internal AI agents in separate
contexts**. That is not an independent external audit; an external audit
remains required before making production-grade assurance claims (see
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)).

Pre-publication revision IDs below identify historical local work; public
history starts from the reviewed Core snapshot. They are not public commit links.

Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO. "Fix" is the commit on this
repository's history; "Test" is the regression test that fails without the
fix (where one exists).

## Summary

| ID | Severity | Title | Status |
|---|---|---|---|
| F-01 | HIGH | `connect`: ControlMaster reuse forwards the unfiltered agent | Fixed |
| F-02 | HIGH | `connect`: indirect ProxyCommand (env/sh -c/wrappers) forwards the unfiltered agent | Fixed (fail closed) |
| F-03 | LOW-MED | `connect`: RemoteForward / config can expose the unfiltered agent (incl. path-spelling bypass) | Fixed |
| F-04 | LOW-MED | `connect`: ProxyCommand children inherit unfiltered `SSH_AUTH_SOCK` | Fixed |
| F-05 | LOW | Idle connections lock out all clients (connection cap) | Fixed (eviction) |
| F-06 | LOW | Eviction could cut in-progress logins / evict a just-read request | Fixed |
| F-07 | LOW | `connect`: signals before ssh start ignored; SIGKILL without grace | Fixed |
| F-08 | LOW | Unquoted `SSH_AUTH_SOCK=` output; terminal escapes in comments; untruncated log names; newline injection in state file | Fixed |
| F-09 | LOW | `PermitLocalCommand`: LocalCommand receives the login agent | Fixed (refused) |
| F-10 | LOW | Forwards silently dropped by ClearAllForwardings | Fixed (warning) |
| F-11 | LOW | `IdentityAgent ${SSH_AUTH_SOCK}` / `$SSH_AUTH_SOCK` configs broke or lost login agent | Fixed |
| F-12 | INFO | Documentation wrongly claimed constrained upstream keys are bypassed | Fixed (docs) |
| F-13 | LOW | Accept loop slept 25 ms when idle (28 ms per new connection) | Fixed |
| F-14 | LOW | Deprecated `GenericArray` API would break `-D warnings` after `cargo update` | Fixed |
| F-15 | MEDIUM (process) | Fuzz seed corpus git-ignored; CI fuzz test would fail | Fixed |
| F-16 | LOW (diagnostic) | RSA binding host key reported as "bad signature" instead of "unsupported" | Fixed |
| F-17 | LOW | Active (non-idle) connections can still saturate an instance | Accepted, documented |
| F-18 | LOW | No timeout on upstream `connect(2)` (Linux full backlog) | Implemented: nonblocking connect + whole-exchange deadline; native Linux regression requires current CI |
| F-19 | LOW | Logging not rate-limited | Fixed: bounded details and suppression summaries; CLI privacy/flood regression |
| F-20 | INFO | Only the socket's immediate parent directory is checked | Hardened: trusted ancestor ownership/modes; extended ACL and same-uid limits remain |
| F-21 | LOW | Destination-binding mode: self-test did not prove binding is active | Fixed |
| F-22 | LOW | Replayed authorized bind+sign sequences trigger upstream signing / Touch ID | Mitigated: shared signing budget + bounded duplicate-attempt cache; protocol-wide prevention not claimed |
| F-23 | INFO | Duplicate bind does not upgrade a forwarding entry to an auth entry | Accepted (matches OpenSSH, fails closed) |
| F-24 | MEDIUM (process) | Deployment-specific strings committed on the unpushed feature branch | Fixed: this release branch (`clean/core-candidate`) carries clean history only |
| F-25 | LOW (supply chain) | RUSTSEC-2026-0387: `crypto-bigint` 0.5.5 timing variability (via p256/p384/p521 0.13). Not exploitable here (verification of public data only), but the audit gate failed | Fixed: upgraded to p256/p384/p521 0.14, ed25519-dalek 3, sha2 0.11 (`crypto-bigint` 0.7.6) |
| F-26 | LOW | P-384/P-521 host-key verification only tested against signatures from the same crates | Fixed: `destination_binding_with_p384_and_p521_host_keys` verifies real OpenSSH signatures (mutation-checked) |
| F-27 | LOW | `release.yml` used `${{ env.HOME }}` (empty), so path remapping was broken | Fixed: remap in a shell step using `$HOME`; exercised by the tag-free rehearsal and the published `fc7484b` tag build. [Release build and native verification](TESTING.md#release-candidate-evidence-2026-10-28) |
| F-28 | INFO | CI installed unpinned cargo-audit/cargo-deny; THIRD_PARTY.md listed crates of another component; no uninstall docs | Fixed |
| F-29 | HIGH | `connect` verified only the destination's ProxyCommand; a wrapper on a ProxyJump (or relay) hop ran with the unfiltered login agent in its environment and could forward it (C-1) | Fixed: every hop verified |
| F-30 | MEDIUM | `Match exec` was detected only from `ssh -G -v` output, i.e. after ssh had run the command during connect's verification | Fixed: user ssh_config (and includes) scanned before ssh runs |
| F-35 | HIGH | CR between an Include keyword and path was treated differently from OpenSSH and hid included Match exec | Fixed in alpha.2: constrained configuration syntax and conservative glob scanning; unit and real-OpenSSH marker regressions |
| F-36 | LOW (protocol) | Non-RSA identities accepted RSA SHA-2 signature flags at the proxy boundary | Fixed: key-type validation before upstream; red/green mock-agent regression; not an authorization bypass |
| F-37 | LOW (policy) | connect accepted explicitly disabled host-key verification | Changed: refuse no/off/false on target and hops; red/green real OpenSSH regression |
| F-38 | LOW (policy) | Legacy RSA/SHA-1 (`ssh-rsa`, flag 0) signing passed through when the upstream allowed it | Fixed: exactly one SHA-2 flag required for RSA, returned algorithm checked; real OpenSSH regression |
| F-39 | LOW | A non-UTF-8 home directory was converted lossily, so the ssh_config pre-scan read a missing path and skipped the real `~/.ssh/config` | Fixed: byte-exact path from the password database; red/green unit regression |
| F-34 | HIGH | Missing or failed initial forwarding bind could expose the ordinary-publickey first-hop exception to a remote client | Fixed: hostbound required for every destination-bound signature; initial failure terminal; regression tests |
| F-33 | LOW (supply chain) | crypto-bigint 0.7.6 was yanked after the earlier local checks; public CI rejected it | Fixed: root and fuzz lockfiles updated to non-yanked 0.7.9 |
| F-32 | HIGH | SSH pre-scan disagreed with OpenSSH on quoted keywords and Include argument delimiters, permitting Match exec during verification | Fixed: conservative keywords, exact space/tab path parsing, UTF-8 validation; regression tests |
| F-31 | HIGH | Review of F-29/F-30: a relay's own `-F` was ignored for its nested hops; hop forwardings were not checked; quoting (`e'x'ec`) hid `Match exec`; X11 forwarding ran xauth with the login agent; unsafe `-F` paths reached ssh's ProxyJump shell command; concurrent stale-socket recovery could have two winners | Fixed (details below) |
| F-40 | LOW (availability) | A slow downstream reader could keep a reply write going indefinitely: SO_SNDTIMEO restarts on every partial transfer | Fixed: nonblocking reply writes under one whole-reply deadline; red/green regression |
| F-41 | LOW (diagnostic) | RSA binding self-test refused by algorithm policy instead of exercising destination enforcement | Fixed: valid RSA/SHA-2 probe; regression catches missing enforcement for RSA, ECDSA and Ed25519 |


### Review scope

Earlier AI reviews checked host-key verification, strict parsing, forwarding
and configuration handling. Later findings F-32 and F-34 show that those
reviews did not establish the absence of high-severity defects. The current
register and executable regression tests supersede earlier review summaries.
None of these reviews is a professional independent audit.

### Internal review of `v0.1.0-alpha.2` source (2026-10-29)

A separate-context AI-assisted review of `src/` at `fc7484be` covered
protocol parsing, keys, policy, destination binding, proxy, resource limits,
upstream and sockets. It reported no new CRITICAL, HIGH, MEDIUM or LOW
finding. Like earlier reviews, it does not establish that no defects remain.
It recorded five INFO observations. None of them is an authorization bypass,
so they receive no F-number:

| Ref | Observation | Classification | Disposition |
|---|---|---|---|
| A-1 | In binding mode an RSA userauth `pkalg` is not tied to the sign-request flags; a mismatched pair costs one upstream signature (possibly one Touch ID prompt) that the server then rejects | Confirmed by code trace | Open, optional hardening; maintainer decision. OpenSSH's agent does not enforce this pairing either |
| A-2 | A session-bind signature is verified before cheaper state checks | Confirmed by code trace | Accepted (bounded by request budgets, F-17). Regression `binds_after_authentication_bind_leave_state_unchanged` pins the state outcome, so the order can be changed safely |
| A-3 | macOS socket creation sets close-on-exec in a second call | Suspected; no concurrent `exec` in the process | Accepted |
| A-4 | Sign responses are checked by algorithm name only | Confirmed; upstream agent is trusted | Accepted (F-38 downgrade check remains) |
| A-5 | `chmod` after `bind` follows symlinks | Out of scope (same-uid attacker, threat model scenario F) | Accepted |

## Details

### F-41 — LOW — RSA binding self-test gave false assurance

After legacy RSA/SHA-1 signing was refused (F-38), the `doctor`/`connect`
unbound allowed-key probe still used flags `0`. With RSA as the first exposed
identity, algorithm validation rejected that probe even when destination
binding was disabled. The self-test could therefore report binding verified
without detecting missing enforcement. This was a diagnostic gap, not an
observed authentication bypass.

The probe now selects `SSH_AGENT_RSA_SHA2_256` for RSA, retaining zero flags
for other key types. `binding_self_test_rejects_missing_enforcement_for_rsa_and_other_keys`
exercises the actual shared self-test against both proxy modes: it must catch
a filtering-only proxy when binding is expected, and pass against a binding
proxy without sending a sign request upstream. It failed before the fix and
passes for RSA, ECDSA P-256 and Ed25519. Agents and keys are synthetic.

### F-40 — LOW — slow reader extends the downstream write timeout

Replies were written with a blocking `write_all` and `SO_SNDTIMEO`. That
timeout bounds each wait for buffer space, and BSD/macOS restarts it whenever
the peer drains a little, so a client reading a few bytes at a time kept one
large reply (for example an identity list with a long comment) in progress
indefinitely. The connection stayed non-idle and could not be evicted, holding
one of the instance's client slots: the same outcome as F-17, without needing
a request. Found by an independent review of the resource code; the first
fix attempt (a deadline around blocking writes) was disproved by the test.
Fix: replies are written nonblocking by `write_frame_until` under one deadline
of `write_timeout` for the whole reply. Regression:
`slow_reader_cannot_extend_the_reply_write_deadline` (250 KB reply, client
reading 1 KB every 50 ms) received the whole reply before the fix and is cut
off after about one second with it.

### F-01 — HIGH — ControlMaster reuse
- **Component:** `src/cli.rs` (`connect`).
- **Preconditions:** connection sharing in ssh_config and an existing master
  with agent forwarding (e.g. started by `ssh -A host`).
- **Impact:** a multiplexed session asks the master to forward *its* agent —
  the unfiltered upstream — while SigSieve's `ForwardAgent` check passed.
- **Reproduction:** start a master with `-o ForwardAgent=yes`, then
  `sigsieve connect` with the same ControlPath; remote `ssh-add -l` showed all
  keys (reproduced against a local sshd with the fix removed).
- **Root cause:** `ssh -G` reports the client's ForwardAgent value, not what a
  master would forward.
- **Mitigation:** `-o ControlPath=none -o ControlMaster=no` first; verify no
  sharing remains in the effective config.
- **Fix:** `750d371`. **Test:** `existing_control_master_with_full_forwarding_is_not_reused` (real sshd; fails without the fix).
- **Residual:** none known for sharing.

### F-02 — HIGH — indirect ProxyCommand
- **Component:** `src/ssh.rs` (`proxycommand_is_ssh_relay`, `verify_ssh_plan`).
- **Preconditions:** a ProxyCommand that starts a nested ssh session indirectly
  (`/usr/bin/env ssh -A …`, `sh -c '…'`, `-W` inside a comment, wrappers) and
  an `IdentityAgent` pointing at the unfiltered agent (Secretive's documented
  setup).
- **Impact:** the nested ssh forwards the full agent to the bastion; setting
  `SSH_AUTH_SOCK` to the filtered socket does not prevent it (reproduced).
- **Root cause:** command-word heuristics are bypassable.
- **Mitigation:** fail closed — refuse every ProxyCommand except a plain
  `ssh … -W …` relay without shell syntax; ProxyJump allowed.
- **Fix:** `84592e3`. **Tests:** `only_plain_ssh_w_relays_are_accepted`, `connect_refuses_unsafe_effective_ssh_configuration`, `connect_with_real_ssh_config_overrides`.
- **Residual:** ProxyCommand users must use ProxyJump or the manual workflow.

### F-29 — HIGH — unverified proxy hops (audit C-1)
- **Component:** `src/ssh.rs` (`verify_proxy_chain`, `ssh_effective_config`).
- **Preconditions:** a ProxyJump (or `ssh -W` relay) hop whose own ssh_config
  has a wrapper ProxyCommand, LocalCommand or KnownHostsCommand, or a
  `Match exec`; and agent forwarding to some host in the user's config.
- **Impact:** each hop runs its own ssh, which reads ssh_config for that host,
  inherits the session environment (including the login agent) and does not
  receive connect's `-o` options. The F-02 check ran on the destination only,
  so a wrapper on the jump host ran inside the session and a nested
  `ssh -A` resolved to `forwardagent yes` with the unfiltered agent
  (reproduced). `--dry-run` reported "all checks passed".
- **Fix:** rebuild every hop's command as ssh does (ProxyJump: ssh.c's
  `ssh [-l] [-p] [-J rest] [-F file] -W '[%h]:%p' host`; relays: getopt-parsed
  ProxyCommand words), evaluate it with `ssh -G -v` and the session
  environment, and require a stdio relay, no local commands and recursively
  verified proxies; refuse KnownHostsCommand and `Match exec` everywhere,
  loops and chains over 8 hops. The relay check now parses ssh's argv, so
  `ssh -l -W bastion nc %h %p` (no relay) is refused, and a relay's `ssh`
  must resolve to the same program connect runs (it is verified with it).
- **Tests:** `connect_verifies_every_proxy_hop` (fails on the old code),
  `verified_proxyjump_still_connects_and_filters` (real sshd hop).
- **Residual:** options ssh does not expose in `ssh -G` (e.g. askpass,
  PKCS#11 providers) are out of scope. (The first fix let `Match exec` run
  once during verification; see F-30.)

### F-31 — HIGH — gaps found by the independent review of F-29/F-30
- **G1:** nested hops of an `ssh -F other -W` relay were evaluated with
  connect's `-F` instead of `other`; a hop2 ProxyCommand ran with the login
  agent. Fix: each hop is evaluated with the `-F` its own ssh reads
  (ProxyJump: the parent's; relay: its own command line's).
- **G3:** a hop's own forwardings (`ClearAllForwardings no` +
  `RemoteForward` of the agent) passed; live, the bastion listed hidden keys.
  Fix: every hop must report `clearallforwardings yes` and no forwards.
- **G5:** the `Match exec` scan stripped only double quotes. Fix: single
  quotes and backslashes too, then a word match (`Match host executor…` is no
  longer a false refusal); any quoted `Include` is refused.
- **G4:** `-X`/`-Y`/`ForwardX11 yes` made ssh run `XAuthLocation` with the
  login agent in `SSH_AUTH_SOCK`. Fix: `ForwardX11=no` is forced and verified.
- **G2:** ssh pastes `-F` unquoted into its ProxyJump shell command. Fix:
  `-F` paths with shell-relevant characters are refused when a hop needs them.
- **Recovery race:** concurrent recovery could remove a newer socket in the
  stat-then-unlink window (two winners, ~3% under load). Fix: check, recover
  and bind run under an exclusive `flock` on the socket directory.
- **Tests:** new cases in `connect_verifies_every_proxy_hop` (fail on the
  previous code); 400 consecutive `tests/socket.rs` runs without failure.
- **Residuals (documented):** `-q`/`-E` in your ssh arguments silence the
  `-v` second line of defence (the pre-scan is the primary check); PKCS#11 /
  security-key provider libraries are trusted like ssh itself.

### F-30 — MEDIUM — `Match exec` executed during verification
- **Component:** `src/sshconfig.rs`, `src/cli.rs` (`connect`).
- **Impact:** `ssh -G` runs `Match exec` commands while evaluating the
  configuration, so connect's verification executed the command once before
  refusing (reproduced with a marker command).
- **Fix:** before any `ssh -G` (the destination and every hop, with that
  hop's `-F`), scan the user configuration and its includes; any `Match`
  line mentioning `exec`, or an include the scan cannot resolve exactly as
  ssh would, is refused. Over-approximating by design.
- **Tests:** `sshconfig::tests::*`; `connect_verifies_every_proxy_hop`
  asserts the marker command never ran (fails with the scan disabled).
- **Residual:** the system-wide ssh_config is trusted (root-owned; its path
  depends on how ssh was built).

### F-03 / F-04 / F-09 / F-10 / F-11 — `connect` configuration leaks
- RemoteForward of the agent (any spelling) → `ClearAllForwardings=yes` first
  and verify no forwards remain (`ce53ee7`).
- ProxyCommand children inheriting `SSH_AUTH_SOCK` → login agent via
  `IdentityAgent=${SIGSIEVE_LOGIN_AGENT}`, `SSH_AUTH_SOCK` = filtered socket
  (`750d371`, `ce53ee7`).
- LocalCommand receives the login agent → `PermitLocalCommand yes` refused
  (`84592e3`).
- Silent forward dropping → warning (`84592e3`).
- `${SSH_AUTH_SOCK}`-based IdentityAgent configs → recognised (`ce53ee7`).
- **Tests:** `connect_refuses_unsafe_effective_ssh_configuration`, `connect_with_real_ssh_config_overrides`, `connect_forwards_only_the_filtered_socket_and_cleans_up`.

### F-05 / F-06 / F-17 — connection exhaustion
- 32 idle connections locked out all clients (reproduced) → evict the
  longest-idle connection (`750d371`); eviction then cut paused logins and
  could evict a just-read request (reproduced) → only evict after ≥ 5 s idle,
  drop requests on evicted connections (`ce53ee7`).
- **Tests:** `idle_connections_cannot_lock_out_new_clients`, `briefly_paused_connections_are_not_evicted`, `busy_connections_are_not_evicted_and_new_client_is_refused`.
- **Residual (F-17):** 32 *active* connections still saturate an instance
  (reproduced); `connect` uses one instance per host. Token budgets now bound
  connection/request churn and signing attempts. FIFO admission limits upstream
  I/O to four exchanges, including a deadline for queued requests. These bounds
  do not identify independent actors behind one forwarded socket or guarantee
  availability to a legitimate client when that endpoint is compromised.

### F-07 / F-08 — lifecycle and output hygiene
- Signals honoured before ssh starts; ssh stopped with SIGTERM then SIGKILL
  (`750d371`). Tests: `terminating_connect_stops_ssh_and_cleans_up`.
- Shell-quoted output, escaped comments, truncated extension names, newline
  rejection (`750d371`). Tests: `run_prints_shell_quoted_socket_path`,
  `doctor_escapes_control_characters_in_comments`.

### F-12 — documentation error
Early docs claimed upstream destination-constrained keys would be bypassed;
reproduction showed OpenSSH's agent refuses them on unbound connections
(fails closed). Corrected (`750d371`); test
`destination_constrained_keys_fail_closed_through_proxy`.

### F-13 — accept latency (found by benchmark)
Idle accept loop slept 25 ms → ~28 ms per new connection. Now waits with
`poll(2)` (`bd9045e`): ~72 µs. Measured in `tests/bench.rs`.

### F-14 / F-15 / F-16 — engineering defects found during hardening
- Deprecated API visible only with a newer lockfile (`ad1c843`).
- Seeds under a git-ignored path; a fresh clone would fail the fuzz test →
  moved to `fuzz/seeds` (`734ceaa`), verified with a fresh-clone test run.
- Misleading binding error for RSA host keys (`4075286`); test
  `forged_or_mismatched_bindings_are_rejected`.

### F-21 — LOW — binding self-test (fresh-context review)
In destination-binding mode, the `doctor`/`connect` self-test only proved
identity filtering. Now it also sends an allowlisted-key sign request on an
unbound connection and requires refusal (refused before the agent is
contacted, so no Touch ID). Test:
`doctor_verifies_destination_binding_without_reaching_the_agent`
(mutation-checked: fails if binding enforcement is removed).

### F-22 — LOW — replay triggers upstream prompts
A malicious remote host with a valid authentication binding to an allowed
destination can replay captured bind+sign sequences; each produces a useless
signature over a stale session but may trigger the upstream agent's user
presence prompt. A shared signing budget now limits attempts to a burst of 32
and refill of 4/s; the upstream's own confirmation policy still applies.
Destination-bound requests are hashed after full authorization (flags excluded)
and attempts remembered across connections, including failed upstream attempts.
Only 256 digests for up to 300 seconds are kept; there is no cached signature
response. New sessions, eviction/expiry and a new instance can bypass duplicate
suppression. This is bounded abuse reduction, not a replay-proof protocol.
Tests: `production_signing_budget_bounds_a_burst_without_changing_authorization`,
`destination_bound_duplicates_do_not_reach_upstream_on_another_connection`.

### F-24 — process — sensitive strings
A real host alias and a real-looking username were committed in two
unpushed commits on the feature branch (a doc line, a test vector and a seed
derived from it). Fixed in the tree (`2a63771`) and the commit scan is now a
hard gate. Public history was created from a clean Core snapshot; the old
internal feature history was not pushed. Do not publish those internal branches.
Existing public history and tags have not been rewritten.

### F-18 / F-19 / F-20 — resource and filesystem hardening

- **F-18:** `socket::connect_until` uses a nonblocking owned descriptor, poll
  and SO_ERROR for EINPROGRESS, and refuses full-queue Linux AF_UNIX EAGAIN
  immediately. `Upstream::request_until` uses the same absolute deadline for
  queue wait, connect, writes and the entire response; partial progress does
  not extend it. Cancellation is checked between nonblocking operations.
  Red/green: `trickling_reply_cannot_restart_the_request_deadline`. Native
  Linux backlog test: `full_unix_listen_queue_cannot_block_upstream_connect`;
  Linux kernel mechanism separately reproduced in a bounded offline container.
  Metadata calls/kernel/scheduler stalls remain outside hard real-time bounds.
- **F-19:** global 16 detail lines/s plus suppression summary; no payloads,
  session IDs or extension names. Regression: `hostile_requests_produce_bounded_logs_without_payloads`.
- **F-20:** private leaf plus canonical ancestor ownership/mode checks,
  permitting trusted sticky temporary directories. Red/green:
  `writable_ancestor_is_refused_even_with_a_private_socket_parent`.
  Portable Unix socket bind has no dirfd-relative API. No global fchdir or new
  privileges were added; same-uid mutation and extended ACL grants remain
  documented limits rather than claiming complete pathname race immunity.

### F-36 / F-37 — protocol and host-verification policy

RSA SHA-2 flags on ECDSA/Ed25519 formerly reached the mock upstream. They now
fail locally, as required by RFC 9987; RSA flags and zero-flag non-RSA signing
remain covered by positive tests. This was a protocol defect, not evidence of
an authorization bypass. Legacy RSA flag-zero SHA-1 was left upstream-dependent
here; F-38 closes it.

`connect` formerly accepted `StrictHostKeyChecking=no/off/false`; the real
OpenSSH dry run demonstrated acceptance. Target and every proxy hop now refuse
it. `ask`, `yes` and trust-on-first-use `accept-new` are preserved. This is an
explicit alpha compatibility change; no SSH setting is silently rewritten.

### F-39 — LOW — lossy home directory in the ssh_config pre-scan

`socket::home_dir` reads the home directory from the password database (as
ssh does for `~`) but converted it with `to_string_lossy`. A home whose name is
not valid UTF-8 became a different path containing U+FFFD; the pre-scan then
found no `~/.ssh/config` there and passed (missing files are skipped, as ssh
does), while ssh read the real file, so a `Match exec` in it went unchecked.
Preconditions: a non-UTF-8 home path in the password database; this is rare
and not attacker-controlled, so it is a fail-open correctness defect rather
than an exploitable bypass. Fix: build the path from the exact bytes
(`OsStr::from_bytes`). Regression: `home_dir_bytes_are_preserved_exactly`
fails on the lossy conversion and passes with the fix.

### F-38 — LOW — legacy RSA/SHA-1 signing

An RSA sign request with flags 0 asks for an `ssh-rsa` (SHA-1) signature, and
real `ssh-agent` produces one; `ssh-keygen -s -U -t ssh-rsa` demonstrated it
through SigSieve. The proxy now derives the one acceptable signature algorithm
from key type and flags (`KeyType::signature_alg`): RSA needs exactly one of
rsa-sha2-256/512, other types none. The upstream reply must use that algorithm,
so an agent that ignores the flags cannot return SHA-1 either, and
destination-bound userauth no longer accepts `ssh-rsa`. There is no silent
fallback or legacy switch; OpenSSH has disabled `ssh-rsa` by default since 8.8.
Compatibility cost: peers accepting only `ssh-rsa` (OpenSSH < 7.2) cannot use
RSA keys through SigSieve. Regressions: `rsa_requires_exactly_one_sha2_flag`,
`signatures_with_an_unrequested_algorithm_are_refused`,
`rsa_userauth_must_name_a_sha2_algorithm` and real OpenSSH
`rsa_sha1_signing_is_refused_while_sha2_works` (upstream control signs SHA-1).

### F-32 — HIGH — SSH configuration tokenization mismatch

OpenSSH accepts a quoted keyword followed immediately by its argument, such
as `"Match"exec`, and keeps `=` and non-space/tab characters inside Include
paths. The earlier scan merged quoted keywords or split those paths,
missing a `Match exec` that SSH then executed while probing configuration.
The verbose-output check detected execution too late. Reproduced with
throwaway configuration files and marker commands.

The scan now refuses quoted/escaped keywords and non-UTF-8 configuration,
handles the optional keyword `=` once, and splits Include paths on the same
ASCII space/tab delimiters as SSH. Regression tests cover direct and included
commands, `=` paths, NBSP and embedded CR/VT/FF. Real OpenSSH tests require
refusal before the marker command runs in both dry-run and connect modes.

### F-33 — LOW (supply chain) — withdrawn transitive dependency

The first public CI run rejected `crypto-bigint 0.7.6` as yanked, while
`cargo audit` reported no known advisory. The [upstream changelog](https://github.com/RustCrypto/crypto-bigint/blob/master/CHANGELOG.md)
records withdrawn 0.7.6–0.7.8 versions and the 0.7.9 correction. Both the Core
and fuzz lockfiles now select 0.7.9. The advisory/license policy is unchanged;
acceptance requires fresh cryptographic verification tests and exact-commit CI.

### F-34 — HIGH — forwarding-context loss in destination binding

The earlier authorization rule allowed ordinary `publickey` when only one
binding was recorded. A failed initial forwarding bind (for example an
unsupported RSA host key) left no binding, and a later valid authentication
bind could replace it. Older forwarding clients can also omit the initial
binding. OpenSSH's client source confirms forwarding can continue after a
bind failure. In the threat-model case where an attacker owns an allowed
host key, the attacker could sign another server's session identifier with
that key and reach the first-hop exception without a host key in the signed
userauth request.

The proxy now requires hostbound authentication for every destination-bound
signature, including single bindings. An initial failed bind is also terminal
for that connection. Existing valid state is retained after a subsequent
failure. Both regression conditions failed before their fixes; valid
single-binding hostbound requests and normal forwarded E2E flows remain tested.

Tests: `failed_bind_disables_signing_and_single_hop_requires_hostbound`,
`failed_initial_binding_cannot_be_replaced_by_an_authentication_bind`, and
`attacker_holding_a_permitted_host_key_cannot_redirect_forwarded_auth`.

### F-35 — HIGH — keyword delimiter mismatch in alpha.1 candidate

OpenSSH accepts a CR between `Include` and its path (also after whitespace or
`=`). The scanner used a narrower keyword delimiter and could skip the real
include. A throwaway `ssh -G` fixture executed the included marker command;
the new unit regression failed on the candidate.

Alpha.2 rejects control characters except LF/tab before parsing and requires
ASCII keywords. Include arguments with quotes, escapes or inline comments
are refused. Wildcard basenames must be ASCII and `?` is over-approximated as
`*` to avoid locale-dependent false negatives. Tests cover the CR variants
and require refusal before any marker runs in dry-run and connect modes.
Hostname canonicalization and state-dependent Match criteria are also refused
on the destination and every hop, keeping effective configuration independent
of DNS/network/final-pass changes. The alpha.1 build was cancelled and no
GitHub Release was published for it.
