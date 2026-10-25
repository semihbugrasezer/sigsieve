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
| F-18 | LOW | No timeout on upstream `connect(2)` (Linux full backlog) | Open, documented |
| F-19 | LOW | Logging not rate-limited | Open, documented |
| F-20 | INFO | Only the socket's immediate parent directory is checked | Open, documented |
| F-21 | LOW | Destination-binding mode: self-test did not prove binding is active | Fixed |
| F-22 | LOW | Replayed authorized bind+sign sequences trigger upstream signing / Touch ID | Accepted, documented |
| F-23 | INFO | Duplicate bind does not upgrade a forwarding entry to an auth entry | Accepted (matches OpenSSH, fails closed) |
| F-24 | MEDIUM (process) | Deployment-specific strings committed on the unpushed feature branch | Fixed: this release branch (`clean/core-candidate`) carries clean history only |
| F-25 | LOW (supply chain) | RUSTSEC-2026-0387: `crypto-bigint` 0.5.5 timing variability (via p256/p384/p521 0.13). Not exploitable here (verification of public data only), but the audit gate failed | Fixed: upgraded to p256/p384/p521 0.14, ed25519-dalek 3, sha2 0.11 (`crypto-bigint` 0.7.6) |
| F-26 | LOW | P-384/P-521 host-key verification only tested against signatures from the same crates | Fixed: `destination_binding_with_p384_and_p521_host_keys` verifies real OpenSSH signatures (mutation-checked) |
| F-27 | LOW | `release.yml` used `${{ env.HOME }}` (empty), so path remapping was broken | Fixed: remap in a shell step using `$HOME` (not yet exercised) |
| F-28 | INFO | CI installed unpinned cargo-audit/cargo-deny; THIRD_PARTY.md listed crates of another component; no uninstall docs | Fixed |
| F-29 | HIGH | `connect` verified only the destination's ProxyCommand; a wrapper on a ProxyJump (or relay) hop ran with the unfiltered login agent in its environment and could forward it (C-1) | Fixed: every hop verified |
| F-30 | MEDIUM | `Match exec` was detected only from `ssh -G -v` output, i.e. after ssh had run the command during connect's verification | Fixed: user ssh_config (and includes) scanned before ssh runs |
| F-33 | LOW (supply chain) | crypto-bigint 0.7.6 was yanked after the earlier local checks; public CI rejected it | Fixed: root and fuzz lockfiles updated to non-yanked 0.7.9 |
| F-32 | HIGH | SSH pre-scan disagreed with OpenSSH on quoted keywords and Include argument delimiters, permitting Match exec during verification | Fixed: conservative keywords, exact space/tab path parsing, UTF-8 validation; regression tests |
| F-31 | HIGH | Review of F-29/F-30: a relay's own `-F` was ignored for its nested hops; hop forwardings were not checked; quoting (`e'x'ec`) hid `Match exec`; X11 forwarding ran xauth with the login agent; unsafe `-F` paths reached ssh's ProxyJump shell command; concurrent stale-socket recovery could have two winners | Fixed (details below) |


### Fresh-context review (4th internal review) — summary

A new reviewer agent with no prior context audited the destination-binding
branch (read-only; probes against its own agents/sshd). Result: **no critical
or high findings**. It specifically examined the single-hop plain-`publickey`
exception (a forged single auth binding would let a plain-publickey
signature be replayed elsewhere) and showed it is unreachable from a remote
attacker: the local ssh client always prepends its forwarding binding to every
forwarded agent connection, so any attacker-influenced connection has ≥ 2
bindings and must use `publickey-hostbound` (confirmed by the E2E raw
attacker log "sign attempted on a forwarding hop"). It also confirmed the
crypto verification details (Ed25519 `verify_strict`, per-curve ECDSA hashes,
strict mpint decoding, algorithm/key-type matching) and that the tests are not
vacuous.

## Details

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
  (reproduced); `connect` uses one instance per host.

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
presence prompt. SigSieve adds no rate limiting; per-use confirmation stays in
the upstream agent. Documented in LIMITATIONS.

### F-24 — process — sensitive strings
A real host alias and a real-looking username were committed in two
unpushed commits on the feature branch (a doc line, a test vector and a seed
derived from it). Fixed in the tree (`2a63771`) and the commit scan is now a
hard gate. **Before any publication, the branch history must be rewritten or
squashed** (requires maintainer approval); `main` is clean.

### F-18 / F-19 / F-20 — open, low
Documented in [LIMITATIONS.md](LIMITATIONS.md); candidates for future work
(non-blocking connect with deadline, log rate limiting, ancestor checks or
directory-fd based binding).

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
