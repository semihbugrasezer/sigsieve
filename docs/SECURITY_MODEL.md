# Security model

This document states exactly what SigSieve guarantees, in which mode, and
which executable test backs each claim. Anything not listed here is not a
guarantee. Read [THREAT_MODEL.md](THREAT_MODEL.md) for attackers and
[LIMITATIONS.md](LIMITATIONS.md) for what is out of reach.

> SigSieve has **not** been independently audited. "Tested" means an
> automated test in this repository exercises the property and fails if it
> breaks (several were additionally mutation-checked: the test was shown to
> fail with the protection removed).

## Two modes

| | Identity filtering (default) | Destination binding (`--allow-destination`) |
|---|---|---|
| Which keys the remote side can list | allowlisted only | allowlisted only |
| Which keys can sign | allowlisted only | allowlisted only |
| What an allowed key can sign | **anything** the remote host asks for | only SSH user-authentication requests for a session cryptographically bound to an allowed destination host key |
| Where an allowed key can authenticate | **any** server that trusts it, while you are connected | only the allowed destination(s) |
| `session-bind@openssh.com` | rejected (not forwarded) | verified and recorded per connection (not forwarded) |
| Works with servers lacking `publickey-hostbound` | yes | no; hostbound authentication is required for every signature |

Destination binding is enforced **inside SigSieve**, so it works with upstream
agents that have no destination-constraint support (for example Secretive).
It mirrors the checks of OpenSSH's own `ssh-agent` (`ssh-agent.c`:
`process_ext_session_bind`, `parse_userauth_request`, `identity_permitted`,
`process_sign_request2`), verified against
[PROTOCOL.agent](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent)
and [agent-restrict](https://www.openssh.org/agent-restrict.html).

### Why destination binding holds against a malicious forwarding host

1. Every binding is verified: the destination's host key must have signed the
   session identifier, which is the server signature from the SSH key
   exchange. Only a party that completed a key exchange with that server holds
   such a signature.
2. A signature is produced only for a well-formed userauth request whose
   session identifier equals the latest (authentication) binding, so it is
   only valid inside that one SSH session with that one server.
3. On forwarded connections the request must be `publickey-hostbound`, which
   embeds the server host key in the signed data; the destination server
   rejects a request carrying another key. This stops an attacker who holds
   the private host key of some permitted host (root on the forwarding host
   always holds that host's key) from forging bindings for other sessions.
4. Nothing may be bound after an authentication binding, and a sign request
   on a connection whose last binding is a forwarding hop is refused.

## Invariants and evidence

Status legend: **Tested** = automated test; **Tested (E2E)** = additionally
exercised over real OpenSSH (`ssh` → throwaway `sshd`); **Partial** = covered
with stated gaps; **N/A** = not a SigSieve property.

### Identity isolation

| # | Invariant | Status | Evidence |
|---|---|---|---|
| 1 | A remote client never discovers a non-allowlisted public identity | Tested (E2E) | `exposes_only_the_approved_identity_among_three`, `comments_are_never_used_for_authorization`, `upstream_malformed_identity_with_allowlisted_fingerprint_is_hidden`, `forwarded_agent_is_filtered_end_to_end` |
| 2 | Non-allowlisted identities never sign | Tested (E2E) | `hidden_identity_cannot_sign_even_with_known_public_key`, raw-protocol attacker in `forwarded_agent_is_filtered_end_to_end`, property test `upstream_only_sees_authorized_traffic` |
| 3 | Blocking does not depend on hiding identities | Tested | sign authorization is computed from the request's key blob on every request: `hidden_identity_cannot_sign_after_enumeration_on_same_connection` |
| 4 | Direct `SIGN_REQUEST` for a hidden key is denied | Tested (E2E) | raw `SIGN_REQUEST` with flags 0/2/4 for each hidden key in `forwarded_agent_is_filtered_end_to_end` |
| 5 | Allowed identities work without exposing others | Tested (E2E) | `authorized_signing_is_delegated_for_each_key_type`, allowed sign + second hop in E2E |
| 6 | Certificates, alternative encodings, duplicates, unusual flags do not bypass | Tested | `identity_substitution_and_encoding_tricks_are_rejected`, `malformed_sign_requests_are_not_forwarded`, `duplicate_allowlist_entries_and_duplicate_upstream_keys_appear_once`, `rejects_malformed_and_unsupported_blobs` |
| 6a | No legacy RSA/SHA-1 signature passes: RSA requests need exactly one SHA-2 flag, other key types none, and the returned signature must use the requested algorithm | Tested (real OpenSSH) | `signature_algorithms_exclude_rsa_sha1_and_foreign_flags`, `rsa_requires_exactly_one_sha2_flag`, `signatures_with_an_unrequested_algorithm_are_refused`, `rsa_userauth_must_name_a_sha2_algorithm`, `rsa_sha1_signing_is_refused_while_sha2_works` |

### Agent integrity

| # | Invariant | Status | Evidence |
|---|---|---|---|
| 7 | No add/remove/lock/unlock/PKCS#11/constrained add | Tested (E2E) | `agent_mutations_are_rejected_and_never_forwarded`, `ssh-add -D/-d` in E2E and `real_ssh_agent_listing_signing_and_mutations` |
| 8 | Unknown operations fail closed | Tested | `unknown_operations_are_rejected`, `non_forwarded_operations_fail_locally` (all 256 types) |
| 9 | No extension creates an alternate signing path | Tested (E2E) | `extensions_including_session_bind_are_rejected_and_not_forwarded`; in binding mode `session-bind` only adds verified state that can only *restrict* signing |
| 10 | Malformed input never panics, allocates unboundedly, hangs or bypasses | Tested | frame cap before allocation, deadlines, proptests, `tests/fuzz_corpus.rs`, libFuzzer smoke runs (see [TESTING.md](TESTING.md)) |

### Connection isolation

| # | Invariant | Status | Evidence |
|---|---|---|---|
| 11 | Each connection is evaluated under the configured policy; binding state is per connection | Tested | bindings live in the per-connection loop; `destination_binding_end_to_end` uses separate connections per hop |
| 12 | Multiplexing/forwarding configuration cannot expose the unfiltered agent through `connect` | Tested (E2E) / Partial | `existing_control_master_with_full_forwarding_is_not_reused` (fails without the fix), `connect_refuses_unsafe_effective_ssh_configuration`, `connect_with_real_ssh_config_overrides`. Gap: see [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md) |
| 13 | A compromised remote host cannot reach the upstream socket | Tested (E2E) | the remote side only receives the filtered socket; `ForwardAgent` verified with `ssh -G` |
| 14 | Temporary sockets are owner-only, securely created and removed | Tested | `default_runtime_dir_is_private_and_cleaned_up`, `run_filters_and_cleans_up_on_sigterm_and_sigint`, `terminating_connect_stops_ssh_and_cleans_up`, `ssh_crash_still_cleans_up_and_reports_failure` |
| 15 | Cleanup never removes unrelated files or sockets | Tested | `replaced_socket_is_not_deleted_on_cleanup`, `existing_socket_is_never_replaced`, `symlink_at_socket_path_is_refused`, `unexpected_files_keep_owned_runtime_dir_in_place`, `killed_process_leaves_socket_that_is_never_auto_deleted` |

### Secretive protection

| # | Invariant | Status | Evidence |
|---|---|---|---|
| 16 | Denied requests are not forwarded upstream | Tested (E2E) | mock-agent receive logs in every denial test; `upstream_only_sees_authorized_traffic` |
| 17 | Denied requests do not trigger Touch ID | Tested (by 16); real-device confirmation pending | follows from 16 (denied requests never reach the agent). A real Secretive run on 2026-10-24 refused raw hidden-key sign requests; whether any prompt appeared has not yet been confirmed by the device owner |
| 18 | Legitimate local Secretive login keeps working | Tested (E2E) + real check | login-port test authorizes only a hidden key, so login must use the unfiltered login agent; real user-assisted run against a CI host passed |
| 19 | No private key material is exported, persisted or copied | By construction | SigSieve has no code path that requests or handles private keys; the protocol messages that carry them (types 17/25) are rejected |
| 20 | Logs do not expose sensitive content and are bounded | Tested | logs contain operation types, public key / host key fingerprints of *denied* requests and denial reasons; never signed data, session identifiers, signatures or untrusted extension names. Hidden keys appear only if the requester supplied them. At most 16 detail lines per second, with a suppression summary (F-19): `hostile_requests_produce_bounded_logs_without_payloads`, `logging_bounds_details_and_aggregates_suppression` |

### Destination binding (binding mode)

| Property | Status | Evidence |
|---|---|---|
| Forged / mismatched bindings rejected (every supported host key type) | Tested | `forged_or_mismatched_bindings_are_rejected`, `mutated_valid_bind_never_verifies`, forged bind from remote in E2E |
| Real OpenSSH host-key signatures verify for Ed25519, P-256, P-384, P-521 | Tested (E2E) | `destination_binding_end_to_end`, `destination_binding_with_p384_and_p521_host_keys` |
| OpenSSH binding state rules (duplicates, rebind after auth, limits) | Tested | `binding_state_rules_match_openssh` |
| Only bound userauth to an allowed destination is signed | Tested (E2E) | `authorization_accepts_only_bound_userauth_to_allowed_destination`, `destination_binding_end_to_end` (allowed host succeeds, other host refused) |
| Attacker holding a permitted host key cannot redirect forwarded auth | Tested | `attacker_holding_a_permitted_host_key_cannot_redirect_forwarded_auth` |
| Arbitrary data never signed by restricted keys | Tested (E2E) | `random_sign_data_is_never_authorized`, `ssh-keygen -Y sign` and raw signing in E2E |
| Mutation check | Done | removing the destination check or bind-signature verification makes `destination_binding_end_to_end` fail; removing the session-id check makes unit tests fail |

## Trust boundaries

```text
 trusted                         | untrusted
 local user account, kernel,     | everything reachable through the
 upstream agent (Secretive),     | forwarded agent socket: remote host
 local ssh client (first hop),   | (root and your account), its processes,
 SigSieve process                | further hops, raw protocol clients
```

The local ssh client is trusted to forward the configured filtered socket and
perform host-key verification honestly. Destination-bound signatures require
hostbound authentication even if the initial forwarding binding is missing.
SigSieve does not defend against code running as your local user (see THREAT_MODEL.md, Scenario F).
