# Design note: username and path constraints for destination binding

Status: **proposal, not implemented, not approved.** Roadmap items P2-03
(username constraints) and P2-04 (path / intermediate-hop binding). Nothing
here changes current behaviour. Implementation is gated on maintainer
approval and an adversarial review of this design. An independent external
review is strongly preferred before shipping either feature.

Where OpenSSH's native destination constraints (`ssh-add -h`, OpenSSH 8.9+)
apply, that is, keys you can load into OpenSSH's `ssh-agent`, they already
provide both features and remain the recommendation. These extensions matter
only for identities that must stay in another agent, such as Secretive.

## Current behaviour (baseline `src/binding.rs`)

- Each downstream connection keeps a list of verified `session-bind@openssh.com`
  bindings (host key, session id, forwarding flag), at most 16
  (`MAX_BINDINGS`). Every binding's host-key signature over the session id
  is verified; only Ed25519/ECDSA host keys are accepted.
- `Bindings::authorize` looks only at the **last** binding. It must be an
  authentication binding (not forwarding). The signed data must be a
  `publickey-hostbound-v00@openssh.com` userauth request for that session
  id and that host key. The host key fingerprint must be in the allowed
  destination set.
- The username in the userauth request is parsed and **ignored**
  (`let _user = r.string()`).
- Earlier (forwarding) bindings are not checked against any policy, so a
  signature can be obtained for an allowed destination reached through any
  chain of hops.

## P2-03: username constraints

### Threat addressed

A compromised host that holds the forwarded socket can drive its own `ssh`
client to an allowed destination. Today it can log in there as **any** user
that trusts the allowed key. The username is part of the signed userauth
request, and the server authenticates the user named in that request. A
constraint on that field therefore limits which accounts at an allowed
destination the forwarded key can unlock.

### Proposed policy shape

`--allow-destination <host-key-fingerprint>` gains an optional user list,
for example `--allow-destination-user FP=deploy,git` (exact syntax to be
settled in review). Semantics:

- No user list for a destination: current behaviour (any user), so the
  change is opt-in and backwards compatible.
- A user list: the request's username must match one entry **byte for
  byte**. No case folding, no Unicode normalisation, no glob or wildcard in
  the first version.

### Invariants

1. A user constraint can only narrow what is allowed, never widen it. A
   request that fails the host-key checks is refused before the username
   is consulted.
2. The username is taken from exactly the bytes the server will verify (the
   parsed userauth request inside the signed data), never from separate
   client-supplied metadata.
3. Empty usernames, embedded NUL bytes and non-UTF-8 bytes are compared
   exactly. They never match a configured name unless it is byte-identical,
   and configured names are validated at startup (non-empty, no NUL).
4. Policy parsing fails closed: a malformed user list stops startup. It
   never degrades to "any user".
5. Refusals are logged with bounded, escaped output (existing log hygiene;
   F-08 and F-19 in [FINDINGS.md](../FINDINGS.md)).

### Required adversarial tests (before merge)

- Unit: allowed host key with a disallowed user → `Denied`; allowed user →
  allowed; prefix and suffix variants (`deploy` vs `deploy2`, `deplo`); case
  variants; a user containing `\0`; empty user; over-long user (bounded by
  the existing message size cap).
- Unit: a user list on destination A does not affect destination B.
- Real OpenSSH E2E (`tests/e2e_sshd.rs`): `ssh -l allowed` succeeds;
  `ssh -l other` against the same allowed host key fails with the signature
  refused locally.
- Fuzz: extend the `session_bind` and sign-request targets with
  user-constrained policies.
- Threat model and [SECURITY_MODEL.md](../SECURITY_MODEL.md) updated with
  exactly what the constraint does and does not stop. It does not stop use
  of an allowed account, and server-side user mapping is out of scope.

## P2-04: path and intermediate-hop constraints (research only)

### What OpenSSH does

OpenSSH's agent (`ssh-agent.c`, `identity_permitted` /
`permitted_by_dest_constraints`) evaluates **every** hop recorded by
`session-bind`. Each hop is checked against "from host → to host"
constraints, and the first hop's "from" is the local machine. A key
constrained to `bastion > target` therefore cannot be used to reach
`target` through some other host. See the OpenSSH
[agent restriction write-up](https://www.openssh.org/agent-restrict.html).

### What a SigSieve equivalent would need

- A policy expressing allowed edges (`from host key → to host key`, with
  "local" as the root), not just a set of final destinations.
- `authorize` walks the full binding list. Each forwarding binding must be
  an allowed edge from the previous hop. The final authentication binding
  must be an allowed edge from the last forwarding hop and must also
  satisfy the existing hostbound checks.
- A decision on the first binding: it is produced by the local `ssh`
  through the forwarded socket of the *local* client. This depends on how
  `sigsieve connect` and the stable-socket mode feed sessions, and must be
  verified, not assumed.

### Open questions (must be answered before design approval)

1. Can SigSieve distinguish the local first hop from a remote client's
   first bind in both `run` (stable socket) and `connect` modes? F-34 shows
   how subtle the first-hop logic is.
2. How do `ProxyJump` chains (where the local client connects through
   hops without forwarding) appear in the binding list, compared with
   agent forwarding to a bastion followed by `ssh` from it?
3. Which OpenSSH versions record all hops consistently? Older servers and
   clients without `session-bind` must fail closed in path mode.
4. Is the configuration usable? Users would need host-key fingerprints for
   every hop. A `connect`-time helper that derives them from verified
   `known_hosts` entries may be needed, but it would introduce trust in
   `known_hosts` parsing.

### Recommendation

Implement P2-03 first. It is a narrow, local check on data that is already
parsed and verified. Keep P2-04 as research until questions 1–3 are answered
with real OpenSSH traces (synthetic keys, local sshd instances), and until
an independent reviewer has seen the design. Until then, document in
[LIMITATIONS.md](../LIMITATIONS.md) that intermediate hops are not
restricted (already stated) and point users to native OpenSSH constraints
where applicable.
