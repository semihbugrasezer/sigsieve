# Threat model

Status: written by the project authors for v0.1.0-dev. **Not independently
reviewed.** Guarantees and their evidence are in
[SECURITY_MODEL.md](SECURITY_MODEL.md); residual limits in
[LIMITATIONS.md](LIMITATIONS.md); the findings register in
[FINDINGS.md](FINDINGS.md).

## System

```text
[upstream agent] <--unix--> [SigSieve] <--unix--> [local ssh] ==SSH==> [remote host] --> [further hops]
 (Secretive …)               (proxy)    filtered    (ForwardAgent=    (forwarded agent
                                        socket       filtered socket)  socket, untrusted)
```

**Assets.** (1) the ability to sign with *hidden* keys; (2) the ability to use
an *allowed* key beyond its intended destination; (3) knowledge of hidden
identities; (4) integrity of the upstream agent's key set and lock state;
(5) the user's normal SSH access; (6) the local filesystem (no deletion or
replacement of files SigSieve did not create).

**Trust assumptions.** The local user account, kernel, upstream agent and
local ssh client are not compromised. The allowlist and destination list
reflect the user's intent. The user verifies host keys (SSH's own job).

## Attackers and what SigSieve does about them

Each entry: capability → protection → residual risk. "Mode B" = destination
binding enabled; "mode A" = identity filtering only.

### Malicious remote host administrator (root on the VPS)

Full control of the remote side: reads the forwarded socket, runs any client,
holds the remote host's private host key, can open many agent channels while
you are connected.

- *Protection:* hidden keys are invisible and unusable (invariants 1–6);
  mutations and extensions refused (7–9). Mode B: the allowed key can only
  authenticate to allowed destination host keys, and only through real SSH
  sessions; arbitrary data cannot be signed; forged bindings (even using the
  VPS's own host key) are rejected or useless (hostbound requirement).
- *Residual:* mode A: the allowed key can be used anywhere it is trusted
  (confused deputy). Mode B: the attacker can still authenticate **to the
  allowed destinations** as you while you are connected. Both modes: denial
  of service against this SigSieve instance; learning the allowed public key.

### Compromised remote account / malicious process on the remote host

Same as above minus root; anyone who can open the forwarded socket (your
remote user and root) has the same power over the agent. Same protections and
residuals.

### Raw SSH agent protocol client

Sends arbitrary frames: truncated, fragmented, oversized, zero-length, smuggled
trailing messages, unknown types, random bytes, slow trickles.

- *Protection:* bounds-checked parser without `unsafe`; 256 KiB frame cap
  checked before allocation; per-frame deadline (10 s) independent of byte
  rate; idle limit (300 s); malformed → `FAILURE`; unframeable → close.
- *Evidence:* unit/property tests, stable mutation fuzzing (~800k inputs per
  run at 50k iterations), libFuzzer smoke runs (~146M executions,
  uninstrumented), raw attackers in real SSH sessions.

### Unauthorized signing with a known public key

Public keys are often public (e.g. `https://github.com/<user>.keys`).
Authorization uses the fingerprint of the key blob *in the request*, on every
request; listing history is irrelevant. Tested directly and over real SSH.

### Repeated and concurrent signing requests

No state is shared between downstream connections except the immutable
policy. Upstream requests use a fresh connection each and are never retried
(a retry could cause a second Touch ID prompt — tested). Concurrency is capped
(32 connections); excess connections are refused or evict a connection idle
≥ 5 s. Residual: an allowed client can keep all slots busy.

### Agent extension manipulation

All extensions are answered locally and never forwarded. In mode B,
`session-bind@openssh.com` is verified (host key signature, size limits,
duplicate/rebind rules) and can only *narrow* what may be signed. Signing is
refused without a valid binding. A failed bind does not discard bindings
already verified on that connection (matching OpenSSH).

### Session binding replay and confusion

- Replaying a captured binding on another connection gives no capability: a
  signature is only usable inside the SSH session whose identifier was bound,
  which the attacker does not control unless they made that session.
- Binding a session identifier with a different host key on the same
  connection is refused; binding after an authentication bind is refused.
- An attacker holding a permitted host key (e.g. the VPS key) can create
  valid-looking bindings for other sessions, but forwarded requests must
  embed the host key (hostbound), which the real destination checks.
- Residual: if an *allowed destination's* host key is compromised, that
  destination can be impersonated; host key security is SSH's job.

### Multi-hop agent forwarding

Each hop's ssh client appends a forwarding binding; SigSieve requires the last
binding to be an authentication binding to an allowed destination and all
earlier ones to be forwarding bindings. Intermediate hops are not themselves
restricted (no "from-host" constraints) — see LIMITATIONS.

### SSH connection multiplexing (ControlMaster/ControlPersist)

An existing master forwards *its own* agent. `connect` passes
`ControlPath=none`/`ControlMaster=no` first (first value wins) and verifies the
effective configuration; real-sshd regression test fails without the fix.

### ProxyCommand / ProxyJump wrappers, nested ssh, LocalCommand

A nested ssh reads your ssh_config and may forward the unfiltered agent via
`IdentityAgent` + `ForwardAgent`, regardless of `SSH_AUTH_SOCK`. `connect`
refuses every ProxyCommand except a plain `ssh … -W …` relay (ProxyJump) and
refuses `PermitLocalCommand yes`, `KnownHostsCommand` and `Match exec`. Every
proxy hop starts its own ssh that reads ssh_config for that host; connect
rebuilds each hop's exact command and applies the same checks to it, so a
wrapper on a jump host is refused too (C-1, F-29). All forwardings are cleared. Rationale and
alternatives: [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md).

### Environment variable manipulation / `SSH_AUTH_SOCK` substitution

- SigSieve never uses `SSH_AUTH_SOCK` as its upstream (explicit `--upstream`
  or `--secretive` only; tested).
- `connect` points ssh's `SSH_AUTH_SOCK` at the filtered socket and passes the
  login agent via `IdentityAgent=${SIGSIEVE_LOGIN_AGENT}`.
- Remote-side environment is outside SigSieve's reach; the remote host only
  ever receives the filtered socket.
- A local process that can change your environment runs as you (Scenario F).

### Symlink and Unix socket races, socket substitution

- Downstream: bind only inside a directory owned by you and not
  group/world-writable; existing paths (incl. symlinks) refused, never
  unlinked; cleanup unlinks only the inode created; per-connection peer uid
  check.
- Upstream: must be a socket owned by you; after connecting, the peer uid of
  the agent process must be yours (defeats races with other users).
- Residual: same-user processes can replace the upstream socket.

### Denial of service

Frame cap, deadlines, connection cap with idle eviction, poll-based accept,
no unbounded queues; ~3200 short-lived connections without descriptor leaks
(tested). Residual: one instance can be saturated by an allowed client; use
one instance per host (`connect` does).

### Host key substitution / trust failures

SigSieve does not change host key verification; `connect --dry-run` reports
`StrictHostKeyChecking` and warns for `no`/`accept-new`. In mode B a forged
destination cannot produce a valid binding for an allowed host key.

### Unexpected termination, partial failures, cleanup races

SIGINT/SIGTERM/SIGHUP clean up; ssh is stopped with SIGTERM then SIGKILL;
ssh crashes are handled (tested). SIGKILL of SigSieve leaves the socket and
state file, and `status` reports `NOT RUNNING`. A later `run` on the same path
replaces them only with proof they are the dead instance's: the socket is ours
in a private directory, the private state file records its dev:inode and a pid
that no longer exists, and connecting is refused; removal re-checks inodes, so
concurrent starts have one winner. Anything else is never removed.

### Local-user compromise and same-UID attacks — Scenario F

Code running as your local user (or root) can use the upstream agent directly,
replace SigSieve, change its arguments or your ssh_config. **Out of scope.**
SigSieve reduces what *remote* hosts can do; it is not a local sandbox.

## Explicitly not defended

- Misuse of an allowed key: anywhere it is trusted (mode A), or at the allowed
  destinations (mode B), while forwarding is active.
- Compromise of the upstream agent, the local machine or account.
- Compromise of an allowed destination's host key.
- Remote-side protection of the forwarded socket.
- Isolation of CI jobs or GitHub Actions workloads (SigSieve complements, not
  replaces, runner isolation).
- Timing side channels (they reveal at most whether a request was
  well-formed or allowed).
