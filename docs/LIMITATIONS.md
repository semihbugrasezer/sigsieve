# Known limitations

SigSieve is experimental and **not independently audited**. Each item below
is either deliberate (fail closed) or not yet addressed. None is hidden
behind wording that suggests otherwise.

## Security

1. **Allowed keys can be misused while forwarding is active.**
   - Identity filtering only (default): a malicious remote host can use an
     allowed key to authenticate to **any** server that trusts it.
   - Destination binding (`--allow-destination`): it can still authenticate
     **to the allowed destinations** as you. Filtering is never the same as
     preventing use of an explicitly allowed identity.
   Use a key dedicated to one destination and enable per-use authentication in
   Secretive.
2. **Destination binding scope.** Only the final destination host key is
   restricted; intermediate forwarding hops are not ("from-host" constraints
   are not implemented). Usernames are not restricted. Destinations must use
   Ed25519 or ECDSA host keys, and forwarded hops require servers that support
   `publickey-hostbound` (OpenSSH ≥ 8.9); otherwise signing is refused (fails
   closed). Support by third-party services such as GitHub is unverified.
3. **Destination binding forbids non-authentication signing** with allowed
   keys (e.g. `git commit -S` or `ssh-keygen -Y sign` through the forwarded
   agent). This is intentional.
4. **Upstream destination constraints are not used.** Keys added to an
   upstream OpenSSH agent with `ssh-add -h` refuse to sign through SigSieve
   (fails closed; they are still listed if allowlisted).
5. **Same-user compromise** is out of scope: any process running as you can
   use the upstream agent directly or alter SigSieve.
6. **Remote side:** root and your remote user can use the forwarded socket
   while you are connected.
7. **No per-request confirmation** in SigSieve; rely on the upstream agent.
   Signing attempts have a shared budget (32 initially, refilling at 4/s).
   Destination-bound attempts also suppress exact duplicates across clients:
   at most 256 SHA256 digests for up to 300 seconds. This is abuse reduction,
   not protocol-wide replay prevention: new sessions, cache eviction/expiry
   and new instances can trigger further prompts. Failed attempts are remembered;
   no signature response is cached and no failed request is automatically retried.
8. **Logging** emits at most 16 detail lines per second per process, plus a
   suppression summary on the next window or shutdown. Payloads, session IDs
   and untrusted extension names are not logged. A blocked stderr destination
   can still stall a logging thread; log rotation belongs to the caller.

## `sigsieve connect`

- Refuses: any `ProxyCommand` other than a plain `ssh -W` relay, and
  `PermitLocalCommand yes`, `KnownHostsCommand` and `Match exec`, on the
  destination and on every ProxyJump/relay hop (each hop is verified with
  `ssh -G`; chains longer than 8 hops are refused). `Match exec` is detected by
  scanning your ssh configuration (the `-F` file or `~/.ssh/config`, with
  every `Include`) before ssh runs, so the command is never executed; any
  `Match` line mentioning `exec` refuses the whole configuration, and
  `Include`s the scan cannot resolve exactly (quotes, `$`/`%` tokens, `~user`,
  directory wildcards) are refused. The system-wide ssh_config (root-owned)
  is trusted and not scanned. Port forwardings are disabled for
  the session (with a warning). Connection sharing is disabled for the
  session. See [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md) for reasons and
  alternatives.
- Requires OpenSSH with `ForwardAgent=<path>` support (8.4+); verified at
  runtime with `ssh -G`. ProxyJump and relays need OpenSSH 8.7+ (`ssh -G`
  must report `sessiontype`); older clients are refused.
- Configuration scanning accepts LF line endings and ASCII keywords; Include
  comments must be on separate lines. Quoted/escaped Include paths and
  non-ASCII wildcard patterns are refused; `?` is scanned conservatively as `*`.
- X11 forwarding is off in `connect` sessions (`-X`/`-Y` are refused): ssh
  runs `xauth` with the login agent in its environment.
- `-F` paths must be simple (letters, digits, `/._-`) when a ProxyJump hop
  needs them; quoted `Include`s are refused.
- PKCS#11 and security-key provider libraries configured in ssh_config are
  trusted like ssh itself. Passing `-q` or `-E` to ssh silences the `-v`
  backstop for `Match exec`; the pre-scan of your configuration is the
  primary check.
- Hostname canonicalization and state-dependent Match criteria (`canonical`,
  `final`, `localnetwork`) are refused, including on proxy hops.
- Disabled host verification (`StrictHostKeyChecking=no/off/false`) is refused
  on the destination and every hop. `accept-new` remains trust on first use;
  it is not proof that an unknown host key was independently verified.
- The `ssh -G` check and the real run are two invocations; a same-user change
  to ssh_config in between is out of scope. `ssh -G` does not evaluate DNS
  canonicalization or `Match exec` exactly; the overriding options cannot be
  changed by such blocks and forwards are cleared regardless.
- A wrapper ProxyCommand that starts ssh internally cannot be inspected; that
  is why such ProxyCommands are refused rather than analysed.
- `SIGSIEVE_LOGIN_AGENT` (your login agent path) is visible to ssh's child
  processes; local processes running as you can reach that agent anyway.

## Functional

- OpenSSH certificates are not supported as identities (hidden, cannot sign).
- RSA keys < 1024 bits are rejected. SHA-1 `ssh-rsa` signatures (flag 0) pass
  through if the upstream allows them.
- `sk-` (FIDO) identities are parsed but untested with hardware.
- No agent extensions are supported except verified `session-bind` in
  destination-binding mode.
- `kill -9`, a crash or power loss leaves the socket (and for `run` its
  `.state` file). `run` on the same path takes them over only with proof they
  are the dead instance's (state records the socket's dev:inode, pid gone,
  nothing listening); otherwise it refuses with the reason. A state file from
  a version without the socket identity cannot prove this: remove it by hand
  after `sigsieve status --socket PATH` reports `NOT RUNNING`.
- One instance serves at most 32 concurrent connections. When full, the
  connection idle longest (≥ 5 s) is evicted; otherwise new connections are
  refused. An allowed client that keeps all slots busy locks out other clients
  of that instance (`connect` uses one instance per host, limiting this to the
  attacker's own session).
- Upstream connections and nonblocking frame I/O share one absolute deadline
  (default 120 s), including queue wait. At most four upstream exchanges run
  concurrently; waiting requests are FIFO and bounded by the client cap.
  SIGINT/TERM/HUP interrupt initial agent queries; stopping a proxy cancels
  its in-flight I/O. Filesystem metadata calls, kernel stalls and scheduling
  delays cannot be given hard real-time deadlines by this implementation.
- Defaults also bound accepted connections to a burst of 64/refill 64 per
  second, requests to 1024/refill 1024 per second globally, and 128/refill 128
  per second per connection. An exhausted request budget closes the client;
  an exhausted signing budget returns FAILURE. Clients behind one forwarding
  socket share these budgets; an attacker can still deny that session service.
- Socket ancestors must belong to root/current uid and reject group/other
  write access unless sticky; the leaf parent must belong to the current uid
  and reject all group/other write access. POSIX mode checks do not assess
  arbitrary extended ACL grants. Same-uid replacement remains out of scope.
- `status` treats a reused PID as running (it also checks that the socket
  answers and exposes only recorded keys).
- Socket paths must fit the OS limit (104 bytes on macOS).

## Verification gaps (see RELEASE_CHECKLIST.md)

- Linux x86_64 passed a previous CI run. Only a green CI run for the exact
  release commit establishes current platform coverage; see the release notes.
- Coverage-guided fuzzing (cargo-fuzz on nightly) has not been run; only
  stable mutation fuzzing and uninstrumented libFuzzer runs.
- No independent external security review.
- Real Secretive testing is limited to one user-assisted session (listing,
  hidden-key refusal, connect to one host).
