# SSH compatibility

Two parts: how SigSieve speaks the **agent protocol**, and how
`sigsieve connect` interprets **ssh client configuration**. Every rule below
is enforced in code; "tested" refers to tests in this repository.

References: [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987),
[OpenSSH PROTOCOL.agent](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent),
[agent-restrict](https://www.openssh.org/agent-restrict.html).

## 1. Agent protocol matrix

Framing: `uint32 length || byte type || contents`. Zero length or
length > 262144 (OpenSSH `AGENT_MAX_LEN`) → close without a reply, no
allocation. A started frame must complete within 10 s; idle connections close
after 300 s.

| Type | Message | Behaviour | Forwarded upstream |
|---|---|---|---|
| 11 | `REQUEST_IDENTITIES` | must be exactly 1 byte; upstream reply strictly parsed and rebuilt with allowlisted, well-formed, de-duplicated keys | yes (listing only) |
| 12 | `IDENTITIES_ANSWER` | only accepted *from* upstream, as above | — |
| 13 | `SIGN_REQUEST` | `string key, string data, uint32 flags`, no trailing bytes; key must be supported and allowlisted; RSA flags ⊆ {`0x02` rsa-sha2-256, `0x04` rsa-sha2-512}, all other key types require zero flags; mode B additionally requires destination authorization (§2); reply must be `SIGN_RESPONSE` with one non-empty signature, else `FAILURE` | only if authorized and admitted by resource budgets; byte-exact |
| 14 | `SIGN_RESPONSE` | validated as above | — |
| 5 / 6 / 28 | `FAILURE` / `SUCCESS` / `EXTENSION_FAILURE` | generated locally | — |
| 17, 25 | add identity (constrained) | `FAILURE` | never |
| 18, 19 | remove identity / remove all | `FAILURE` | never |
| 20, 21, 26 | smartcard / PKCS#11 add/remove | `FAILURE` | never |
| 22, 23 | lock / unlock | `FAILURE` | never |
| 27 | extension: `session-bind@openssh.com` | mode A: `FAILURE`. Mode B: verified and recorded per connection, `SUCCESS` or `EXTENSION_FAILURE` (RFC 9987 §5.8) | never |
| 27 | any other extension (incl. `query`) | `FAILURE` | never |
| 0xff | `restrict-destination-v00@openssh.com` (constraint, part of add) | rejected with the add message | never |
| other | unknown / SSH1-era | `FAILURE` | never |

### Key types (identities)

| Algorithm | Validation | Status |
|---|---|---|
| `ssh-ed25519` | 32-byte key | tested, incl. real `ssh-agent` |
| `ecdsa-sha2-nistp256/384/521` | curve name matches, uncompressed point (65/97/133 bytes) | P-256 tested incl. real agents (Secretive keys are P-256); 384/521 unit-tested |
| `ssh-rsa` | canonical mpints; `e` odd, > 1; `n` odd, 1024–16384 bits; SHA-1 (flag 0) passes through if the upstream allows it | tested incl. `rsa-sha2-512` via real `ssh-keygen -Y sign` |
| `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com` | structural | **untested with hardware** |
| `*-cert-v01@openssh.com` | unsupported | hidden, cannot sign |

### Destination binding (mode B) — host keys and methods

| Item | Behaviour |
|---|---|
| Binding host keys | Ed25519, ECDSA P-256/384/521 verified (real OpenSSH: Ed25519 and P-256 E2E). RSA and certificate host keys: bind fails → restricted signing refused. Use `-o HostKeyAlgorithms=ssh-ed25519,ecdsa-sha2-nistp256` if a server offers RSA first |
| Session id | ≤ 128 bytes; duplicate (same id + key) accepted once; same id with another key refused |
| Bindings per connection | ≤ 16; none after an authentication binding |
| Failed initial binding | terminal for that connection: subsequent binds and restricted signing are refused, even if a remote peer offers a valid binding |
| Userauth methods | **`publickey-hostbound-v00@openssh.com` always required**; ordinary `publickey` is refused, including on single-binding connections |
| Server support | `publickey-hostbound` is advertised by OpenSSH ≥ 8.9 servers. Whether a given service (e.g. GitHub) supports it is **not verified** by this project — test with `connect` before relying on it |
| `restrict-destination` constraints in the upstream agent | not used; keys constrained in an upstream OpenSSH agent refuse to sign through SigSieve (fail closed, tested) |

## 2. `sigsieve connect` and ssh client configuration

`connect` builds `ssh -o ForwardAgent=<filtered socket> -o ControlPath=none
-o ControlMaster=no -o ForwardX11=no -o ClearAllForwardings=yes [-o IdentityAgent=${SIGSIEVE_LOGIN_AGENT}] HOST [ARGS]`.
OpenSSH uses the **first** value it obtains for an option, so these override
ssh_config, `Include`d files, `Match` blocks and later command-line options.
It then runs the exact invocation with `-G` (same arguments, same
environment) against your real configuration and refuses to start ssh unless
all checks pass. `connect --dry-run` performs everything except starting ssh.

| Configuration | Behaviour | Why | Safe alternative |
|---|---|---|---|
| `ForwardAgent` (any value, `-A`, `-o ForwardAgent=…`) | overridden by the filtered socket; effective value verified | only the filtered socket may be forwarded | — |
| `ControlMaster` / `ControlPath` / `ControlPersist` | sharing disabled for the session | an existing master forwards its own (unfiltered) agent — reproduced and regression-tested | none needed; plain ssh outside `connect` keeps sharing |
| `LocalForward` / `RemoteForward` / `DynamicForward`, `-L/-R/-D` | cleared, with a warning listing them | `RemoteForward` can expose any local socket, including the agent, under any path spelling | `sigsieve run` + manual ssh if you need forwards |
| `ProxyJump` (single or multi-hop) | allowed if every hop verifies | each hop is its own `ssh … -W` that reads ssh_config for that host and inherits the session environment but not connect's `-o` options; connect rebuilds each hop's command as ssh does and checks it with `ssh -G`: stdio relay only, no local commands, its own proxies verified the same way (C-1) | — |
| `ProxyCommand ssh … -W …` (plain, no shell syntax, no remote command; `ssh` resolving to the same program connect runs) | allowed if the relay's host verifies | relay only; the relay's own ssh is checked like a ProxyJump hop | — |
| A proxy hop whose ssh_config has a wrapper `ProxyCommand`, `PermitLocalCommand yes` or `KnownHostsCommand` | **refused** | that program runs with the session environment and can forward the unfiltered agent (reproduced in audit, C-1) | fix the hop's configuration, or `sigsieve run` + manual ssh |
| `KnownHostsCommand` (destination or any hop) | **refused** | runs an arbitrary program during the connection | `UserKnownHostsFile` |
| `Match exec` anywhere in your ssh configuration (the `-F` file or `~/.ssh/config`, and everything they `Include`) | **refused before ssh runs** | `ssh -G` would execute it; connect scans the files first (any `Match` line mentioning `exec`; unresolvable `Include`s, quoted/escaped keywords and non-UTF-8 files are refused too) and never runs the command. `ssh -G -v` output is checked as a second line of defence | `Match host`/`Match user` criteria, or a dedicated `-F` file for connect |
| More than 8 proxy hops, hop loops, or hop specs ssh syntax connect cannot model | **refused** | cannot be verified | shorter chain |
| any other `ProxyCommand` (incl. `env ssh`, `sh -c '…'`, wrappers, non-ssh tools such as `cloudflared`) | **refused** | a nested ssh started indirectly can forward the unfiltered agent via `IdentityAgent` + `ForwardAgent`; command strings cannot be verified (bypasses reproduced in review) | `ProxyJump`, or `sigsieve run` + manual ssh after checking the tool never forwards an agent |
| `PermitLocalCommand yes` | **refused** | ssh exports the login agent to `LocalCommand` | disable it for that host |
| `IdentityAgent` set in ssh_config | kept (login uses it) | preserve your login configuration | — |
| `IdentityAgent` unset, `SSH_AUTH_SOCK`, `$SSH_AUTH_SOCK`, `${SSH_AUTH_SOCK}` | login agent passed as `IdentityAgent=${SIGSIEVE_LOGIN_AGENT}`; ssh's `SSH_AUTH_SOCK` set to the filtered socket | ProxyCommand children and `${SSH_AUTH_SOCK}` expansions then see the filtered agent | — |
| `StrictHostKeyChecking` | `no/off/false` refused on destination and hops; `yes`, `ask`, `accept-new` preserved and reported | refuse explicitly disabled verification; `accept-new` still trusts the first key | use a verified known_hosts entry with `yes` |
| option value mentions the upstream/login agent path (any remaining option except `IdentityAgent`) | refused | heuristic backstop | — |
| X11 forwarding (`-X`, `-Y`) | **refused**; `ForwardX11=no` forced and verified | prevents ssh from running xauth with the login agent | plain ssh outside `connect` |
| `CanonicalizeHostname`, `Match canonical`, `Match final`, `Match localnetwork` | **refused** (destination and proxy hops) | configuration must remain the same between `ssh -G` and the connection | static `Host` / `Match host` rules, or a dedicated `-F` file |

### Tools

| Tool | Status |
|---|---|
| `ssh` via `sigsieve connect` | tested end to end (real `ssh`/`sshd`) |
| `scp`, `sftp`, `git` **on the remote host**, using the forwarded agent | standard agent protocol; second-hop `ssh` tested; `scp`/`sftp`/`git` themselves not separately tested |
| local `scp`/`sftp`/`git` through a filtered agent | use `sigsieve run` and pass `-o ForwardAgent=<socket> -o ControlPath=none` (e.g. via `GIT_SSH_COMMAND`); not automated by `connect` |

### Conservative configuration syntax

The pre-scan is deliberately narrower than OpenSSH. Use UTF-8 with LF line
endings and ASCII option names. CRLF, embedded control characters (except
newlines/tabs), quoted/escaped keywords, and quoted, escaped or inline-commented
Include lines are refused. Put Include comments on separate lines. Literal
Unicode paths are supported; wildcard basenames must be ASCII. `?` is scanned
as `*`, so the scan may inspect additional files and refuse a configuration
OpenSSH would accept. Use a dedicated `-F` file when these restrictions matter.
