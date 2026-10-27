# Usage and troubleshooting

[Install from source](../README.md#install-from-source) first. Start with
identity filtering; add destination binding only after checking the
[destination's compatibility](SSH_COMPATIBILITY.md).

## Choose your upstream agent

Run one of the following in the terminal you will use for SigSieve.

**macOS with Secretive:** start Secretive, then select its socket:

```bash
upstream="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"
```

**Linux with OpenSSH ssh-agent:** use the socket of an already running agent:

```bash
upstream="$SSH_AUTH_SOCK"
```

If no agent is running, start one with `eval "$(ssh-agent -s)"`, load a
key you intend to use with `ssh-add /path/to/your/key`, then set `upstream`.
This loads the key into OpenSSH, not SigSieve. A separate agent containing
only that key may already solve your problem; see the
[alternatives](../README.md#do-you-need-it).

List the available public fingerprints locally and choose the one the
remote host may use:

```bash
SSH_AUTH_SOCK="$upstream" ssh-add -l
fp='SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT'
```

Replace the entire placeholder with a fingerprint from the listing. All
hosts and paths in this guide are placeholders. Do not post your unredacted
listing or connection plan in an issue. SigSieve requires an explicit
`--upstream` (or `--secretive`); it never implicitly filters `SSH_AUTH_SOCK`.

## Check, preview, connect

```bash
sigsieve doctor --upstream "$upstream" --allow-fingerprint "$fp"
sigsieve connect build-host --upstream "$upstream" --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
sigsieve connect build-host --upstream "$upstream" --allow-fingerprint "$fp" \
  -- -o StrictHostKeyChecking=yes
```

`doctor` should report `Approved identities: 1/1`, a count of hidden
identities (without printing them), `Filtering: verified` and
`Result: all checks passed`. It lists keys and checks locally rejected
signing probes; it does not request a real-key signature from your agent.
With destination binding it also checks that an unbound allowed-key request
is refused. This is a local self-check, not proof of remote authentication.

`--dry-run` queries the agent, creates and removes a temporary filtered
socket, scans your SSH configuration and runs `ssh -G` to verify the plan.
It does not open an SSH session or sign with a real key. Review the login
agent, filtered `ForwardAgent` and proxy hops before connecting.

Replace `build-host` with your SSH host alias. Verify its host key through a
trusted channel and put it in your known_hosts first; the example deliberately
requires an existing trusted entry. Your login still uses your normal agent;
only the allowlisted identity is forwarded. `connect` disables connection
sharing, port forwarding and X11 for that session. It removes its socket
when SSH exits.

On the remote host, `ssh-add -l` should list only the allowed identity.
Exit the session when finished. In filtering-only mode that identity can
still sign arbitrary data and authenticate to any server that trusts it.

For the Secretive device procedure and the limits of the recorded results,
see [Secretive integration](SECRETIVE_INTEGRATION.md). A successful OpenSSH
agent check does not establish Secretive signing or Touch ID behaviour.

## Using it from ssh_config (stable socket)

For plain `ssh` without `sigsieve connect`, run the filtered agent on a
fixed path and point `ForwardAgent` at it:

```bash
mkdir -m 700 ~/.sigsieve                  # must be private: SigSieve checks
sigsieve run --upstream "$upstream" --allow-fingerprint "$fp" \
  --socket ~/.sigsieve/agent.sock         # keep it running (e.g. a terminal tab)
```

```sshconfig
Host build-host
  # OpenSSH 8.4+: forward this socket only
  ForwardAgent ~/.sigsieve/agent.sock
  # a shared master connection would forward its own, unfiltered agent
  ControlPath none
```

Put any `-o ForwardAgent=…` on the ssh command line first: ssh uses the first
value it sees. `connect` does all of this for you and verifies it.
An annotated configuration is in [examples/ssh_config](../examples/ssh_config).

Check it with `sigsieve status --socket ~/.sigsieve/agent.sock`. If the
process was killed, the next `sigsieve run` on that path takes the socket
over when it can prove it was left by the dead instance (see
[Uninstall and recovery](#uninstall-and-recovery)). There is no launchd or
systemd unit; keep it in the foreground or in a terminal multiplexer.

**Through a bastion:** `ProxyJump` works with `connect`; the bastion needs no
agent and each hop is verified:

```sshconfig
Host build-host
  ProxyJump bastion
```

**Destination binding** (the forwarded key may only log in to servers you
name, onward from the build host). This requires a destination supporting
OpenSSH hostbound authentication; an arbitrary Git/SSH service may not support it:

```bash
ssh-keyscan -t ed25519 destination.example | ssh-keygen -lf -
# Verify this fingerprint through the destination operator's trusted channel.
sigsieve connect build-host --upstream "$upstream" --allow-fingerprint "$fp" \
  --allow-destination "SHA256:REPLACE_WITH_VERIFIED_HOST_KEY_FINGERPRINT" \
  -- -o StrictHostKeyChecking=yes
```

The dated [Git-host measurements](SSH_COMPATIBILITY.md#git-hosting-services)
report GitHub advertising hostbound authentication (end-to-end acceptance
still unverified), and GitLab.com/Bitbucket Cloud not advertising it. Use
identity filtering alone for services that lack it. The **remote host's**
SSH client chooses the destination host key; an RSA host key cannot bind.
See the compatibility guide before changing that remote configuration.

## CLI reference

```text
sigsieve run      [--upstream PATH | --secretive] [--allow-fingerprint FP]... [--allow-destination HK]... [--socket PATH]
sigsieve doctor   [--upstream PATH | --secretive] [--allow-fingerprint FP]... [--allow-destination HK]... [--socket PATH]
sigsieve status   [--socket PATH]          (default: $SSH_AUTH_SOCK)
sigsieve connect  HOST [--upstream PATH | --secretive] --allow-fingerprint FP... [--allow-destination HK]...
                  [--dry-run] [--ssh PATH] [-- SSH_ARGS...]
```

- Lists are repeatable or comma-separated. `SIGSIEVE_UPSTREAM`,
  `SIGSIEVE_ALLOW` and `SIGSIEVE_DESTINATIONS` supply defaults.
  `SSH_AUTH_SOCK` is never an implicit upstream.
- `--upstream-timeout SECS` (default 120) covers Touch ID waits.
- Agent I/O and queue wait share that deadline; cancellation stops initial
  queries and in-flight proxy I/O. Per-session budgets bound connections,
  requests, signing attempts and logs; see [resource limits](RESOURCE_LIMITS.md).
- Exit codes: `0` success, `1` runtime failure or failed check, `2` invalid
  usage/configuration. `connect` returns ssh's exit code once ssh has started.
- `connect` rules for ssh_config (ProxyCommand, ControlMaster, forwards,
  IdentityAgent, …): [docs/SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md).

## Troubleshooting

| Message | Meaning and fix |
|---|---|
| `upstream agent unreachable` | The upstream agent is not running (start Secretive) or the path is wrong. |
| `none of the allowlisted identities is present` | The fingerprint is not in the upstream agent; list keys as shown in [Choose your upstream agent](#choose-your-upstream-agent). |
| `refusing to connect: ProxyCommand … cannot be verified` | `connect` allows only plain `ssh -W` relays and `ProxyJump`. Use `ProxyJump`, or `sigsieve run` + plain ssh after checking the tool never forwards an agent. |
| `unsupported control character` | Use LF line endings in your SSH configuration; move inline Include comments to separate lines. A dedicated `-F` file can avoid unsupported syntax. |
| `… on proxy hop …` | A jump host's own ssh_config runs a program (ProxyCommand wrapper, LocalCommand, KnownHostsCommand). Fix that host's entry. |
| `` `Match exec` would run a command `` | Any `Match … exec` in your ssh config (or an included file) is refused before ssh runs. Use `Match host`/`user`, or pass a dedicated `-F` file. |
| `refusing to replace existing path …` | Another process uses the socket, or SigSieve cannot prove it is a stale one of its own. The message says which; see below. |
| The jump host rejects your key | Hops do not receive `connect`'s `-o` options: put their `User`, `IdentityFile`, `IdentityAgent` in ssh_config. |
| Destination-bound authentication fails | Check that the destination supports hostbound authentication and the **remote** SSH client selected an allowed Ed25519/ECDSA host key, not RSA. See [compatibility](SSH_COMPATIBILITY.md#git-hosting-services); `doctor` cannot check the remote host. |
| More Touch ID prompts than expected | Allowed remote requests can trigger Secretive prompts. Check its per-key setting; stop forwarding if prompts are unexpected. Report a prompt during a known denied-key check privately. |
| `signing budget exhausted or duplicate …` | The session is busy or that destination-bound authentication was already attempted. Start a new SSH authentication session; repeated requests do not automatically retry the agent. |

`sigsieve doctor` checks a setup without connecting; `connect --dry-run`
prints the verified plan.

## Uninstall and recovery

SigSieve installs nothing system-wide: no daemons or launch agents, no
configuration files, and no changes to `~/.ssh/config`, your agent or
Secretive. If you added a manual `ForwardAgent` entry, remove it before
returning to ordinary SSH.

1. Stop running instances with Ctrl-C or `kill -TERM <pid>`. They remove
   their socket and state file on exit. `connect` sessions clean up when ssh
   exits.
2. After a crash or `kill -9`, the socket and state file are left behind.
   The next `sigsieve run --socket` on the same path takes them over only
   if it can prove they belong to the dead instance (the state file records
   that exact socket, its pid is gone and nothing listens), and says so.
   Otherwise it refuses and explains why. To clean up by hand, confirm
   nothing uses the socket, then remove it:

   ```bash
   sigsieve status --socket /path/to/agent.sock   # must report NOT RUNNING
   rm /path/to/agent.sock /path/to/agent.sock.state
   ```

3. Remove the binary: `cargo uninstall sigsieve` (if installed with
   `cargo install`), or delete the file you copied.
4. If you forwarded manually, remove the `ForwardAgent` entry you added to
   ssh_config and stop passing `-o ForwardAgent=<socket>`. Restore any other
   manual edits you made. Test ordinary access with `ssh -a host` (forwarding
   disabled); SigSieve does not change your keys or the upstream agent.
