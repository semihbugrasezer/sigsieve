# Five-minute quickstart (synthetic keys)

See identity filtering work without touching your real keys, your agent or
any remote host. Everything runs in a throwaway directory with a
throwaway `ssh-agent` and two generated keys, then is deleted.

You need `sigsieve` ([install](INSTALL.md)) and OpenSSH (`ssh-agent`,
`ssh-add`, `ssh-keygen`). Run the blocks in one shell, in order.

## 1. A throwaway agent with two synthetic keys

```bash
unset SSH_AUTH_SOCK                 # never use your real agent here
demo=$(mktemp -d); chmod 700 "$demo"; cd "$demo"
eval "$(ssh-agent -s -a "$demo/upstream.sock")"
ssh-keygen -q -t ed25519 -N '' -C demo-allowed -f allowed
ssh-keygen -q -t ed25519 -N '' -C demo-hidden  -f hidden
SSH_AUTH_SOCK="$demo/upstream.sock" ssh-add -q allowed hidden
rm allowed hidden                   # keys now exist only inside the agent
fp=$(ssh-keygen -lf allowed.pub | awk '{print $2}')
SSH_AUTH_SOCK="$demo/upstream.sock" ssh-add -l   # two identities
```

The private key files are deleted on purpose. `ssh-keygen -Y sign`
otherwise falls back to a key file on disk when the agent does not offer
the key, which would make the demo look like a signature passed through.

## 2. Check the policy

```bash
sigsieve doctor --upstream "$demo/upstream.sock" --allow-fingerprint "$fp"
```

Expect `Approved identities: 1/1 available`, `Hidden identities: 1`, and
`Filtering: verified (... non-allowlisted sign request rejected)`, ending
with `Result: all checks passed`.

## 3. Run the filtered socket and use it

```bash
sigsieve run --upstream "$demo/upstream.sock" --allow-fingerprint "$fp" \
  --socket "$demo/filtered.sock" >/dev/null 2>run.log &
sigsieve_pid=$!
sleep 1
SSH_AUTH_SOCK="$demo/filtered.sock" ssh-add -l      # only demo-allowed
echo hello > msg
SSH_AUTH_SOCK="$demo/filtered.sock" ssh-keygen -Y sign -f allowed.pub -n demo msg </dev/null \
  && echo "allowed key: signed"
SSH_AUTH_SOCK="$demo/filtered.sock" ssh-keygen -Y sign -f hidden.pub -n demo msg </dev/null \
  || echo "hidden key: not available"
SSH_AUTH_SOCK="$demo/filtered.sock" ssh-add -D || echo "removing keys: refused"
sigsieve status --socket "$demo/filtered.sock"
```

Expect only `demo-allowed` to be listed and the allowed key to sign. The
hidden key is not offered at all, so `ssh-keygen` reports that it has no key
(step 2's `doctor` is what sends a sign request for a hidden key and
confirms SigSieve rejects it). Key removal is refused; `run.log` shows
`rejected agent operation`. The upstream agent still holds both keys.

## 4. Clean up

```bash
kill "$sigsieve_pid"
SSH_AUTH_SOCK="$demo/upstream.sock" ssh-agent -k >/dev/null
cd / && rm -rf "$demo"
```

## What this did not show

- **Destination binding.** It needs real SSH sessions; it is covered by the
  real-`sshd` tests (`tests/e2e_sshd.rs`) and described in [USAGE.md](USAGE.md).
- **Your agent.** Next, follow the README's
  [first safe check with OpenSSH](../README.md#first-safe-check-with-openssh-linux-or-macos)
  or [first session with Secretive](../README.md#first-session-with-secretive-macos),
  and preview a connection with `sigsieve connect … --dry-run` before
  using it.

SigSieve is experimental and not independently audited. Read the
[security model](SECURITY_MODEL.md) and [limitations](LIMITATIONS.md)
before relying on it.
