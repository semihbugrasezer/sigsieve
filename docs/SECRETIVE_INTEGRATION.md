# Using SigSieve with Secretive (macOS)

[Secretive](https://github.com/maxgoedjen/secretive) stores SSH keys in the
Secure Enclave (ECDSA P-256) and serves them through an SSH agent socket.
SigSieve sits in front of that socket. It never sees private keys, and every
signature is still produced inside the Secure Enclave by Secretive.

## Socket location

```text
~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
```

`--secretive` uses that path; `--upstream PATH` overrides it.

## Touch ID behaviour

Secretive decides when to ask for authentication, based on each key's
settings ("Require authentication" when the key was created) and macOS's own
authentication caching. SigSieve does not change this:

- A request for a hidden key is rejected by SigSieve **before** Secretive is
  contacted, so it never triggers a prompt and is never signed.
- A request for an allowed key is passed to Secretive unchanged. It may or
  may not prompt, depending on Secretive.
- `doctor` and `connect` self-tests only list keys and send a sign request
  for a *synthetic* key that SigSieve itself rejects. They do not cause
  Secretive prompts.

For forwarding, use a key that requires authentication, so each remote
signature needs your presence.

## Automated controlled check

`scripts/agent-integration-check.sh` runs the procedure below in one go. It
writes only to a private temporary directory, prints only the allowed key's
fingerprint plus counts of the others, and changes no configuration:

```bash
cargo build --release
scripts/agent-integration-check.sh --sigsieve target/release/sigsieve \
  --allow SHA256:<allowed>                 # default upstream: Secretive
# add --sign-allowed to also sign a test message with the allowed key
# (Touch ID may prompt). No prompt is expected without it.
```

If Secretive prompts for authentication during the hidden-key step, deny it
and report a bug: those requests must be rejected by SigSieve before they
reach Secretive.

## Controlled verification procedure (manual)

Run these yourself. They change no configuration: no `~/.ssh/config` edits,
no Secretive settings, no server changes.

1. **Public listing only** (no signing):

   ```bash
   S=~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
   SSH_AUTH_SOCK=$S ssh-add -l          # note the fingerprint to allow
   sigsieve doctor --secretive --allow-fingerprint SHA256:<allowed>
   ```

   Expect `Approved identities: 1/1`, `Hidden identities: N (not shown)`, and
   `Filtering: verified`.

2. **Filtered listing:**

   ```bash
   sigsieve run --secretive --allow-fingerprint SHA256:<allowed> &
   # use the printed path:
   SSH_AUTH_SOCK=<printed path> ssh-add -l    # exactly one line
   ```

3. **Hidden key cannot sign** (no Touch ID prompt expected):

   ```bash
   SSH_AUTH_SOCK=$S ssh-add -L | grep '<hidden key comment>' > /tmp/hidden.pub
   echo test > /tmp/msg
   SSH_AUTH_SOCK=<printed path> ssh-keygen -Y sign -n test -f /tmp/hidden.pub /tmp/msg
   # expected: failure, no /tmp/msg.sig, no Touch ID prompt
   ```

   Note: `ssh-keygen` checks the agent's listing first and may not send a
   sign request at all for an unlisted key. The automated script sends a raw
   `SIGN_REQUEST` instead, which is the stronger test.

4. **Allowed key can sign** (Touch ID prompt possible):

   ```bash
   SSH_AUTH_SOCK=$S ssh-add -L | grep '<allowed key comment>' > /tmp/allowed.pub
   SSH_AUTH_SOCK=<printed path> ssh-keygen -Y sign -n test -f /tmp/allowed.pub /tmp/msg
   ssh-keygen -Y check-novalidate -n test -f /tmp/allowed.pub -s /tmp/msg.sig < /tmp/msg
   ```

5. **Stop and confirm cleanup:** `kill %1` (or Ctrl-C), then check that the
   printed socket path no longer exists.

6. **Normal access is unaffected:** `ssh <host>` without SigSieve still works.

Steps 3–4 write only to `/tmp`. Delete those files afterwards.

## Destination binding with Secretive

Secretive has no destination-constraint support of its own. With
`--allow-destination SHA256:<host key>`, SigSieve enforces destination
binding before any request reaches Secretive, so a compromised forwarding
host cannot use the Secretive key for other servers. Get the destination's
host key fingerprint from a source you trust (for example
`ssh-keygen -lf ~/.ssh/known_hosts` after verifying it, or the service's
published fingerprints). Not yet verified with a real Secretive key.

## Recorded real-device results

| Date | What | Result |
|---|---|---|
| 2026-10-24 | `scripts/agent-integration-check.sh` (no signing) against Secretive with 3 keys, 1 allowed | PASS: filtered listing exactly 1 key; raw sign requests for the 2 hidden keys refused; socket cleaned up; upstream unchanged |
| 2026-10-24 | `sigsieve connect <ci host>` (one allowed key, `StrictHostKeyChecking=yes`) | PASS: remote `ssh-add -l` showed only the allowed key; cleanup verified; plain ssh unaffected afterwards |
| 2026-10-24 | `connect --dry-run` against the real ssh_config | PASS: login agent kept (Secretive via IdentityAgent), only filtered socket forwarded |
| pending | whether any Touch ID prompt appeared during hidden-key refusal | awaiting owner confirmation |
| pending | `--sign-allowed`, destination binding with Secretive | not run |
