# Using SigSieve with Secretive (macOS)

[Secretive](https://github.com/maxgoedjen/secretive) stores SSH keys in the
Secure Enclave (ECDSA P-256) and serves them through an SSH agent socket.
SigSieve sits in front of that socket and never sees private keys. Allowed
signing requests are delegated to Secretive; its key storage and user-presence
policy remain in control. One owner-assisted allowed-key signing and destination-binding test passed
on release commit `fc7484b`; this does not guarantee every Secretive
configuration.
See the [recorded results](#recorded-real-device-results).

The released `v0.1.0-alpha.2` source is
`fc7484be0371242f517b6628b0f7dcc3a9a12a29`; its
[release evidence](TESTING.md#release-candidate-evidence-2026-10-28) is separate
from the earlier 2026-10-24 observations below. The release-device record
covers one real P-256 key and two localhost SSH servers. Secretive version
and full per-operation prompt counts were not recorded; other devices,
versions and external services remain unverified.

For installation and a first session, start with the
[usage guide](USAGE.md). The procedure below is a device verification check,
not a record that every step has passed.

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
- `doctor` and `connect` self-tests list keys and send a sign request for a
  *synthetic* key that SigSieve rejects. With destination binding they also
  probe an unbound allowed-key request, which SigSieve must reject locally.
  These probes do not ask Secretive to sign. During the 2026-10-28 tested
  configuration, the owner reported no unexpected prompts in the forbidden
  destination or generic-signing steps; a full per-operation prompt count was
  not recorded.

For forwarding, consider a key configured to require authentication.
Secretive decides when to prompt and may cache authorization: SigSieve
cannot guarantee user presence on every remote signature.

## Automated controlled check

`scripts/agent-integration-check.sh` runs the procedure below in one go. It
writes only to a private temporary directory, prints only the allowed key's
fingerprint plus counts of the others, and changes no configuration. Set
`fp` from the [usage guide](USAGE.md#choose-your-upstream-agent) first:

```bash
cargo build --release --locked
scripts/agent-integration-check.sh --sigsieve target/release/sigsieve \
  --allow "$fp"                 # default upstream: Secretive
# add --sign-allowed to also sign a test message with the allowed key
# (Touch ID may prompt). No prompt is expected without it.
```

If Secretive prompts for authentication during the hidden-key step, deny it
and report a bug: those requests must be rejected by SigSieve before they
reach Secretive.

## Owner-assisted verification

Use the script above after choosing `fp` as described in the usage guide.
It uses a private temporary directory and sends raw hidden-key signing
requests; a listing-only tool may refuse a hidden key without ever testing
sign authorization. Check the allowed fingerprint and do not share raw output.

Run the default check first. To test allowed-key signing, add `--sign-allowed`
to the same command. This asks the real agent to sign a test message and
verifies the signature, so Secretive may request user presence. Deny any
unexpected prompt. Record the OS, SigSieve commit, Secretive/OpenSSH versions,
which checks passed and your prompt observations, without key or host details.

For filtered forwarding, follow [Check, preview, connect](USAGE.md#check-preview-connect).
After exiting, confirm the filtered socket is gone and ordinary SSH still
works. Do not mark allowed-key signing, destination binding or Touch ID as
verified unless you observed those specific steps on the device.

## Destination binding with Secretive

Secretive has no destination-constraint support of its own. With
`--allow-destination SHA256:<host key>`, SigSieve enforces destination
binding before any request reaches Secretive, so a compromised forwarding
host cannot use the Secretive key for servers other than the allowed
destinations (it can still authenticate to those while you are connected).
It passed an owner-assisted test with one real Secretive key and two
localhost test SSH servers on 2026-10-28; coverage of other versions,
configurations, host keys and remote services is not established. Get the
destination's host key fingerprint from a source you trust (for example
`ssh-keygen -lf ~/.ssh/known_hosts` after verifying it, or the service's
published fingerprints). This has not been tested with an external production
destination.

## Recorded real-device results

| Date | What | Result |
|---|---|---|
| 2026-10-24 | `scripts/agent-integration-check.sh` (no signing) against Secretive with 3 keys, 1 allowed | PASS: filtered listing exactly 1 key; raw sign requests for the 2 hidden keys refused; socket cleaned up; upstream unchanged |
| 2026-10-24 | `sigsieve connect <ci host>` (one allowed key, `StrictHostKeyChecking=yes`) | PASS: remote `ssh-add -l` showed only the allowed key; cleanup verified; plain ssh unaffected afterwards |
| 2026-10-24 | `connect --dry-run` against the real ssh_config | PASS: login agent kept (Secretive via IdentityAgent), only filtered socket forwarded |
| 2026-10-28 | Candidate `fc7484b`: real Secretive signing, P-256 key, signature verified locally, 1 identity forwarded to localhost sshd | PASS: 9/9 scripted checks, including hostbound allowed destination, forbidden destination refusal after key offer, generic-signing refusal, socket cleanup and unchanged upstream key count |
| 2026-10-28 | Device-owner Touch ID observations during forbidden destination and generic signing steps | No unexpected prompts observed for those two steps; full per-step counts and Secretive version were not recorded |
| pending | Integration with other Secretive versions, production SSH services, and full user-presence prompt matrix | not verified |
