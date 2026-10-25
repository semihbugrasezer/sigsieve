# Protocol references and design rationale

Checked against primary sources on 2026-10-26. This is a comparison of the
implementation with its sources, not a security audit or a conformance
certification. Executable evidence belongs in [SECURITY_MODEL.md](SECURITY_MODEL.md)
and [TESTING.md](TESTING.md).

## Standards and extensions

The base agent protocol is now [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html)
(Standards Track, May 2026), which supersedes the earlier SSH agent
Internet-Draft as a reference. Its sections 3 and 5 permit agents to expose
a subset of keys and refuse operations. SigSieve implements that restricted
role: framed identity requests and authorized signature requests; key
addition, removal, locking and provider loading are refused. See
[`protocol.rs`](../src/protocol.rs), [`keys.rs`](../src/keys.rs) and
[`proxy.rs`](../src/proxy.rs).

Destination binding uses **OpenSSH extensions**, not an extension to the
base RFC invented by SigSieve:

| Source | What SigSieve takes from it | Implementation |
|---|---|---|
| [OpenSSH PROTOCOL.agent, section 1](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent) | `session-bind@openssh.com`: host key, session identifier, host-key signature and forwarding flag, with state attached to the agent connection | `Bindings::bind` in [`binding.rs`](../src/binding.rs) verifies each accepted binding; bindings cannot be appended after an authentication binding |
| [RFC 4253, section 7.2](https://www.rfc-editor.org/rfc/rfc4253.html#section-7.2) | The first key-exchange hash becomes the SSH session identifier | Binding verification checks the supplied host-key signature over that identifier; SigSieve does not perform the network key exchange |
| [RFC 4252, section 7](https://www.rfc-editor.org/rfc/rfc4252.html#section-7) | Public-key authentication signs the session identifier and authentication request | `parse_userauth_request` checks the message type, service, method, signature-present flag, key and exact end of input |
| [OpenSSH PROTOCOL, section 3.1](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL) | `publickey-hostbound-v00@openssh.com` adds the destination server's host key to the signed request | `Bindings::authorize` requires hostbound requests on forwarded connections, matches the host key and session identifier, then checks the destination allowlist |

## Deliberate scope differences

OpenSSH's [destination-constraint design](https://www.openssh.org/agent-restrict.html)
and [`ssh-add -h` manual](https://man.openbsd.org/ssh-add.1#h) describe per-key
constraints over forwarding paths, optional destination usernames and host
certificate authorities. **SigSieve is not a replacement implementation of
that complete policy.** Its policy applies an identity allowlist and,
optionally, a final destination host-key allowlist to one proxy instance.
It does not restrict intermediate hosts or usernames, accept host
certificates, or implement `restrict-destination-v00@openssh.com` key loading.
Binding verification supports Ed25519 and ECDSA P-256/384/521 host keys;
other host-key types are refused.

An accepted single authentication binding may use ordinary `publickey`;
forwarded connections require hostbound authentication. This follows the
first-hop exception in the OpenSSH design and depends on the **trusted local
SSH client** recording the initial forwarding binding before exposing an
agent channel. A raw remote client cannot be treated as a trusted local
client. Bindings and authorized requests can still be replayed to request
signatures for an already bound session; they do not grant unrestricted
signing or extend the destination policy.

Bindings are handled locally and are not propagated to the upstream agent.
Upstream OpenSSH keys already constrained by `ssh-add -h` are therefore not
supported through this proxy; see the fail-closed regression in
[`tests/openssh.rs`](../tests/openssh.rs).

## Forwarding and remaining trust

The [`ssh_config` manual](https://man.openbsd.org/ssh_config.5) distinguishes
`IdentityAgent` (login authentication) from `ForwardAgent` (remote access),
warns that remote users can use forwarded keys, and specifies first-value
configuration precedence. `connect` keeps login authentication separate,
forwards the filtered socket, disables connection sharing and other
forwardings, and verifies each accepted proxy hop. Its conservative handling
of local commands, `Match exec` and includes is a SigSieve restriction, not
general OpenSSH compatibility. See [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md).

[RFC 9987, section 10](https://www.rfc-editor.org/rfc/rfc9987.html#section-10)
explains why agent socket access is sensitive and recommends filesystem
permissions and peer checks. SigSieve applies both. It cannot protect a
compromised local account or stop a remote host from using an explicitly
allowed key at an allowed destination while forwarding is active.

Hardware protection does not remove this distinction: Secretive's
[official documentation](https://github.com/maxgoedjen/secretive#why)
describes Secure Enclave storage and configurable user authentication.
Those controls remain the upstream agent's responsibility; SigSieve neither
exports private keys nor promises a Touch ID prompt for every signature.
Real-device compatibility must be measured separately from protocol tests.
