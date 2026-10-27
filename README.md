# SigSieve

**Forward the SSH identities a remote host needs, while keeping your existing agent.**

SigSieve is a local SSH agent proxy for macOS and Linux. It filters forwarded
identities by SHA256 fingerprint and can optionally restrict authentication
to approved destination host keys. Signing stays in your existing agent:
there is no private-key export, replacement agent or key migration.

Its main use case is forwarding a **non-exportable, hardware-backed identity**
from Secretive's Secure Enclave when you need SSH authentication on a remote
build or development host. OpenSSH connects normally; SigSieve controls the
agent socket it forwards.

> [!WARNING]
> **Experimental security software. Not independently audited.**
> `0.1.0-alpha.2` is an unreleased source candidate; there are no verified
> binary releases or published Homebrew installation yet. Real Secretive
> signing and destination binding remain unverified. Read the
> [security model](docs/SECURITY_MODEL.md) and [limitations](docs/LIMITATIONS.md)
> before relying on it, and keep ordinary SSH access available.

Free, MIT-licensed and local-first. No SaaS, accounts, telemetry or mandatory
cloud infrastructure.

## Do you need it?

Use SigSieve when a remote process needs your forwarded agent, but should
have access to only a subset of its identities. Hardware backing prevents
key extraction; it does not prevent a compromised remote host from requesting
signatures through a forwarded socket.

| Your need | Consider first |
|---|---|
| Reach a target through a bastion | [ProxyJump](https://man.openbsd.org/ssh_config#ProxyJump) (`ssh -J bastion target`); the bastion needs no forwarded agent. |
| Forward only selected keys that you can load into another agent | A separate OpenSSH `ssh-agent` containing just those keys. Non-exportable Secretive identities cannot be copied into it. |
| Restrict keys loaded into OpenSSH's agent | Native [destination constraints](https://www.openssh.org/agent-restrict.html) (`ssh-add -h`, OpenSSH 8.9+); they also support path/user constraints that SigSieve does not. |
| Select the identity for your own SSH login | `IdentityFile`, `IdentityAgent`, `IdentitiesOnly`; login selection alone does not filter a forwarded agent. |
| Forward selected identities from an existing agent such as Secretive | SigSieve; no change to where keys live or which agent signs. |

```text
Existing agent → SigSieve → filtered socket → OpenSSH → remote process
 (all keys)                  (allowed keys)
```

## Protection and limits

| | Identity filtering (default) | Optional destination binding |
|---|---|---|
| Keys visible and usable remotely | Allowlisted identities only | Allowlisted identities only |
| What an allowed key may sign | Arbitrary data; any server that trusts it | SSH hostbound authentication to allowed destination host keys only |
| Mutations, lock/unlock, PKCS#11, unknown operations | Refused locally | Refused locally |

**An allowed key remains usable by a compromised remote host while you are
connected**, including at allowed destinations in binding mode. SigSieve
does not protect a compromised local account or upstream agent, replace SSH
host-key verification, or add per-use confirmation. Secretive controls its
own authentication policy and Touch ID prompts.

Destination binding requires compatible OpenSSH clients/servers and
Ed25519/ECDSA host keys. It restricts host keys, not usernames or intermediate
hops, and refuses non-authentication signing such as `git commit -S` through
the forwarded agent. Consult [compatibility](docs/SSH_COMPATIBILITY.md)
before using it with a Git hosting service.

## Install from source

Current installation requires Rust (the checkout pins 1.99.1) and OpenSSH
8.4+; ProxyJump/relay sessions require 8.7+. Tested platforms are macOS arm64
and Linux x86_64/aarch64. Planned binary targets are macOS arm64 and Linux
x86_64; Linux aarch64 is source-only. No Windows or Intel macOS validation
is claimed.

Planned Linux archives use the Ubuntu 24.04 / glibc 2.39 baseline; build from
source on older distributions.

```bash
git clone https://github.com/semihbugrasezer/sigsieve
cd sigsieve
git rev-parse HEAD                   # inspect CI for this exact revision
cargo install --locked --path .
sigsieve --version
```

Ensure `~/.cargo/bin` is on your PATH. There is no published `brew install`
command yet. The alpha.1 source tag is superseded; its release build was
cancelled. Future archives must pass the
[release checklist](docs/RELEASE_CHECKLIST.md), including checksums, license
notices, native smoke tests and provenance verification, before appearing on
[Releases](https://github.com/semihbugrasezer/sigsieve/releases).

## First session with Secretive (macOS)

Start Secretive and list its public fingerprints locally:

```bash
SSH_AUTH_SOCK="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh" ssh-add -l
```

Replace the entire placeholder below with the fingerprint of the one key
the remote host may use. Replace `build-host` with your SSH alias, whose
host key you have already verified and saved in known_hosts.

```bash
fp='SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT'
sigsieve doctor --secretive --allow-fingerprint "$fp"
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  -- -o StrictHostKeyChecking=yes
```

`doctor` checks filtering locally; `--dry-run` verifies the connection plan
without opening a session or signing with a real key. When connected, remote
`ssh-add -l` should show only the allowed identity. Exit SSH to stop forwarding
and clean up. Your login still uses your normal agent. `connect` disables
connection sharing, port forwarding and X11 for that session.

For **Linux/OpenSSH ssh-agent**, optional destination binding, stable sockets,
CLI options, common errors and returning to ordinary SSH, follow the
[usage and troubleshooting guide](docs/USAGE.md). For device testing, see
[Secretive integration](docs/SECRETIVE_INTEGRATION.md).

## Evidence and compatibility

These are distinct kinds of evidence, not security certifications. Test
results apply to the revision exercised; a green older run does not validate
a new candidate.

| Evidence | Current scope |
|---|---|
| Code review | Internal AI-assisted reviews in separate contexts; [findings and residual risks](docs/FINDINGS.md). No independent external audit. |
| Automated tests | Parsers, policy, adversarial agents, lifecycle and resource limits; [test layers and historical results](docs/TESTING.md). |
| Real OpenSSH | Real `ssh-agent`, `ssh` and throwaway `sshd` tests in CI on macOS arm64 and Linux x86_64/aarch64; inspect [CI for your exact commit](https://github.com/semihbugrasezer/sigsieve/actions/workflows/ci.yml). |
| Real Secretive (ECDSA P-256) | One recorded user-assisted session: listing, hidden-key refusal and filtered forwarding. Allowed-key signing, destination binding and device-owner confirmation of Touch ID observations remain pending. [Recorded results](docs/SECRETIVE_INTEGRATION.md#recorded-real-device-results). |
| Git hosts | 2026-10-27 advertisement measurements: GitHub advertises hostbound authentication (end-to-end unverified); GitLab.com and Bitbucket Cloud do not. [Measurements and caveats](docs/SSH_COMPATIBILITY.md#git-hosting-services). |
| Fuzzing | Stable corpus mutation, historical uninstrumented runs and a recorded 60 s/target instrumented libFuzzer smoke run. Sustained campaigns remain outstanding. [Run and limits](docs/TESTING.md#recorded-coverage-guided-smoke-run). |
| Other integrations | 1Password and physical FIDO keys untested; SSH identity certificates unsupported. [Key types and protocol matrix](docs/SSH_COMPATIBILITY.md). |
| Distribution | Packaging and provenance workflow prepared; no verified published archives. [Release gates](docs/RELEASE_CHECKLIST.md). |

## Learn more and contribute

- **Use it:** [usage, troubleshooting and uninstall](docs/USAGE.md),
  [Secretive](docs/SECRETIVE_INTEGRATION.md), [example ssh_config](examples/ssh_config).
- **Evaluate it:** [threat model](docs/THREAT_MODEL.md),
  [security model and test evidence](docs/SECURITY_MODEL.md),
  [limitations](docs/LIMITATIONS.md), [resource limits](docs/RESOURCE_LIMITS.md).
- **Understand it:** [architecture](docs/ARCHITECTURE.md),
  [protocol references](docs/REFERENCES.md).
- **Contribute:** [setup and first contributions](CONTRIBUTING.md),
  [testing](docs/TESTING.md), [changelog](CHANGELOG.md),
  [Code of Conduct](CODE_OF_CONDUCT.md).
- **Report a problem:** use a [bug report](https://github.com/semihbugrasezer/sigsieve/issues/new/choose)
  with redacted output. Report vulnerabilities privately via [SECURITY.md](SECURITY.md).

[MIT license](LICENSE). Binary distributions include [third-party notices](docs/THIRD_PARTY.md).
