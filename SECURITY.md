# Security Policy

SigSieve is experimental security software and has **not** been
independently audited by a professional security firm. Its reviews so far
are AI-assisted reviews in separate contexts plus the automated test suite. We take reports seriously and appreciate responsible
disclosure.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.0-alpha.* (experimental preview) | security reports accepted |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/semihbugrasezer/sigsieve/security/advisories/new)
("Security" tab → "Report a vulnerability").

If that form is unavailable, open a public issue titled "Security contact
request" **without any details** of the problem; the maintainer will reply
with a private channel.

Please include:

- affected version or commit,
- a description of the issue and its impact,
- steps or a proof of concept to reproduce (synthetic keys only, never real
  private keys or credentials),
- any suggested fix.

## What to expect

- Acknowledgement within 7 days.
- An initial assessment within 14 days.
- Coordinated disclosure: we aim to fix confirmed issues and publish an
  advisory within 90 days, crediting you unless you prefer otherwise.

## Scope

In scope: anything that lets a downstream client list or use a
non-allowlisted identity, reach the upstream agent with operations other than
allowlisted listing and signing, crash or exhaust SigSieve, make SigSieve
delete or replace files it didn't create, or make `sigsieve connect` forward
an unfiltered agent. Also in scope: documentation that claims a guarantee the
code doesn't provide.

Out of scope: issues that require a compromised local user account, root, or
a compromised upstream agent; misuse of explicitly allowed keys; and the
limitations documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/LIMITATIONS.md](docs/LIMITATIONS.md). We still welcome ideas for
hardening in these areas as regular issues.
