# Support and usage questions

SigSieve is experimental security software. It has no guaranteed response time, no paid support, and no production assurance or independent audit.

## Before asking for help

1. Follow the [README quick checks](README.md#first-safe-check-with-openssh-linux-or-macos) or the [Secretive walkthrough](README.md#first-session-with-secretive-macos).
2. Read [usage and troubleshooting](docs/USAGE.md#troubleshooting), [known limitations](docs/LIMITATIONS.md), and [SSH compatibility](docs/SSH_COMPATIBILITY.md).
3. Check whether the problem is reproducible with a throwaway OpenSSH agent and synthetic keys. You do **not** need to disclose a real key or host.

## Where to ask

- **How-to / installation question:** open a [Usage question](https://github.com/semihbugrasezer/sigsieve/issues/new/choose) using the issue form.
- **Reproducible bug:** use the Bug report form. Include the exact version or commit, platform, upstream agent, OpenSSH version and redacted steps.
- **Feature idea:** use the Feature request form and explain how it affects the upstream agent trust boundary.
- **Security vulnerability:** **do not create a public issue**. Use [private vulnerability reporting](SECURITY.md#reporting-a-vulnerability).

Do not paste private keys, authentication tokens, agent socket dumps, real hostnames or unredacted `ssh -vv` output. Redact connection details and fingerprints that are private to you.

No one should need access to your machine or agent to reproduce a public issue. Issues and contributions are welcome, but response and fix timelines are not guaranteed.
