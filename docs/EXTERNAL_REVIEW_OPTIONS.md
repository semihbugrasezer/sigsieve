# External review options

Checked: **2026-10-29**. These are possible inquiry routes, not selected
reviewers, endorsements, quotations or completed security assurance. No
provider has been contacted, no application submitted and no cost approved.

The intended target remains released `v0.1.0-alpha.2`, source
`fc7484be0371242f517b6628b0f7dcc3a9a12a29`. Use the existing
[external validation protocol](EXTERNAL_VALIDATION.md) as the scope and
reporting packet; this note only identifies ways to obtain the review.

| Route and role | Primary evidence and date | Relevance and unresolved fit | Public inquiry path |
|---|---|---|---|
| **Cure53 — auditing provider** | Its [libssh assessment](https://www.libssh.org/security/audit/SSH-01-report-cure53.pdf) covered SSH client/server code review, code-assisted testing and protocol fuzzing in September–October 2019. Its [rustls assessment](https://cure53.de/pentest-report_rustls.pdf) covered Rust TLS code, protocol handlers and related cryptographic libraries in May–June 2020. | The combination suggests relevant SSH and Rust protocol-review experience; that is an inference from historical reports, not evidence of current staffing or SigSieve-specific session-binding expertise. Ask who would review the agent protocol, hostbound authorization and SSH configuration boundary. Current availability and a SigSieve-specific fee are unknown. | [Official business contact](https://cure53.de/) lists its inquiry channel. Request a scoped proposal; the historical reports do not establish present availability. |
| **Quarkslab — auditing provider** | Its [Paramiko audit write-up, published 2026-05-05](https://blog.quarkslab.com/paramiko-security-audit.html), describes SSHv2 review, cryptographic integration, static/dynamic analysis and CI work. [OSTIF dates the engagement to November 2025](https://ostif.org/paramiko-audit-complete/). The provider explicitly excludes an audit of OpenSSL or rust-openssl themselves. | This suggests relevant SSH implementation and cryptographic-use review experience, not proof of expertise in every SigSieve boundary. Ask for demonstrated Rust parser, agent-forwarding and hostbound-authentication coverage, reviewer identity and a retest plan. Current availability and a SigSieve-specific fee are unknown. | The write-up links the official [security-audit inquiry form](https://content.quarkslab.com/talk-to-our-experts-blog). No form was submitted. |
| **OSTIF — coordination and potential funding route** | Its [Get an Audit process](https://ostif.org/get-an-audit/) describes scoping with maintainers, sourcing independent audit teams, collecting bids and coordinating remediation/reporting. It also describes helping projects find sponsors. Its [Paramiko announcement](https://ostif.org/paramiko-audit-complete/) identifies Quarkslab as the audit team and Alpha-Omega as a supporter. | Relevant if the maintainer needs help choosing expertise or sourcing funding. OSTIF is the coordinator in this route, not a substitute for the independent technical review team. SigSieve's eligibility, acceptance, sponsor funding, schedule and project-specific cost are all unconfirmed. | Start from the official [Get an Audit page](https://ostif.org/get-an-audit/), which links its intake form. Application or funding success is not guaranteed. |

## Maintainer decision

Choose whether to request a direct provider proposal or explore coordinated
scoping/funding first. Send the same immutable source revision and existing
packet to any chosen route so proposals cover comparable work. Ask for named
reviewers, their relevant experience, independence from implementation,
explicit exclusions, deliverables, remediation retesting, reporting/disclosure
terms, schedule and a written project-specific quote. Approve scope and cost
before commissioning work; do not treat public report dates as current bookings.

No SigSieve-specific price or delivery commitment was obtained. Historical
engagements support making an inquiry; they do not establish the suitability
of the particular people who would be assigned. The independent expert
review and three real-user trials remain **not started**. The candidate
selection step itself provides no new security assurance or compatibility
evidence.
