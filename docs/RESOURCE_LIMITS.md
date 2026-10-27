# Resource bounds and their evidence

These defaults serve one developer's forwarded session. They reduce abuse;
they do not distinguish legitimate clients from a compromised forwarding host.
There is no new daemon, privilege, runtime dependency or automatic retry.

| Resource | Default | Exhaustion behavior |
|---|---|---|
| Downstream clients | 32 | Evict the longest-idle client after at least 5 s; otherwise refuse new client |
| Accepted connections | 64 burst, refill 64/s | Close new connection before spawning a worker |
| Parsed requests, instance | 1024 burst, refill 1024/s | Close client |
| Requests, one connection | 128 burst, refill 128/s | Close client |
| Authorized signing attempts | 32 burst, refill 4/s | Agent FAILURE; no upstream call |
| Upstream exchanges | 4 active; FIFO queue bounded by 32 clients | Queue wait shares the request deadline; no unbounded worker/task allocation |
| Whole upstream request | 120 s, configurable with existing --upstream-timeout | Close upstream and fail; cancellation checked between nonblocking operations |
| Started downstream frame / whole reply write | 10 s / 10 s | Close client |
| Idle client | 300 s | Close client |
| Agent frame | 256 KiB | Reject/close before allocation |
| Destination-bound duplicate cache | 256 SHA256 digests, at most 300 s | Oldest evicted; repeated attempt refused while remembered |
| Runtime log details | 16/s per process | Count suppression; summary at next window or shutdown |

The initial signing burst matches the existing 32-client cap. Four upstream
exchanges and four signing tokens/s limit sustained agent/prompt pressure
without shortening an admitted user's configured presence-check timeout.
Connection burst capacity allows twice that client cap. Request budgets leave
room for listing/binding/denials alongside signing; they are separate from
signing admission. These are conservative alpha defaults, not a benchmark of
human Touch ID response times or a universal fairness policy.

Executed validation uses synthetic agents and disposable OpenSSH hosts:

- A production-default profile opens 32 clients, lists the approved identity,
  signs once per client and rejects hidden-key requests: all 32 permitted
  signatures must reach the upstream.
- A 100-signature burst must admit no more than 32 + elapsed-time refill,
  while preserving hidden-key rejection. Before the fix all 100 reached the
  upstream immediately; that regression failed as expected.
- One client cannot complete 300 rapid requests without hitting its budget.
- FIFO/concurrency tests check acquisition order, cancellation, queue deadline
  cleanup and permit release. Stalled and trickling agents test total deadlines.
- The descriptor stress sends 3,200 short-lived connections, including partial
  frames, and retains the original no-leak/continued-service assertions.
  That throughput test explicitly uses generous token rates; separate tests
  exercise production defaults. It is not evidence of unlimited production
  throughput.
- CLI flooding checks detail limits, suppression summaries and absence of a
  synthetic sensitive payload from stderr. Duplicate tests prove another client
  cannot repeat the same authorized destination-bound attempt, including after
  an upstream failure; no response is cached.

An attacker can consume the shared budgets or occupy all active client slots.
New sessions or cache eviction can trigger more prompts. The upstream decides
whether a permitted request requires user presence. Slow filesystem metadata,
kernel stalls, scheduler delays and a blocked log destination are outside hard
real-time guarantees. See [LIMITATIONS.md](LIMITATIONS.md) and the linked
[OS references](RESOURCE_REFERENCES.md).
