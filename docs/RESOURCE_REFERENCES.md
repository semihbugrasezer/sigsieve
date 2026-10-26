# Socket resource and deadline references

Checked against primary sources on 2026-10-26, including the installed Rust
1.99.1 source. This is implementation research, not a runtime acceptance result.
Context7 resolved `/rust-lang/rust`; its versioned connect query returned no
matches, and its narrower `UnixStream set_read_timeout` query returned Rust
source. The official documentation and operating-system sources below supply
the remaining details.

## Bounded upstream connection establishment

Rust 1.99.1 has no `UnixStream::connect_timeout`. Its
[`connect` implementation](https://doc.rust-lang.org/src/std/os/unix/net/stream.rs.html#100-108)
creates a socket and calls `connect(2)` before returning. Calling
`set_nonblocking` or setting I/O timeouts on the returned stream cannot bound
that preceding call. The
[`UnixStream` API](https://doc.rust-lang.org/std/os/unix/net/struct.UnixStream.html)
does expose nonblocking mode, `take_error` (`SO_ERROR`), and conversion from an
owned descriptor.

The smallest implementation using the already installed `libc` dependency is
an unconnected `AF_UNIX` / `SOCK_STREAM` socket made nonblocking **before**
`connect`, with these outcomes:

| Outcome | Required handling | Primary source |
|---|---|---|
| `connect` succeeds | Continue to peer validation; no readiness wait is needed | [Linux `connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html) |
| `EINPROGRESS` | Wait for writable readiness within the remaining deadline, then require `SO_ERROR == 0`; readiness alone is insufficient | [Linux `connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html), [Apple `connect(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/connect.2.html) |
| Linux `AF_UNIX` `EAGAIN` | Fail this attempt. It is not evidence of a pending connection that `poll` can complete | [Linux `unix_stream_connect`](https://github.com/torvalds/linux/blob/master/net/unix/af_unix.c): a full listener queue returns `EAGAIN` before the client is connected |
| Any other error | Close the owned descriptor and report the error | [Linux `connect(2)`, notes](https://man7.org/linux/man-pages/man2/connect.2.html#NOTES): portable reconnection uses a new socket after failure |

Failing immediately on Linux backlog saturation is the smallest bounded
policy. If retrying is later required, use fresh attempts with an explicitly
bounded delay and the same deadline; do not busy-poll an unconnected socket or
infer success from its zero `SO_ERROR`. Darwin differs: Apple's current
[`unp_connect`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c)
returns `ECONNREFUSED` when `sonewconn` fails, and
[`sonewconn_internal`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket2.c)
can fail on queue saturation. Tests must not require Linux's errno on macOS.

## One deadline for the whole exchange

Create one absolute
[`Instant`](https://doc.rust-lang.org/std/time/struct.Instant.html) deadline at
request entry, using `checked_add` to reject an unrepresentable timeout. Carry
it through connect, request writing, reply header and reply body. Recompute
remaining time before each operation and after interruptions or partial
progress; no phase or received byte should start a fresh full timeout. Check
expiry before accepting the completed exchange.

For a portable socket-wait budget, keep the socket nonblocking throughout the
exchange. Read/write partial data normally; on `WouldBlock`, poll the required
direction using the remaining budget. Treat zero-length reads as EOF and
zero-length writes as failure. This avoids relying on inactivity timers:
[Linux socket timeouts](https://man7.org/linux/man-pages/man7/socket.7.html)
apply to individual I/O calls, while Apple's
[`SO_RCVTIMEO` / `SO_SNDTIMEO` documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getsockopt.2.html)
describes timers that restart with progress. A single timeout followed by
`write_all` or `read_exact` does not establish one exchange deadline.

[`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html) uses an integer
millisecond timeout: round positive fractional milliseconds up, cap at
`c_int::MAX`, and never turn overflow into a negative infinite timeout. Retry
`EINTR` against the original deadline. Inspect `revents`, not merely the return
count; `POLLNVAL` is an error. For connect completion, error/hangup is not
success. During reply reading, `POLLHUP` may coexist with buffered data, so
readable data must still be consumed before EOF. Apple's
[`poll(2)` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/poll.2.html)
also specifies millisecond waits and interruption.

These are application-controlled wait bounds, not hard real-time guarantees:
poll rounding and scheduling can overrun, `Instant` suspend behavior varies,
and synchronous metadata/path lookup is not interrupted by this deadline.
Apple's [`unp_connect`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c)
explicitly performs filesystem lookup. Do not describe this as bounding every
possible kernel or filesystem stall.

## Address, descriptor and trust details

- Use the target's `libc::sockaddr_un`, zero-initialize it, set `AF_UNIX`, and
  copy pathname **bytes** after rejecting embedded NUL and lengths greater
  than or equal to `sun_path.len()`. Include the terminator and use
  `offset_of!(sockaddr_un, sun_path) + path_bytes.len() + 1` for the address
  length. This matches the approach in
  [Rust's address constructor](https://doc.rust-lang.org/src/std/os/unix/net/addr.rs.html#24-74).
  Do not hard-code Linux's 108-byte array: Darwin has `sun_len` and a
  104-byte array, reflected in
  [Apple's header](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/un.h)
  and the [Rust libc definitions](https://github.com/rust-lang/libc/blob/main/src/unix/bsd/mod.rs).
  Populate `sun_len` on Darwin with the supplied address length. Keep the
  address storage alive throughout the synchronous call. No abstract namespace
  support is needed for filesystem agent paths; it is
  [Linux-specific](https://man7.org/linux/man-pages/man7/unix.7.html).
- Immediately give each successful raw descriptor exactly one
  [`OwnedFd`](https://doc.rust-lang.org/std/os/fd/struct.OwnedFd.html) owner, so
  all error paths close it. Transfer ownership with `From<OwnedFd>`; never
  construct two owners from one raw descriptor. See
  [`FromRawFd` safety](https://doc.rust-lang.org/std/os/fd/trait.FromRawFd.html#tymethod.from_raw_fd).
- On Linux, pass `SOCK_CLOEXEC | SOCK_NONBLOCK` atomically to
  [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html).
  On Darwin, [Rust's socket constructor](https://doc.rust-lang.org/src/std/sys/net/connection/socket/unix.rs.html#65-109)
  instead creates the socket, owns it, and sets close-on-exec;
  [`FileDesc::set_cloexec`](https://doc.rust-lang.org/src/std/sys/fd/unix.rs.html#567-591)
  uses `ioctl(FIOCLEX)` on this target. An immediate
  `fcntl(F_SETFD, FD_CLOEXEC)` has the same non-atomic creation-to-flag window
  as existing `UnixStream::connect`, although the second syscall differs.
  Set the flag before other setup and fail if configuration fails.
- Raw creation must preserve Apple's `SO_NOSIGPIPE` setup from that same Rust
  constructor. Merely converting an `OwnedFd` to `UnixStream` does not run the
  constructor. Setting `SO_NOSIGPIPE` **before** `connect` is exactly the
  ordering used by standard socket creation. Apple's
  [`SO_NOSIGPIPE`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getsockopt.2.html)
  prevents a disconnected write from generating `SIGPIPE`.
- Preserve both pathname ownership validation and the connected peer UID
  check **before sending protocol bytes**. Peer credentials refer to the local
  connected process, as specified by
  [Linux `SO_PEERCRED`](https://man7.org/linux/man-pages/man7/unix.7.html)
  and [Darwin's credential capture](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c).

The installed Rust 1.99.1
[`Command::posix_spawn` implementation](https://doc.rust-lang.org/src/std/sys/process/unix/unix.rs.html#693-767)
does not remove that Darwin inheritance window: it starts with zero spawn
flags, configures stdio duplication, and adds process-group/signal flags,
without `POSIX_SPAWN_CLOEXEC_DEFAULT` or a close-from file action. A search of
the installed standard-library source found no `closefrom`, `addclosefrom` or
`addinherit` implementation. Apple's
[`posix_spawn(2)` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/posix_spawn.2.html)
states that descriptors without close-on-exec remain open unless a file
action changes that behavior. Therefore the custom fallback preserves an
existing non-atomic limitation; it must not be advertised as race-free or as
protected by Rust's spawn defaults.

## Resource bounds do not prove fairness

Connection caps, frame limits and deadlines bound admitted work and how long
a stalled connection retains a slot. They cannot reserve service for a
particular remote client when clients share the same authenticated local
identity. OpenSSH's
[`client_request_agent`](https://github.com/openssh/openssh-portable/blob/master/clientloop.c)
opens local agent connections for forwarded channels through
[`ssh_get_authentication_socket_path`](https://github.com/openssh/openssh-portable/blob/master/authfd.c).
Consequently, local peer credentials identify that forwarding process, not an
independent remote user.

The fairness conclusion is an inference from those identity boundaries:
indistinguishable clients can repeatedly occupy or reacquire all available
slots. Global/per-connection limits constrain resource consumption but do not
guarantee availability, fair admission or progress for an honest competing
client. Such a guarantee needs a separately trustworthy client identity and
an admission policy based on it.

No new dependency, implementation, load simulation, real-agent interaction
or hardware authentication was performed for this note.
