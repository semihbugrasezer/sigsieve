//! The filtering proxy: per-request authorization, per-connection loop and
//! the accept loop.
//!
//! Only two operations ever reach the upstream agent:
//! - `REQUEST_IDENTITIES`: the reply is parsed and rebuilt from allowed keys.
//! - `SIGN_REQUEST`: forwarded only after the key blob is parsed, validated
//!   and its fingerprint found in the allowlist, with known flags only.
//!
//! With destination binding enabled, sign requests must additionally pass
//! [`Bindings::authorize`], and `session-bind@openssh.com` is verified and
//! recorded per connection (answered locally, never forwarded).
//!
//! Everything else (mutations, lock/unlock, smartcard/PKCS#11, constraints,
//! all other extensions, `session-bind` when destination binding is off,
//! unknown types) is answered locally with `SSH_AGENT_FAILURE` and never
//! forwarded.

use std::collections::HashMap;
use std::io;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::binding::Bindings;
use crate::keys::{parse_public_key, Fingerprint};
use crate::policy::Policy;
use crate::protocol::{self, Reader, WireError};
use crate::socket;
use crate::upstream::{parse_identities_answer, Upstream, UpstreamError};

mod resources;
use resources::{Budget, LogWindow, Resources};

#[derive(Debug, Clone)]
pub struct Limits {
    /// Concurrent downstream connections. When full, the longest-idle
    /// connection is evicted; if none is idle, the new one is closed.
    pub max_clients: usize,
    /// How long a connection may sit idle between requests.
    pub idle_timeout: Duration,
    /// How long a started frame may take to arrive completely.
    pub frame_timeout: Duration,
    /// Downstream write timeout.
    pub write_timeout: Duration,
    /// Minimum idle time before a connection may be evicted to make room.
    /// Protects clients pausing briefly between requests (e.g. an ssh login
    /// waiting for the server between listing and signing).
    pub evict_after: Duration,
    /// Whole-instance request and connection budgets (one second burst).
    pub request_rate: u32,
    pub connection_rate: u32,
    /// Signing attempts per second, with an initial burst of max_clients.
    pub signing_rate: u32,
    /// Concurrent upstream exchanges; queued requests share their I/O deadline.
    pub max_upstream: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_clients: 32,
            idle_timeout: Duration::from_secs(300),
            frame_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            evict_after: Duration::from_secs(5),
            request_rate: 1024,
            connection_rate: 64,
            signing_rate: 4,
            max_upstream: 4,
        }
    }
}

pub struct Proxy {
    policy: Policy,
    upstream: Upstream,
    limits: Limits,
    resources: Resources,
    cancelled: AtomicBool,
}

static LOG_WINDOW: OnceLock<Mutex<LogWindow>> = OnceLock::new();

fn log(msg: std::fmt::Arguments<'_>) {
    let suppressed = LOG_WINDOW
        .get_or_init(|| Mutex::new(LogWindow::new(Instant::now())))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .admit(Instant::now());
    if let Some(suppressed) = suppressed {
        if suppressed > 0 {
            eprintln!(
                "sigsieve: suppressed {suppressed} repeated events during the previous log window"
            );
        }
        eprintln!("sigsieve: {msg}");
    }
}

const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// Decide and produce the response payload for one downstream request.
/// `bindings` is the per-connection session-binding state.
impl Proxy {
    pub fn new(policy: Policy, upstream: Upstream, limits: Limits) -> Self {
        let resources = Resources::new(&limits);
        Self {
            policy,
            upstream,
            limits,
            resources,
            cancelled: AtomicBool::new(false),
        }
    }

    /// None closes a flooding connection; policy denials remain agent FAILURE.
    pub fn handle_request(&self, req: &[u8], bindings: &mut Bindings) -> Option<Vec<u8>> {
        if self.cancelled.load(Ordering::Relaxed) || !self.resources.request() {
            log(format_args!("request budget exhausted; closing client"));
            return None;
        }
        Some(handle_request(req, self, bindings))
    }

    fn upstream_request(&self, req: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        let deadline = self.upstream.deadline();
        let _permit = self
            .resources
            .acquire(deadline, &self.cancelled)
            .map_err(UpstreamError::Unreachable)?;
        self.upstream.request_until(req, deadline, &self.cancelled)
    }
}

fn handle_request(req: &[u8], proxy: &Proxy, bindings: &mut Bindings) -> Vec<u8> {
    match req.first().copied() {
        Some(protocol::SSH_AGENTC_REQUEST_IDENTITIES) => list_identities(req, proxy),
        Some(protocol::SSH_AGENTC_SIGN_REQUEST) => sign(req, proxy, bindings),
        Some(protocol::SSH_AGENTC_EXTENSION) => extension(&req[1..], &proxy.policy, bindings),
        Some(t) => {
            log(format_args!("rejected agent operation type {t}"));
            protocol::failure()
        }
        None => protocol::failure(),
    }
}

fn list_identities(req: &[u8], proxy: &Proxy) -> Vec<u8> {
    if req.len() != 1 {
        return protocol::failure();
    }
    let ids = match proxy
        .upstream_request(req)
        .and_then(|reply| parse_identities_answer(&reply))
    {
        Ok(ids) => ids,
        Err(e) => {
            log(format_args!("identity request failed: {e}"));
            return protocol::failure();
        }
    };
    let mut seen = std::collections::HashSet::new();
    let allowed: Vec<_> = ids
        .iter()
        .filter(|id| proxy.policy.allows(&id.blob) && seen.insert(id.blob.as_slice()))
        .collect();
    let mut out = vec![protocol::SSH_AGENT_IDENTITIES_ANSWER];
    protocol::put_u32(&mut out, allowed.len() as u32);
    for id in allowed {
        protocol::put_string(&mut out, &id.blob);
        protocol::put_string(&mut out, &id.comment);
    }
    out
}

/// Extensions are never forwarded. `session-bind@openssh.com` is verified and
/// recorded only when destination binding is enforced; otherwise accepting it
/// would suggest a guarantee that is not provided.
fn extension(body: &[u8], policy: &Policy, bindings: &mut Bindings) -> Vec<u8> {
    let mut r = Reader::new(body);
    let Ok(name) = r.string() else {
        log(format_args!("rejected malformed extension request"));
        return protocol::failure();
    };
    if name == SESSION_BIND && policy.destinations().is_some() {
        let rest = &body[4 + name.len()..];
        return match bindings.bind(rest) {
            Ok(()) => vec![protocol::SSH_AGENT_SUCCESS],
            Err(e) => {
                log(format_args!("rejected session-bind: {e}"));
                vec![protocol::SSH_AGENT_EXTENSION_FAILURE]
            }
        };
    }
    log(format_args!("rejected unsupported extension request"));
    protocol::failure()
}

fn sign(req: &[u8], proxy: &Proxy, bindings: &Bindings) -> Vec<u8> {
    let policy = &proxy.policy;
    let parsed = (|| -> Result<(&[u8], &[u8], u32), WireError> {
        let mut r = Reader::new(&req[1..]);
        let blob = r.string()?;
        let data = r.string()?;
        let flags = r.u32()?;
        r.finish()?;
        Ok((blob, data, flags))
    })();
    let (blob, data, flags) = match parsed {
        Ok(v) => v,
        Err(e) => {
            log(format_args!("rejected malformed sign request: {e}"));
            return protocol::failure();
        }
    };
    if !policy.allows(blob) {
        log(format_args!(
            "denied sign request for non-allowlisted key {}",
            Fingerprint::of_blob(blob)
        ));
        return protocol::failure();
    }
    let Some(alg) = parse_public_key(blob)
        .ok()
        .and_then(|kind| kind.signature_alg(flags))
    else {
        log(format_args!(
            "rejected sign request with flags {flags:#x}: invalid for the key type, or legacy RSA/SHA-1"
        ));
        return protocol::failure();
    };
    if let Some(destinations) = policy.destinations() {
        if let Err(reason) = bindings.authorize(blob, data, destinations) {
            log(format_args!(
                "denied sign request for {} (destination binding): {reason}",
                Fingerprint::of_blob(blob)
            ));
            return protocol::failure();
        }
    }
    if !proxy
        .resources
        .signature(req, policy.destinations().is_some())
    {
        log(format_args!(
            "signing budget exhausted or duplicate destination-bound attempt; request refused"
        ));
        return protocol::failure();
    }
    // The request was fully parsed with no trailing bytes, so forwarding it
    // verbatim forwards exactly the fields that were authorized.
    match proxy.upstream_request(req) {
        Ok(resp) if is_valid_sign_response(&resp, alg) => resp,
        Ok(resp) => {
            if resp.first() != Some(&protocol::SSH_AGENT_FAILURE) {
                log(format_args!(
                    "upstream returned an invalid sign response or an unrequested signature algorithm"
                ));
            }
            protocol::failure()
        }
        Err(e) => {
            log(format_args!("sign request failed: {e}"));
            protocol::failure()
        }
    }
}

/// A single signature whose algorithm is exactly the one requested, so an
/// upstream that ignores the flags cannot return a legacy `ssh-rsa` (SHA-1)
/// signature through SigSieve.
fn is_valid_sign_response(resp: &[u8], alg: &[u8]) -> bool {
    let mut r = Reader::new(resp);
    matches!(r.u8(), Ok(protocol::SSH_AGENT_SIGN_RESPONSE))
        && r.string()
            .is_ok_and(|sig| Reader::new(sig).string().is_ok_and(|a| a == alg))
        && r.finish().is_ok()
}

/// Serve one downstream connection until EOF, error, timeout or eviction.
fn serve_client(mut s: UnixStream, proxy: &Proxy, slot: &Slot) {
    // Bounds the blocking write of a final error reply; normal replies use
    // the nonblocking, whole-reply deadline below.
    if s.set_write_timeout(Some(proxy.limits.write_timeout))
        .is_err()
    {
        return;
    }
    let mut bindings = Bindings::default();
    let mut budget = Budget::new(128, 128, Instant::now());
    loop {
        slot.set_idle(true);
        let frame = protocol::read_frame(
            &mut s,
            proxy.limits.idle_timeout,
            proxy.limits.frame_timeout,
        );
        if !slot.set_idle(false) {
            // Evicted while the request arrived: do not act on it.
            return;
        }
        match frame {
            Ok(None) => return,
            Ok(Some(req)) => {
                if !budget.take(Instant::now()) {
                    log(format_args!(
                        "client request budget exhausted; closing client"
                    ));
                    return;
                }
                let Some(resp) = proxy.handle_request(&req, &mut bindings) else {
                    return;
                };
                // One deadline for the whole reply. Nonblocking, because a
                // blocking write's SO_SNDTIMEO restarts whenever the client
                // reads a little, so a slow reader could hold it forever.
                let deadline = Instant::now() + proxy.limits.write_timeout;
                let sent = s
                    .set_nonblocking(true)
                    .and_then(|()| {
                        protocol::write_frame_until(&mut s, &resp, deadline, &proxy.cancelled)
                    })
                    .and_then(|()| s.set_nonblocking(false));
                if sent.is_err() {
                    return;
                }
            }
            Err(e @ (WireError::TooLarge(_) | WireError::Empty)) => {
                // The stream cannot be resynchronised; answer and drop it.
                log(format_args!("closing client: {e}"));
                let _ = protocol::write_frame(&mut s, &protocol::failure());
                return;
            }
            Err(_) => return,
        }
    }
}

struct Conn {
    /// Handle used to shut the connection down when evicting it.
    stream: UnixStream,
    /// `Some(since)` while waiting for (or receiving) a request.
    idle_since: Option<Instant>,
}

/// Active connections. Its size is the concurrency count.
type Registry = Arc<Mutex<HashMap<u64, Conn>>>;

fn lock(reg: &Registry) -> std::sync::MutexGuard<'_, HashMap<u64, Conn>> {
    // A panicking client thread must not take the whole proxy down.
    reg.lock().unwrap_or_else(|e| e.into_inner())
}

/// A connection's registry entry; removed when the thread ends, including by
/// panic.
struct Slot {
    id: u64,
    reg: Registry,
}

impl Slot {
    /// Mark the connection idle or busy. Returns `false` if it was evicted.
    fn set_idle(&self, idle: bool) -> bool {
        match lock(&self.reg).get_mut(&self.id) {
            Some(c) => {
                c.idle_since = idle.then(Instant::now);
                true
            }
            None => false,
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        lock(&self.reg).remove(&self.id);
    }
}

/// Register a new connection. When full, evict the connection that has been
/// idle longest (and at least `evict_after`), so idle connections cannot lock
/// everyone out; otherwise refuse the new connection.
fn admit(reg: &Registry, id: u64, stream: &UnixStream, limits: &Limits) -> Option<Slot> {
    let handle = stream.try_clone().ok()?;
    let mut map = lock(reg);
    if map.len() >= limits.max_clients {
        let now = Instant::now();
        let victim = map
            .iter()
            .filter_map(|(k, c)| c.idle_since.map(|t| (t, *k)))
            .filter(|(t, _)| now.duration_since(*t) >= limits.evict_after)
            .min()
            .map(|(_, k)| k)?;
        if let Some(c) = map.remove(&victim) {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
        log(format_args!(
            "connection limit reached; evicted the longest-idle connection"
        ));
    }
    map.insert(
        id,
        Conn {
            stream: handle,
            idle_since: Some(Instant::now()),
        },
    );
    Some(Slot {
        id,
        reg: Arc::clone(reg),
    })
}

/// Accept connections until `shutdown` is set.
pub fn serve(listener: &UnixListener, proxy: Arc<Proxy>, shutdown: &AtomicBool) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let me = socket::current_uid();
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let mut next_id: u64 = 0;
    while !shutdown.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Sleep until a connection arrives; wake periodically to
                // notice `shutdown`.
                if let Err(e) = socket::wait_readable(listener, Duration::from_millis(200)) {
                    log(format_args!("poll failed: {e}"));
                    thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // e.g. EMFILE: back off rather than spin.
                log(format_args!("accept failed: {e}"));
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        match socket::peer_uid(&stream) {
            Ok(uid) if uid == me => {}
            Ok(uid) => {
                log(format_args!("rejected connection from uid {uid}"));
                continue;
            }
            Err(e) => {
                log(format_args!(
                    "rejected connection: cannot read peer credentials: {e}"
                ));
                continue;
            }
        }
        if !proxy.resources.connection() {
            log(format_args!(
                "connection budget exhausted; closing new connection"
            ));
            continue;
        }
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        next_id += 1;
        let Some(slot) = admit(&registry, next_id, &stream, &proxy.limits) else {
            log(format_args!(
                "connection limit reached and no connection idle long enough to evict; closing new connection"
            ));
            continue;
        };
        let proxy = Arc::clone(&proxy);
        let spawned = thread::Builder::new()
            .name("sigsieve-client".into())
            .spawn(move || serve_client(stream, &proxy, &slot));
        if let Err(e) = spawned {
            // The closure (and its Slot) was dropped, releasing the entry.
            log(format_args!("cannot spawn client thread: {e}"));
        }
    }
    proxy.cancelled.store(true, Ordering::Relaxed);
    for conn in lock(&registry).values() {
        let _ = conn.stream.shutdown(Shutdown::Both);
    }
    if let Some(window) = LOG_WINDOW.get() {
        let count = window.lock().unwrap_or_else(|e| e.into_inner()).finish();
        if count > 0 {
            eprintln!("sigsieve: suppressed {count} repeated events before shutdown");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn unreachable_upstream() -> Upstream {
        Upstream::new("/nonexistent/sigsieve-test.sock", Duration::from_millis(50))
    }

    #[test]
    fn non_forwarded_operations_fail_locally() {
        let (p, _) = Policy::from_fingerprints::<&str>(&[]).unwrap();
        for t in 0u8..=255 {
            if t == protocol::SSH_AGENTC_REQUEST_IDENTITIES
                || t == protocol::SSH_AGENTC_SIGN_REQUEST
            {
                continue;
            }
            assert_eq!(
                Proxy::new(p.clone(), unreachable_upstream(), Limits::default())
                    .handle_request(&[t], &mut Bindings::default()),
                Some(vec![5])
            );
        }
    }

    #[test]
    fn sign_response_validation() {
        let response = |alg: &[u8], trailing: &[u8]| {
            let mut sig = Vec::new();
            protocol::put_string(&mut sig, alg);
            protocol::put_string(&mut sig, b"signature bytes");
            let mut out = vec![protocol::SSH_AGENT_SIGN_RESPONSE];
            protocol::put_string(&mut out, &sig);
            out.extend_from_slice(trailing);
            out
        };
        let alg = b"rsa-sha2-512";
        assert!(is_valid_sign_response(&response(alg, b""), alg));
        assert!(!is_valid_sign_response(&response(alg, &[9]), alg));
        assert!(!is_valid_sign_response(&response(b"ssh-rsa", b""), alg));
        assert!(!is_valid_sign_response(
            &response(b"rsa-sha2-256", b""),
            alg
        ));
        assert!(!is_valid_sign_response(&[14, 0, 0, 0, 1, 9], alg));
        assert!(!is_valid_sign_response(&[14, 0, 0, 0, 0], alg));
        assert!(!is_valid_sign_response(&[12, 0, 0, 0, 0], alg));
        assert!(!is_valid_sign_response(&[], alg));
    }

    #[test]
    fn recognized_extension_failure_is_distinct_from_unsupported_extension() {
        let fp = "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE";
        let (policy, _) = Policy::from_fingerprints(&[fp]).unwrap();
        let policy = policy.with_destinations(&[fp]).unwrap();
        for (name, expected) in [
            (SESSION_BIND, protocol::SSH_AGENT_EXTENSION_FAILURE),
            (b"unknown@example".as_slice(), protocol::SSH_AGENT_FAILURE),
        ] {
            let mut req = vec![protocol::SSH_AGENTC_EXTENSION];
            protocol::put_string(&mut req, name);
            assert_eq!(
                Proxy::new(policy.clone(), unreachable_upstream(), Limits::default())
                    .handle_request(&req, &mut Bindings::default()),
                Some(vec![expected])
            );
        }
    }

    proptest! {
        // Arbitrary requests never panic and, with an empty policy and no
        // upstream, always yield FAILURE.
        #[test]
        fn arbitrary_requests_fail_closed(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let (p, _) = Policy::from_fingerprints::<&str>(&[]).unwrap();
            prop_assert_eq!(Proxy::new(p, unreachable_upstream(), Limits::default()).handle_request(&data, &mut Bindings::default()), Some(vec![5]));
        }
    }
}
