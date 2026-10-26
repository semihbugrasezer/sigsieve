//! Client for the upstream (real) SSH agent.
//!
//! Each request uses a fresh connection, so no upstream protocol state is
//! shared between downstream clients. Before any bytes are sent we check that
//! the endpoint is a socket owned by, and served by a process running as, the
//! current user.

use std::fmt;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use crate::protocol::{self, Reader, WireError, SSH_AGENTC_REQUEST_IDENTITIES};
use crate::socket;

static NOT_CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub enum UpstreamError {
    Unreachable(io::Error),
    UntrustedSocket(String),
    Protocol(WireError),
    /// Upstream closed the connection without replying.
    Closed,
    /// Upstream replied with an unexpected message.
    UnexpectedReply(u8),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Unreachable(e) => write!(f, "upstream agent unreachable: {e}"),
            UpstreamError::UntrustedSocket(why) => write!(f, "upstream socket rejected: {why}"),
            UpstreamError::Protocol(e) => write!(f, "upstream protocol error: {e}"),
            UpstreamError::Closed => write!(f, "upstream agent closed the connection"),
            UpstreamError::UnexpectedReply(t) => {
                write!(f, "upstream sent unexpected reply type {t}")
            }
        }
    }
}

impl std::error::Error for UpstreamError {}

impl From<WireError> for UpstreamError {
    fn from(e: WireError) -> Self {
        UpstreamError::Protocol(e)
    }
}

pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    path: PathBuf,
    timeout: Duration,
}

impl Upstream {
    /// `timeout` bounds a whole request/response exchange. It must be long
    /// enough for user presence checks (Touch ID) in agents like Secretive.
    pub fn new(path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Upstream {
            path: path.into(),
            timeout,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<UnixStream, UpstreamError> {
        let meta = std::fs::metadata(&self.path).map_err(UpstreamError::Unreachable)?;
        let me = socket::current_uid();
        if !meta.file_type().is_socket() {
            return Err(UpstreamError::UntrustedSocket("not a Unix socket".into()));
        }
        if meta.uid() != me {
            return Err(UpstreamError::UntrustedSocket(format!(
                "socket owned by uid {}, expected {me}",
                meta.uid()
            )));
        }
        let s = socket::connect_until(&self.path, deadline, cancelled)
            .map_err(UpstreamError::Unreachable)?;
        // The file check above is racy; the peer credential is not.
        match socket::peer_uid(&s) {
            Ok(uid) if uid == me => {}
            Ok(uid) => {
                return Err(UpstreamError::UntrustedSocket(format!(
                    "agent process runs as uid {uid}, expected {me}"
                )))
            }
            Err(e) => return Err(UpstreamError::Unreachable(e)),
        }
        Ok(s)
    }

    /// Send one request and return the raw reply payload.
    pub fn request(&self, payload: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        self.request_until(payload, self.deadline(), &NOT_CANCELLED)
    }

    pub(crate) fn deadline(&self) -> Instant {
        // Unrepresentable durations fail closed instead of panicking.
        Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now)
    }

    pub(crate) fn request_until(
        &self,
        payload: &[u8],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, UpstreamError> {
        let mut s = self.connect(deadline, cancelled)?;
        protocol::write_frame_until(&mut s, payload, deadline, cancelled)
            .map_err(UpstreamError::Unreachable)?;
        protocol::read_frame_until(&mut s, deadline, cancelled)?.ok_or(UpstreamError::Closed)
    }

    /// Fetch and strictly parse the upstream identity list.
    pub fn identities(&self) -> Result<Vec<Identity>, UpstreamError> {
        self.identities_cancellable(&NOT_CANCELLED)
    }

    pub fn identities_cancellable(
        &self,
        cancelled: &AtomicBool,
    ) -> Result<Vec<Identity>, UpstreamError> {
        let reply =
            self.request_until(&[SSH_AGENTC_REQUEST_IDENTITIES], self.deadline(), cancelled)?;
        parse_identities_answer(&reply)
    }
}

pub fn parse_identities_answer(reply: &[u8]) -> Result<Vec<Identity>, UpstreamError> {
    let mut r = Reader::new(reply);
    let t = r.u8()?;
    if t != protocol::SSH_AGENT_IDENTITIES_ANSWER {
        return Err(UpstreamError::UnexpectedReply(t));
    }
    let n = r.u32()?;
    // No preallocation from the untrusted count; the frame limit bounds it.
    let mut ids = Vec::new();
    for _ in 0..n {
        let blob = r.string()?.to_vec();
        let comment = r.string()?.to_vec();
        ids.push(Identity { blob, comment });
    }
    r.finish()?;
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrepresentable_timeout_fails_closed() {
        let deadline = Upstream::new("/unused", Duration::MAX).deadline();
        assert!(deadline <= Instant::now());
    }

    #[test]
    fn trickling_reply_cannot_restart_the_request_deadline() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        use std::time::Instant;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let t = Duration::from_secs(2);
            protocol::read_frame(&mut s, t, t).unwrap().unwrap();
            std::thread::sleep(Duration::from_millis(300));
            let _ = s.write_all(&[0]);
            std::thread::sleep(Duration::from_millis(300));
            let _ = s.write_all(&[0, 0, 5, 12, 0, 0, 0, 0]);
        });
        let started = Instant::now();
        let result = Upstream::new(path, Duration::from_millis(400)).identities();
        let elapsed = started.elapsed();
        worker.join().unwrap();
        assert!(
            result.is_err(),
            "a late complete reply must not be accepted"
        );
        assert!(
            elapsed < Duration::from_millis(600),
            "request took {elapsed:?}"
        );
    }

    #[test]
    fn cancellation_stops_a_stalled_upstream_without_retry() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        use std::sync::{atomic::Ordering, Arc};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let t = Duration::from_secs(2);
            protocol::read_frame(&mut s, t, t).unwrap().unwrap();
            tx.send(()).unwrap();
            s.set_read_timeout(Some(t)).unwrap();
            let mut byte = [0];
            assert_eq!(
                s.read(&mut byte).unwrap(),
                0,
                "cancelled client must disconnect"
            );
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancelled);
        let trigger = std::thread::spawn(move || {
            rx.recv_timeout(Duration::from_secs(2)).unwrap();
            stop.store(true, Ordering::Relaxed);
        });
        let upstream = Upstream::new(path, Duration::from_secs(5));
        let started = Instant::now();
        let result = upstream.request_until(
            &[SSH_AGENTC_REQUEST_IDENTITIES],
            upstream.deadline(),
            &cancelled,
        );
        let elapsed = started.elapsed();
        trigger.join().unwrap();
        worker.join().unwrap();
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert!(
            elapsed < Duration::from_secs(1),
            "cancellation took {elapsed:?}"
        );
    }

    #[test]
    fn identities_answer_parsing_is_strict() {
        assert!(parse_identities_answer(&[12, 0, 0, 0, 0])
            .unwrap()
            .is_empty());
        // Count larger than the entries present.
        assert!(parse_identities_answer(&[12, 0xff, 0xff, 0xff, 0xff]).is_err());
        // Trailing junk.
        assert!(parse_identities_answer(&[12, 0, 0, 0, 0, 1]).is_err());
        // Wrong type.
        assert!(matches!(
            parse_identities_answer(&[5]),
            Err(UpstreamError::UnexpectedReply(5))
        ));
    }
}
