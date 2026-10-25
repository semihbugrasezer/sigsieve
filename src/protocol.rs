//! SSH agent wire protocol: framing and primitive field encoding.
//!
//! Reference: RFC 9987 ("SSH Agent Protocol"). Every message
//! is `uint32 length || byte type || payload`. All parsing here is over
//! untrusted bytes and must never panic.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Largest frame we accept, matching OpenSSH's `AGENT_MAX_LEN` (256 KiB).
pub const MAX_FRAME: usize = 256 * 1024;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

/// Signature flags we pass through: `SSH_AGENT_RSA_SHA2_256` and `_512`.
pub const ALLOWED_SIGN_FLAGS: u32 = 0x02 | 0x04;

#[derive(Debug)]
pub enum WireError {
    /// A field or frame ended before its declared length.
    Truncated,
    /// Bytes remained after a message that should have been fully consumed.
    TrailingData,
    /// Declared frame length exceeds [`MAX_FRAME`].
    TooLarge(usize),
    /// Zero-length frame (no message type).
    Empty,
    /// A frame did not complete before its deadline.
    Timeout,
    Io(io::Error),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "truncated message"),
            WireError::TrailingData => write!(f, "unexpected trailing data"),
            WireError::TooLarge(n) => write!(f, "frame of {n} bytes exceeds limit of {MAX_FRAME}"),
            WireError::Empty => write!(f, "empty frame"),
            WireError::Timeout => write!(f, "timed out"),
            WireError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => WireError::Timeout,
            io::ErrorKind::UnexpectedEof => WireError::Truncated,
            _ => WireError::Io(e),
        }
    }
}

/// Bounds-checked cursor over an untrusted message.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.buf.len() < n {
            return Err(WireError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// An SSH `string`: `uint32 length || bytes`.
    pub fn string(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// Require that the whole message was consumed.
    pub fn finish(self) -> Result<(), WireError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingData)
        }
    }
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    // Callers only encode data that came out of a frame bounded by MAX_FRAME.
    put_u32(
        out,
        u32::try_from(s.len()).expect("string length fits in u32"),
    );
    out.extend_from_slice(s);
}

/// The single-byte `SSH_AGENT_FAILURE` message.
pub fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

/// Set the read timeout. Returns `None` if the peer has already gone away:
/// macOS rejects `setsockopt` with EINVAL on a socket whose peer has closed.
fn set_timeout(s: &UnixStream, d: Duration) -> Result<Option<()>, WireError> {
    match s.set_read_timeout(Some(d)) {
        Ok(()) => Ok(Some(())),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Fill `buf` from `s`, giving up at `deadline`. The deadline is enforced
/// across reads so a peer trickling one byte at a time cannot hold us forever.
fn read_full(s: &mut UnixStream, buf: &mut [u8], deadline: Instant) -> Result<(), WireError> {
    let mut filled = 0;
    while filled < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(WireError::Timeout);
        }
        set_timeout(s, left)?.ok_or(WireError::Truncated)?;
        match s.read(&mut buf[filled..]) {
            Ok(0) => return Err(WireError::Truncated),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Read one frame and return its payload (type byte included).
///
/// Returns `Ok(None)` on a clean EOF between frames. `idle` bounds the wait
/// for the first byte; once a frame has started it must complete within
/// `frame`. Oversized and empty frames are rejected before allocating.
pub fn read_frame(
    s: &mut UnixStream,
    idle: Duration,
    frame: Duration,
) -> Result<Option<Vec<u8>>, WireError> {
    let mut hdr = [0u8; 4];
    if set_timeout(s, idle)?.is_none() {
        return Ok(None);
    }
    let first = loop {
        match s.read(&mut hdr) {
            Ok(n) => break n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    };
    if first == 0 {
        return Ok(None);
    }
    let deadline = Instant::now() + frame;
    read_full(s, &mut hdr[first..], deadline)?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len == 0 {
        return Err(WireError::Empty);
    }
    if len > MAX_FRAME {
        return Err(WireError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    read_full(s, &mut payload, deadline)?;
    Ok(Some(payload))
}

/// Write one frame. `payload` must be non-empty and within [`MAX_FRAME`].
pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to write invalid frame",
        ));
    }
    let mut buf = Vec::with_capacity(4 + payload.len());
    put_string(&mut buf, payload);
    w.write_all(&buf)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn reader_rejects_truncation_and_trailing() {
        assert!(matches!(
            Reader::new(&[0, 0, 0, 5, 1]).string(),
            Err(WireError::Truncated)
        ));
        let mut r = Reader::new(&[0, 0, 0, 1, 9, 7]);
        assert_eq!(r.string().unwrap(), &[9]);
        assert!(matches!(r.finish(), Err(WireError::TrailingData)));
    }

    #[test]
    fn huge_declared_string_does_not_allocate_or_panic() {
        assert!(matches!(
            Reader::new(&[0xff, 0xff, 0xff, 0xff]).string(),
            Err(WireError::Truncated)
        ));
    }

    #[test]
    fn frame_roundtrip_and_limits() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_frame(&mut a, &[11]).unwrap();
        let t = Duration::from_secs(1);
        assert_eq!(read_frame(&mut b, t, t).unwrap().unwrap(), vec![11]);

        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes()).unwrap();
        assert!(matches!(
            read_frame(&mut b, t, t),
            Err(WireError::TooLarge(_))
        ));
        a.write_all(&[0, 0, 0, 0]).unwrap();
        assert!(matches!(read_frame(&mut b, t, t), Err(WireError::Empty)));

        assert!(write_frame(&mut a, &[]).is_err());
        assert!(write_frame(&mut a, &vec![0; MAX_FRAME + 1]).is_err());

        drop(a);
        assert!(read_frame(&mut b, t, t).unwrap().is_none());
    }

    #[test]
    fn partial_frame_times_out() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&[0, 0, 0, 10, 1]).unwrap();
        let r = read_frame(&mut b, Duration::from_secs(1), Duration::from_millis(100));
        assert!(matches!(r, Err(WireError::Timeout)));
    }

    proptest! {
        #[test]
        fn reader_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut r = Reader::new(&data);
            while r.string().is_ok() {}
            let mut r = Reader::new(&data);
            let _ = r.u8();
            let _ = r.u32();
        }

        #[test]
        fn string_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut out = Vec::new();
            put_string(&mut out, &data);
            let mut r = Reader::new(&out);
            prop_assert_eq!(r.string().unwrap(), &data[..]);
            prop_assert!(r.finish().is_ok());
        }
    }
}
