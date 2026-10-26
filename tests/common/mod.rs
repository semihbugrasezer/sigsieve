//! Shared test helpers: a fake upstream agent, a proxy harness and a client.
//! All key material here is synthetic and generated solely for these tests.
#![allow(dead_code)]

use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use sigsieve::keys::Fingerprint;
use sigsieve::policy::Policy;
use sigsieve::protocol::{self, put_string, put_u32};
use sigsieve::proxy::{self, Limits, Proxy};
use sigsieve::socket::RuntimeSocket;
use sigsieve::upstream::Upstream;
use tempfile::TempDir;

/// A temporary directory created with mode 0700 whatever the umask. SigSieve
/// refuses group- or world-writable socket directories, so tests must not
/// rely on a 022 umask (Ubuntu gives users with private groups 002).
pub fn private_tempdir() -> TempDir {
    tempfile::Builder::new()
        .prefix("ss")
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

/// Secretive-style Secure Enclave identity: ECDSA P-256.
pub const ECDSA_CI: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA1abwZk+OzBA5adgQFl7Qrqk5/lKinYuHEaY4UOpQdWjJ6drflUMK1bAj3EbuPY1eK8iSv24Q108y8McHLkNYk=";
pub const ECDSA_CI_FP: &str = "SHA256:VRO/kv535DR0mIZ50/cjw2hm1/JzqMCFiQw2Iko9hXI";
pub const ECDSA_CI_COMMENT: &str = "ci-deploy@secretive.example.local";

pub const ED_ADMIN: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJodCRRgD2YmhX4C1i8E4CrhCRTjXD9w8Y3QnaoqwQqJ";
pub const ED_ADMIN_FP: &str = "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE";
pub const ED_ADMIN_COMMENT: &str = "privileged-admin@example";

pub const ED_PERSONAL: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQFUWrKG0MuzBEljkn3p2VVup/sQ5u3VmASKurN842H";
pub const ED_PERSONAL_FP: &str = "SHA256:2bGVY0+cQ52mlgPf3fYS9/lnifFeGvY9bqVJYX4S1KM";
pub const ED_PERSONAL_COMMENT: &str = "personal@example";

pub const RSA_LEGACY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHv5D4WLpHMocNgizCnJBpBSL1aoTF3JhC1tZpjRam4a9GiCh8lL+y/iT+KN+QY3srHhZAwFmsiQRa2Aaxeb47eUDD66y3ZrDRUdz71GwZWJs5nhuMs0OAcT9hKiUZ87pUcfSxtgTLuXruU54JflI1v4tAr+wTiKwG9wk/aKz4iqSoXOtlXEn1rJDbL4J0fJ/nQQUeL0mWkZiNUCbrHcrTIB97Rr6RUCl6ZXbyO1hx39XFlAXScIbkceEBc7Uq3kWpfqyHa6OUtsiUVXZUwEABMQfkUm/DrSxKSqBMbmHylh6+amzldHDxLYg8T51vK02rgvfat8+DpYs8ddghxlxJ";
pub const RSA_LEGACY_FP: &str = "SHA256:i5ZyJ0v3TndyWZIVkZBZoV3wQfM3fn8s1qjdhbqQtFE";
pub const RSA_LEGACY_COMMENT: &str = "legacy-rsa@example";

pub fn blob(line: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(line.split_whitespace().nth(1).unwrap())
        .unwrap()
}

/// The three-identity agent from the README scenario.
pub fn three_identities() -> Vec<(Vec<u8>, String)> {
    vec![
        (blob(ECDSA_CI), ECDSA_CI_COMMENT.into()),
        (blob(ED_ADMIN), ED_ADMIN_COMMENT.into()),
        (blob(ED_PERSONAL), ED_PERSONAL_COMMENT.into()),
    ]
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Behaves like a normal agent; answers anything else with SUCCESS so a
    /// wrongly forwarded mutation would be observable.
    Normal,
    /// Always replies SSH_AGENT_FAILURE.
    Failure,
    /// Replies with structurally invalid messages.
    Garbage,
    /// Accepts the request and never replies.
    Hang,
    /// Closes the connection without replying.
    Drop,
    /// Sends a frame header announcing more than MAX_FRAME bytes.
    Oversized,
    /// Answers sign requests with the wrong message type.
    WrongType,
    /// Like `Normal`, but ignores the flags and signs with legacy `ssh-rsa`
    /// (SHA-1), as an outdated or hostile upstream might.
    LegacySignature,
}

pub struct MockAgent {
    pub path: PathBuf,
    _dir: TempDir,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MockAgent {
    pub fn start(ids: Vec<(Vec<u8>, String)>, mode: Mode) -> MockAgent {
        let dir = private_tempdir();
        let path = dir.path().join("up.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (rx, sd) = (Arc::clone(&received), Arc::clone(&shutdown));
        let ids = Arc::new(ids);
        let thread = thread::spawn(move || {
            while !sd.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((s, _)) => {
                        s.set_nonblocking(false).unwrap();
                        let (rx, ids) = (Arc::clone(&rx), Arc::clone(&ids));
                        thread::spawn(move || mock_conn(s, &ids, mode, &rx));
                    }
                    Err(_) => {
                        let _ =
                            sigsieve::socket::wait_readable(&listener, Duration::from_millis(100));
                    }
                }
            }
        });
        MockAgent {
            path,
            _dir: dir,
            received,
            shutdown,
            thread: Some(thread),
        }
    }

    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }

    pub fn received_types(&self) -> Vec<u8> {
        self.received().iter().map(|m| m[0]).collect()
    }

    pub fn sign_requests(&self) -> Vec<Vec<u8>> {
        self.received()
            .into_iter()
            .filter(|m| m[0] == protocol::SSH_AGENTC_SIGN_REQUEST)
            .collect()
    }
}

impl Drop for MockAgent {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn mock_conn(mut s: UnixStream, ids: &[(Vec<u8>, String)], mode: Mode, rx: &Mutex<Vec<Vec<u8>>>) {
    let t = Duration::from_secs(30);
    while let Ok(Some(req)) = protocol::read_frame(&mut s, t, t) {
        rx.lock().unwrap().push(req.clone());
        let resp = match mode {
            Mode::Hang => {
                thread::sleep(Duration::from_secs(30));
                return;
            }
            Mode::Drop => return,
            Mode::Oversized => {
                let _ = s.write_all(&(protocol::MAX_FRAME as u32 + 1).to_be_bytes());
                return;
            }
            Mode::Failure => vec![protocol::SSH_AGENT_FAILURE],
            Mode::Garbage => match req[0] {
                protocol::SSH_AGENTC_REQUEST_IDENTITIES => vec![12, 0, 0, 0, 9],
                _ => vec![protocol::SSH_AGENT_SIGN_RESPONSE],
            },
            Mode::WrongType => match req[0] {
                protocol::SSH_AGENTC_SIGN_REQUEST => identities_answer(ids),
                _ => identities_answer(ids),
            },
            Mode::Normal | Mode::LegacySignature => match req[0] {
                protocol::SSH_AGENTC_REQUEST_IDENTITIES => identities_answer(ids),
                protocol::SSH_AGENTC_SIGN_REQUEST => {
                    let mut r = sigsieve::protocol::Reader::new(&req[1..]);
                    let key = r.string().unwrap().to_vec();
                    r.string().unwrap();
                    let flags = r.u32().unwrap();
                    // Name the algorithm as a real agent would: the flag picks
                    // the RSA hash, other key types sign with their own name.
                    let key_alg = sigsieve::protocol::Reader::new(&key).string().unwrap();
                    let alg: &[u8] = match (mode, key_alg, flags) {
                        (Mode::LegacySignature, _, _) => b"ssh-rsa",
                        (_, b"ssh-rsa", 0x02) => b"rsa-sha2-256",
                        (_, b"ssh-rsa", 0x04) => b"rsa-sha2-512",
                        (_, a, _) => a,
                    };
                    let mut sig = Vec::new();
                    put_string(&mut sig, alg);
                    put_string(&mut sig, Fingerprint::of_blob(&key).to_string().as_bytes());
                    let mut out = vec![protocol::SSH_AGENT_SIGN_RESPONSE];
                    put_string(&mut out, &sig);
                    out
                }
                _ => vec![protocol::SSH_AGENT_SUCCESS],
            },
        };
        if protocol::write_frame(&mut s, &resp).is_err() {
            return;
        }
    }
}

pub fn identities_answer(ids: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![protocol::SSH_AGENT_IDENTITIES_ANSWER];
    put_u32(&mut out, ids.len() as u32);
    for (b, c) in ids {
        put_string(&mut out, b);
        put_string(&mut out, c.as_bytes());
    }
    out
}

/// A proxy serving on a private socket in a background thread.
pub struct Harness {
    pub path: PathBuf,
    _dir: TempDir,
    rt: Option<RuntimeSocket>,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

pub fn test_limits() -> Limits {
    Limits {
        max_clients: 64,
        idle_timeout: Duration::from_secs(10),
        frame_timeout: Duration::from_secs(2),
        write_timeout: Duration::from_secs(2),
        evict_after: Duration::from_millis(200),
        // Throughput/property tests keep their exact authorization assertions;
        // production budgets are exercised separately with Limits::default().
        request_rate: 100_000,
        connection_rate: 100_000,
        signing_rate: 100_000,
        ..Limits::default()
    }
}

pub fn start_proxy(upstream: &Path, allow: &[&str]) -> Harness {
    start_proxy_with(upstream, allow, test_limits(), Duration::from_secs(5))
}

pub fn start_proxy_with(
    upstream: &Path,
    allow: &[&str],
    limits: Limits,
    upstream_timeout: Duration,
) -> Harness {
    let (policy, _) = Policy::from_fingerprints(allow).unwrap();
    let dir = private_tempdir();
    let (listener, rt) = RuntimeSocket::bind(Some(&dir.path().join("f.sock"))).unwrap();
    let path = rt.path().to_path_buf();
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let proxy = Arc::new(Proxy::new(
        policy,
        Upstream::new(upstream, upstream_timeout),
        limits,
    ));
    let thread = thread::spawn(move || {
        proxy::serve(&listener, proxy, &flag).unwrap();
    });
    Harness {
        path,
        _dir: dir,
        rt: Some(rt),
        shutdown,
        thread: Some(thread),
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.rt.take();
    }
}

pub fn connect(path: &Path) -> UnixStream {
    UnixStream::connect(path).unwrap()
}

/// Send one frame on an existing connection and read the reply.
pub fn roundtrip(s: &mut UnixStream, payload: &[u8]) -> Vec<u8> {
    protocol::write_frame(s, payload).unwrap();
    let t = Duration::from_secs(10);
    protocol::read_frame(s, t, t).unwrap().expect("reply")
}

pub fn request(path: &Path, payload: &[u8]) -> Vec<u8> {
    roundtrip(&mut connect(path), payload)
}

/// Exposed identities as (fingerprint, comment).
pub fn list(path: &Path) -> Vec<(String, String)> {
    let reply = request(path, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
    sigsieve::upstream::parse_identities_answer(&reply)
        .unwrap()
        .into_iter()
        .map(|i| {
            (
                Fingerprint::of_blob(&i.blob).to_string(),
                String::from_utf8(i.comment).unwrap(),
            )
        })
        .collect()
}

pub fn sign_request(key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut req = vec![protocol::SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut req, key);
    put_string(&mut req, data);
    put_u32(&mut req, flags);
    req
}

pub const FAILURE: [u8; 1] = [protocol::SSH_AGENT_FAILURE];

pub fn is_sign_response(r: &[u8]) -> bool {
    r.first() == Some(&protocol::SSH_AGENT_SIGN_RESPONSE)
}
