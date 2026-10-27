//! Secure creation, inspection and cleanup of the downstream Unix socket.
//!
//! Rules:
//! - The socket lives in a directory owned by the current user that no other
//!   user can write to (a fresh 0700 temp dir by default).
//! - An existing path is never replaced or unlinked, except the socket of a
//!   SigSieve process that provably died without cleanup (`recover_stale`).
//! - On shutdown we unlink only the exact inode we created.
//! - Every accepted connection is checked against the current uid.

use std::collections::hash_map::RandomState;
use std::ffi::CStr;
use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub fn current_uid() -> u32 {
    // SAFETY: getuid(2) takes no arguments, touches no memory and cannot fail.
    unsafe { libc::getuid() }
}

/// Effective uid of the process on the other end of a connected socket.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the fd is owned by `s` and open for this call; uid/gid are valid
    // writable locals of the types getpeereid(3) expects.
    let rc = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// Effective uid of the process on the other end of a connected socket.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the fd is owned by `s`; `cred` is a valid, writable ucred and
    // `len` holds its exact size, as SO_PEERCRED requires.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Wait until `fd` is readable (e.g. a listener has a pending connection),
/// for at most `timeout`. Returns `Ok(false)` on timeout.
pub fn wait_readable(fd: &impl AsRawFd, timeout: std::time::Duration) -> io::Result<bool> {
    wait_event(fd, libc::POLLIN, timeout)
}

pub(crate) fn wait_writable(fd: &impl AsRawFd, timeout: Duration) -> io::Result<bool> {
    wait_event(fd, libc::POLLOUT, timeout)
}

fn wait_event(fd: &impl AsRawFd, events: libc::c_short, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events,
        revents: 0,
    };
    let ms =
        libc::c_int::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(libc::c_int::MAX);
    // SAFETY: `pfd` is a valid, writable pollfd for an fd owned by the caller
    // for the duration of the call, and the count passed is exactly 1.
    let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
    match rc {
        -1 => {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(e)
            }
        }
        0 => Ok(false),
        _ => Ok(true),
    }
}

/// Remaining I/O wait budget, checked between nonblocking operations.
pub(crate) fn time_left(deadline: Instant, cancelled: &AtomicBool) -> io::Result<Duration> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "request cancelled",
        ));
    }
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "request deadline exceeded",
        ));
    }
    Ok(left)
}

/// Connect without a blocking syscall; keep the stream nonblocking for the
/// whole request. Linux AF_UNIX EAGAIN means a full queue, not EINPROGRESS.
pub(crate) fn connect_until(
    path: &Path,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<UnixStream> {
    time_left(deadline, cancelled)?;
    // SAFETY: an all-zero sockaddr_un is a valid initialization; fields and
    // the bounded, NUL-terminated path are filled before passing it to connect.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dest, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dest = *src as libc::c_char;
    }
    let len =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        addr.sun_len = len as u8;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let kind = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let kind = libc::SOCK_STREAM;
    // SAFETY: socket takes scalar arguments and returns a new descriptor.
    let fd = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this is the newly created descriptor; the stream becomes its
    // sole owner and closes it on every following error path.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SAFETY: the descriptor is owned and open; this sets only CLOEXEC.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        stream.set_nonblocking(true)?;
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let one: libc::c_int = 1;
        // SAFETY: valid owned fd, pointer to an int and its exact size;
        // matches std's Apple socket setup before any connection or write.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: addr is initialized and lives through the call, len names only
    // its initialized header/path, and fd is owned and nonblocking.
    if unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len) } == 0 {
        time_left(deadline, cancelled)?;
        return Ok(stream);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(err);
    }
    loop {
        let left = time_left(deadline, cancelled)?;
        if wait_writable(&stream, left.min(Duration::from_millis(100)))? {
            if let Some(err) = stream.take_error()? {
                return Err(err);
            }
            time_left(deadline, cancelled)?;
            return Ok(stream);
        }
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn deadline_socket_is_nonblocking_and_close_on_exec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        let stream = connect_until(
            &path,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap();
        // SAFETY: fcntl reads flags on a descriptor owned by stream.
        let fd_flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
        // SAFETY: fcntl reads status flags on the same open descriptor.
        let status_flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
        assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
            // SAFETY: writable int and its exact size on an owned descriptor.
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_NOSIGPIPE,
                        (&mut value as *mut libc::c_int).cast(),
                        &mut len,
                    )
                },
                0
            );
            assert_eq!(value, 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_unix_listen_queue_cannot_block_upstream_connect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // SAFETY: change only this test's listener backlog. Linux permits one
        // pending connection with backlog zero; nothing accepts it.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let filler = UnixStream::connect(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result =
                crate::upstream::Upstream::new(path, Duration::from_millis(200)).identities();
            tx.send(matches!(result, Err(crate::upstream::UpstreamError::Unreachable(e)) if e.kind() == io::ErrorKind::WouldBlock)).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(1));
        drop(listener);
        drop(filler);
        worker.join().unwrap();
        assert_eq!(
            result,
            Ok(true),
            "a full socket queue must fail closed immediately"
        );
    }
}

/// Whether a process with this pid exists (used by `status`).
pub fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 performs only the existence/permission check; no
    // signal is delivered and no memory is involved.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Send SIGTERM to a process we started.
pub fn terminate(pid: u32) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        if pid > 0 {
            // SAFETY: kill(2) with a positive pid of our own child and a valid
            // signal number; no memory is involved.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }
}

/// A directory is safe to hold our socket if it is a real directory owned by
/// us and not writable by group or others (nobody else can swap entries).
pub fn check_private_dir(dir: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != current_uid() {
        return Err(format!(
            "{} is not owned by the current user",
            dir.display()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by group or others (mode {:o})",
            dir.display(),
            meta.mode() & 0o7777
        ));
    }
    let resolved = fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Some(parent) = resolved.parent() {
        check_ancestors(parent)?;
    }
    Ok(())
}

/// A trusted sticky directory (e.g. /tmp) protects our entry from other uids.
fn check_ancestors(dir: &Path) -> Result<(), String> {
    let me = current_uid();
    for ancestor in dir.ancestors() {
        let meta =
            fs::symlink_metadata(ancestor).map_err(|e| format!("{}: {e}", ancestor.display()))?;
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != me)
            || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0)
        {
            return Err(format!("unsafe socket ancestor {}: require root/current-user ownership and no group/other write access, or a sticky directory", ancestor.display()));
        }
    }
    Ok(())
}

/// Check an existing socket path: our socket, private mode, private parent.
pub fn check_socket(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symlink", path.display()));
    }
    if !meta.file_type().is_socket() {
        return Err(format!("{} is not a Unix socket", path.display()));
    }
    if meta.uid() != current_uid() {
        return Err(format!(
            "{} is not owned by the current user",
            path.display()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is accessible by group or others (mode {:o})",
            path.display(),
            meta.mode() & 0o777
        ));
    }
    check_private_dir(&parent_dir(path)?)
}

fn parent_dir(path: &Path) -> Result<PathBuf, String> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::canonicalize(parent).map_err(|e| format!("{}: {e}", parent.display()))
}

/// Identity of a filesystem object we created, so cleanup never removes a
/// file that was replaced after we made it.
#[derive(Debug, Clone, Copy)]
struct Inode {
    dev: u64,
    ino: u64,
}

impl Inode {
    fn of(path: &Path) -> io::Result<Inode> {
        let m = fs::symlink_metadata(path)?;
        Ok(Inode {
            dev: m.dev(),
            ino: m.ino(),
        })
    }

    fn remove_if_same(self, path: &Path) -> bool {
        match Inode::of(path) {
            Ok(now) if now.dev == self.dev && now.ino == self.ino => fs::remove_file(path).is_ok(),
            _ => false,
        }
    }
}

/// A bound downstream socket. Dropping it removes the socket, its state file
/// and (if we created it) the private runtime directory.
#[derive(Debug)]
pub struct RuntimeSocket {
    path: PathBuf,
    inode: Inode,
    state: Option<(PathBuf, Inode)>,
    owned_dir: Option<PathBuf>,
    recovered: Option<u32>,
}

impl RuntimeSocket {
    /// Bind at `path`, or in a fresh private temp directory when `None`.
    pub fn bind(path: Option<&Path>) -> io::Result<(UnixListener, RuntimeSocket)> {
        // Held until the new socket is bound: checking, recovering and
        // binding a given path is one step for every SigSieve instance.
        let _dir_lock;
        let (path, owned_dir) = match path {
            Some(p) => {
                let parent = parent_dir(p).map_err(io::Error::other)?;
                check_private_dir(&parent).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("unsafe socket directory: {e}"),
                    )
                })?;
                let name = p.file_name().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "socket path has no file name")
                })?;
                _dir_lock = lock_dir(&parent)?;
                (parent.join(name), None)
            }
            None => {
                let dir = create_private_temp_dir()?;
                (dir.join("agent.sock"), Some(dir))
            }
        };
        let cleanup_dir = |dir: &Option<PathBuf>| {
            if let Some(d) = dir {
                let _ = fs::remove_dir(d);
            }
        };
        let mut recovered = None;
        if fs::symlink_metadata(&path).is_ok() {
            cleanup_dir(&owned_dir);
            match recover_stale(&path) {
                Ok(pid) => recovered = Some(pid),
                Err(why) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "refusing to replace existing path {}: {why}",
                            path.display()
                        ),
                    ))
                }
            }
        }
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                cleanup_dir(&owned_dir);
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot bind {}: {e}", path.display()),
                ));
            }
        };
        let rt = RuntimeSocket {
            inode: Inode::of(&path)?,
            path,
            state: None,
            owned_dir,
            recovered,
        };
        // Defence in depth: the directory already excludes other users, and
        // every connection's peer uid is checked.
        fs::set_permissions(&rt.path, Permissions::from_mode(0o600))?;
        Ok((listener, rt))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Pid of the dead SigSieve whose stale socket this bind replaced.
    pub fn recovered_from(&self) -> Option<u32> {
        self.recovered
    }

    /// Path of the status file written next to the socket.
    pub fn state_path_for(socket: &Path) -> PathBuf {
        let mut s = socket.as_os_str().to_owned();
        s.push(".state");
        PathBuf::from(s)
    }

    /// Write the status file (mode 0600, never replacing an existing file).
    /// It records the socket's identity so a later instance can prove the
    /// socket is ours if this process dies without cleanup.
    pub fn write_state(&mut self, contents: &str) -> io::Result<()> {
        let path = Self::state_path_for(&self.path);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        self.state = Some((path.clone(), Inode::of(&path)?));
        f.write_all(contents.as_bytes())?;
        f.write_all(format!("socket_id={}:{}\n", self.inode.dev, self.inode.ino).as_bytes())
    }
}

impl Drop for RuntimeSocket {
    fn drop(&mut self) {
        self.inode.remove_if_same(&self.path);
        if let Some((p, ino)) = &self.state {
            ino.remove_if_same(p);
        }
        if let Some(d) = &self.owned_dir {
            // Only succeeds if empty: unexpected files are left in place.
            let _ = fs::remove_dir(d);
        }
    }
}

/// Take an exclusive advisory lock on a directory (released when the
/// returned handle is dropped), so concurrent SigSieve starts on one socket
/// path cannot interleave their check, recovery and bind.
fn lock_dir(dir: &Path) -> io::Result<fs::File> {
    let f = fs::File::open(dir)?;
    // SAFETY: flock(2) on a file descriptor we own; no memory is involved.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(f)
}

/// Largest state file `recover_stale` reads.
const MAX_STATE_LEN: u64 = 64 * 1024;

/// Remove the socket (and state file) a SigSieve process left behind when it
/// died without cleanup (SIGKILL, crash), and return that process's pid. Only
/// when everything proves it: the path is a socket we own (in a directory the
/// caller has checked is private), its private state file records this exact
/// socket (dev:inode) and a pid that no longer exists, and nothing accepts
/// connections on it. Removal re-checks the inodes, so a path replaced in
/// between, or recovered concurrently, is left alone. Otherwise the reason is
/// returned and nothing is touched.
pub fn recover_stale(path: &Path) -> Result<u32, String> {
    let manual = |why: &str| {
        format!(
            "{why}; if no SigSieve is using it, check with `sigsieve status --socket {p}` \
             and remove {p} (and {p}.state) yourself",
            p = path.display()
        )
    };
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_socket() || meta.uid() != current_uid() {
        return Err(manual("it is not a socket owned by you"));
    }
    let state_path = RuntimeSocket::state_path_for(path);
    let smeta = fs::symlink_metadata(&state_path)
        .map_err(|_| manual("there is no SigSieve state file next to it"))?;
    if !smeta.is_file()
        || smeta.uid() != current_uid()
        || smeta.mode() & 0o077 != 0
        || smeta.len() > MAX_STATE_LEN
    {
        return Err(manual("its state file is not a private regular file"));
    }
    let text = fs::read_to_string(&state_path).map_err(|e| manual(&e.to_string()))?;
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
    };
    let pid: u32 = field("pid")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| manual("its state file has no pid"))?;
    let recorded = field("socket_id")
        .and_then(|v| v.split_once(':'))
        .and_then(|(d, i)| Some((d.parse::<u64>().ok()?, i.parse::<u64>().ok()?)));
    if recorded != Some((meta.dev(), meta.ino())) {
        return Err(manual("its state file does not record this socket"));
    }
    if pid_alive(pid) {
        return Err(format!(
            "SigSieve process {pid} is still running for it (stop it first)"
        ));
    }
    match UnixStream::connect(path) {
        Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => {}
        Ok(_) => return Err("something is still accepting connections on it".into()),
        Err(e) => return Err(manual(&format!("cannot probe it ({e})"))),
    }
    let sock = Inode {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    if !sock.remove_if_same(path) {
        return Err("it changed while being checked".into());
    }
    Inode {
        dev: smeta.dev(),
        ino: smeta.ino(),
    }
    .remove_if_same(&state_path);
    Ok(pid)
}

fn create_private_temp_dir() -> io::Result<PathBuf> {
    let base = std::env::var_os("TMPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let base = fs::canonicalize(&base)?;
    check_ancestors(&base).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
    for _ in 0..16 {
        let mut h = RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        let dir = base.join(format!("sigsieve-{:012x}", h.finish() & 0xffff_ffff_ffff));
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {
                let meta = fs::symlink_metadata(&dir)?;
                if !meta.is_dir() || meta.uid() != current_uid() || meta.mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("runtime directory {} is not private", dir.display()),
                    ));
                }
                return Ok(dir);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique runtime directory",
    ))
}

/// The home directory from the password database, which is what ssh uses
/// for `~` (not `$HOME`).
pub fn home_dir() -> Option<PathBuf> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: passwd is a plain C struct; all-zero (null pointers, zero ids)
    // is a valid value and getpwuid_r overwrites it.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r writes only into `pw` and `buf` (whose length is
    // passed) and sets `out` to `&pw` or null; strings in `pw` point into
    // `buf`, which outlives their use below.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string inside `buf`.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    Some(path_from_c(dir))
}

/// Byte-exact: a non-UTF-8 home must name the same directory ssh uses.
fn path_from_c(dir: &CStr) -> PathBuf {
    PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_dir_bytes_are_preserved_exactly() {
        // A lossy conversion would turn a non-UTF-8 home into a different,
        // missing path, and the ssh_config pre-scan would skip the real
        // ~/.ssh/config that ssh reads.
        let raw = b"/home/caf\xe9\xff";
        let c = std::ffi::CString::new(&raw[..]).unwrap();
        assert_eq!(path_from_c(&c).as_os_str().as_bytes(), raw);
    }

    #[test]
    fn remove_if_same_unlinks_only_the_recorded_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sock");

        // Same inode: removed.
        fs::write(&path, b"ours").unwrap();
        let ours = Inode::of(&path).unwrap();
        assert!(ours.remove_if_same(&path));
        assert!(!path.exists());

        // Already gone: nothing to do.
        let gone = Inode {
            dev: ours.dev,
            ino: ours.ino,
        };
        assert!(!gone.remove_if_same(&path));

        // Replaced by another file: kept. The original stays linked
        // elsewhere so its inode number cannot be reused.
        let original = dir.path().join("original");
        fs::write(&original, b"ours").unwrap();
        let recorded = Inode::of(&original).unwrap();
        fs::write(&path, b"theirs").unwrap();
        assert!(!recorded.remove_if_same(&path));
        assert_eq!(fs::read(&path).unwrap(), b"theirs");
        fs::remove_file(&path).unwrap();

        // Replaced by a symlink to the recorded file: neither is removed.
        std::os::unix::fs::symlink(&original, &path).unwrap();
        let recorded = Inode::of(&original).unwrap();
        assert!(!recorded.remove_if_same(&path));
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&original).unwrap(), b"ours");
    }
}
