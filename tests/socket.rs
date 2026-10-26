//! Socket creation, permission and cleanup tests.

mod common;

use std::fs::{self, Permissions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;

use common::private_tempdir;
use sigsieve::socket::{check_private_dir, check_socket, RuntimeSocket};

fn mode(p: &std::path::Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o777
}

#[test]
fn default_runtime_dir_is_private_and_cleaned_up() {
    let (_l, rt) = RuntimeSocket::bind(None).unwrap();
    let sock = rt.path().to_path_buf();
    let dir = sock.parent().unwrap().to_path_buf();
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&sock), 0o600);
    assert!(fs::symlink_metadata(&sock).unwrap().file_type().is_socket());
    assert!(check_socket(&sock).is_ok());
    drop(rt);
    assert!(!sock.exists());
    assert!(!dir.exists());
}

#[test]
fn explicit_socket_in_private_dir_is_cleaned_up_with_state_file() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    let (_l, mut rt) = RuntimeSocket::bind(Some(&path)).unwrap();
    rt.write_state("pid=1\n").unwrap();
    let state = RuntimeSocket::state_path_for(rt.path());
    assert_eq!(mode(&state), 0o600);
    drop(rt);
    assert!(!path.exists());
    assert!(!state.exists());
    assert!(dir.path().exists(), "caller's directory must be left alone");
}

#[test]
fn existing_regular_file_is_never_replaced() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    fs::write(&path, b"precious").unwrap();
    let err = RuntimeSocket::bind(Some(&path)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path).unwrap(), b"precious");
}

#[test]
fn existing_socket_is_never_replaced() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    let _other = UnixListener::bind(&path).unwrap();
    assert!(RuntimeSocket::bind(Some(&path)).is_err());
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
}

#[test]
fn symlink_at_socket_path_is_refused() {
    let dir = private_tempdir();
    let target = dir.path().join("target");
    fs::write(&target, b"victim").unwrap();
    let path = dir.path().join("agent.sock");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(RuntimeSocket::bind(Some(&path)).is_err());
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&target).unwrap(), b"victim");

    // Dangling symlink too.
    let dangling = dir.path().join("dangling.sock");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
    assert!(RuntimeSocket::bind(Some(&dangling)).is_err());
    assert!(!dir.path().join("nowhere").exists());
}

#[test]
fn group_or_world_writable_parent_is_refused() {
    let dir = private_tempdir();
    for m in [0o777, 0o770, 0o1777] {
        fs::set_permissions(dir.path(), Permissions::from_mode(m)).unwrap();
        let err = RuntimeSocket::bind(Some(&dir.path().join("agent.sock"))).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "mode {m:o}"
        );
        assert!(check_private_dir(dir.path()).is_err());
    }
    fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
    assert!(check_private_dir(dir.path()).is_ok());
}

#[test]
fn writable_ancestor_is_refused_even_with_a_private_socket_parent() {
    let dir = private_tempdir();
    let ancestor = dir.path().join("shared");
    let parent = ancestor.join("private");
    fs::create_dir(&ancestor).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
    for mode in [0o770, 0o777] {
        fs::set_permissions(&ancestor, Permissions::from_mode(mode)).unwrap();
        let result = RuntimeSocket::bind(Some(&parent.join("agent.sock")));
        assert!(
            result.is_err(),
            "unsafe ancestor mode {mode:o} was accepted"
        );
        assert!(check_private_dir(&parent).is_err());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }
    // Sticky directories prevent another uid from renaming our child entry.
    fs::set_permissions(&ancestor, Permissions::from_mode(0o1777)).unwrap();
    assert!(RuntimeSocket::bind(Some(&parent.join("agent.sock"))).is_ok());
}

#[test]
fn replaced_socket_is_not_deleted_on_cleanup() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    let (_l, rt) = RuntimeSocket::bind(Some(&path)).unwrap();
    // Something else takes over the path after we bound it.
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"someone else's file").unwrap();
    drop(rt);
    assert_eq!(fs::read(&path).unwrap(), b"someone else's file");
}

#[test]
fn unexpected_files_keep_owned_runtime_dir_in_place() {
    let (_l, rt) = RuntimeSocket::bind(None).unwrap();
    let dir = rt.path().parent().unwrap().to_path_buf();
    let stray = dir.join("unexpected");
    fs::write(&stray, b"x").unwrap();
    drop(rt);
    assert!(
        stray.exists(),
        "cleanup must not delete files it did not create"
    );
    fs::remove_file(&stray).unwrap();
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn check_socket_flags_unsafe_modes_and_non_sockets() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    let _l = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o666)).unwrap();
    assert!(check_socket(&path).is_err());
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    assert!(check_socket(&path).is_ok());

    let file = dir.path().join("plain");
    fs::write(&file, b"").unwrap();
    fs::set_permissions(&file, Permissions::from_mode(0o600)).unwrap();
    assert!(check_socket(&file).is_err());
    assert!(check_socket(&dir.path().join("missing")).is_err());
}

#[test]
fn concurrent_binds_to_same_path_have_one_winner() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    let results: Vec<_> = (0..8)
        .map(|_| {
            let p = path.clone();
            std::thread::spawn(move || RuntimeSocket::bind(Some(&p)).ok())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_some()).count(), 1);
}

/// Serializes forks and listener lifetimes in these tests: macOS has no
/// SOCK_CLOEXEC, so a child forked while another test's listener is open can
/// inherit it and keep a "dead" socket accepting connections.
static FORK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Pid of a process that has exited.
fn dead_pid() -> u32 {
    let _g = FORK.lock().unwrap_or_else(|e| e.into_inner());
    let mut c = std::process::Command::new("true").spawn().unwrap();
    let pid = c.id();
    c.wait().unwrap();
    pid
}

/// A socket and state file as left by a SigSieve that was SIGKILLed: the
/// listener is gone and nothing was cleaned up.
fn killed_instance(path: &std::path::Path, pid: u32) {
    let _g = FORK.lock().unwrap_or_else(|e| e.into_inner());
    let (listener, mut rt) = RuntimeSocket::bind(Some(path)).unwrap();
    rt.write_state(&format!("pid={pid}\n")).unwrap();
    std::mem::forget(rt);
    drop(listener);
}

#[test]
fn socket_of_a_dead_sigsieve_is_recovered() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    let pid = dead_pid();
    killed_instance(&path, pid);
    let (_l, rt) = RuntimeSocket::bind(Some(&path)).unwrap();
    assert_eq!(rt.recovered_from(), Some(pid));
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    assert!(!RuntimeSocket::state_path_for(&path).exists());
}

#[test]
fn stale_looking_sockets_are_kept_unless_provably_ours() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    let state = RuntimeSocket::state_path_for(&path);
    let refused = |why: &str| {
        let err = RuntimeSocket::bind(Some(&path)).unwrap_err().to_string();
        assert!(err.contains("refusing to replace"), "{why}: {err}");
        assert!(fs::symlink_metadata(&path).is_ok(), "{why}: path removed");
        err
    };

    // The recorded process is still alive (e.g. stopped, or pid reused).
    killed_instance(&path, std::process::id());
    assert!(refused("live pid").contains("still running"));
    fs::remove_file(&path).unwrap();
    fs::remove_file(&state).unwrap();

    // Something still listens on it.
    killed_instance(&path, dead_pid());
    fs::remove_file(&path).unwrap();
    let _listener = UnixListener::bind(&path).unwrap();
    let ino = fs::symlink_metadata(&path).unwrap();
    fs::write(
        &state,
        format!(
            "pid={}\nsocket_id={}:{}\n",
            dead_pid(),
            ino.dev(),
            ino.ino()
        ),
    )
    .unwrap();
    fs::set_permissions(&state, Permissions::from_mode(0o600)).unwrap();
    assert!(refused("listening").contains("accepting connections"));
    drop(_listener);

    // A state file recording a different socket.
    fs::write(&state, format!("pid={}\nsocket_id=1:2\n", dead_pid())).unwrap();
    assert!(refused("other socket").contains("does not record this socket"));

    // A group-readable state file, or one that is a symlink.
    fs::set_permissions(&state, Permissions::from_mode(0o640)).unwrap();
    assert!(refused("open state").contains("not a private regular file"));
    fs::remove_file(&state).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    fs::write(
        &elsewhere,
        format!(
            "pid={}\nsocket_id={}:{}\n",
            dead_pid(),
            ino.dev(),
            ino.ino()
        ),
    )
    .unwrap();
    std::os::unix::fs::symlink(&elsewhere, &state).unwrap();
    assert!(refused("symlinked state").contains("not a private regular file"));
    fs::remove_file(&state).unwrap();

    // No state file at all: someone else's socket.
    assert!(refused("no state").contains("no SigSieve state file"));
    fs::remove_file(&path).unwrap();

    // A regular file at the path is never removed.
    fs::write(&path, b"data").unwrap();
    assert!(refused("regular file").contains("not a socket"));
    assert_eq!(fs::read(&path).unwrap(), b"data");
}

#[test]
fn concurrent_recovery_has_one_winner() {
    let dir = private_tempdir();
    let path = dir.path().join("agent.sock");
    killed_instance(&path, dead_pid());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (path, barrier) = (path.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                RuntimeSocket::bind(Some(&path))
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
}
