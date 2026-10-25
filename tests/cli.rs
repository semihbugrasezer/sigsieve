//! Tests that drive the real `sigsieve` binary.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::*;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigsieve"));
    // Never let the developer's environment leak into tests.
    c.env_remove("SSH_AUTH_SOCK")
        .env_remove("SIGSIEVE_UPSTREAM")
        .env_remove("SIGSIEVE_ALLOW");
    c
}

fn out(c: &mut Command) -> Output {
    c.output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {path:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// A spawned `sigsieve run` that is killed if the test fails early, so a
/// failing assertion never leaves an orphaned process behind.
struct RunGuard(Option<Child>);

impl RunGuard {
    fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    fn finish(mut self) -> Output {
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if let Some(c) = &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn spawn_run(upstream: &Path, socket: &Path, allow: &[&str]) -> RunGuard {
    let mut c = bin();
    c.arg("run")
        .arg("--upstream")
        .arg(upstream)
        .arg("--socket")
        .arg(socket);
    for a in allow {
        c.args(["--allow-fingerprint", a]);
    }
    let child = c
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let guard = RunGuard(Some(child));
    wait_for(&sigsieve::socket::RuntimeSocket::state_path_for(socket));
    guard
}

fn signal(child: &RunGuard, sig: i32) {
    // SAFETY: sending a signal to our own child process by pid.
    assert_eq!(unsafe { libc::kill(child.id() as i32, sig) }, 0);
}

#[test]
fn help_and_version() {
    let o = out(bin().arg("--help"));
    assert!(o.status.success());
    for cmd in ["run", "doctor", "status", "connect"] {
        assert!(stdout(&o).contains(cmd));
    }
    let o = out(bin().arg("--version"));
    assert!(o.status.success());
    assert!(stdout(&o).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn invalid_fingerprint_fails_closed_without_creating_a_socket() {
    let dir = private_tempdir();
    let sock = dir.path().join("f.sock");
    let o = out(bin()
        .args(["run", "--upstream", "/nonexistent", "--socket"])
        .arg(&sock)
        .args([
            "--allow-fingerprint",
            ECDSA_CI_FP,
            "--allow-fingerprint",
            "SHA256:bogus",
        ]));
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("invalid fingerprint"));
    assert!(!sock.exists());
}

#[test]
fn missing_upstream_is_a_configuration_error() {
    let o = out(bin().args(["run", "--allow-fingerprint", ECDSA_CI_FP]));
    assert_eq!(o.status.code(), Some(2));
    // SSH_AUTH_SOCK is not an implicit upstream.
    let o = out(bin().env("SSH_AUTH_SOCK", "/tmp/whatever").args([
        "doctor",
        "--allow-fingerprint",
        ECDSA_CI_FP,
    ]));
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn run_filters_and_cleans_up_on_sigterm_and_sigint() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        let dir = private_tempdir();
        let sock = dir.path().join("f.sock");
        let child = spawn_run(&up.path, &sock, &[ECDSA_CI_FP, ECDSA_CI_FP]);
        assert_eq!(list(&sock).len(), 1);
        signal(&child, sig);
        let o = child.finish();
        assert!(o.status.success(), "signal {sig}: {o:?}");
        assert!(stderr(&o).contains("duplicate allowlist entry"));
        assert!(stdout(&o).contains("SSH_AUTH_SOCK="));
        assert!(!sock.exists(), "socket left behind after signal {sig}");
        assert!(!sigsieve::socket::RuntimeSocket::state_path_for(&sock).exists());
    }
}

#[test]
fn killed_process_socket_is_reported_then_recovered() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let sock = dir.path().join("f.sock");
    let child = spawn_run(&up.path, &sock, &[ECDSA_CI_FP]);
    let dead = child.id();
    signal(&child, libc::SIGKILL);
    let _ = child.finish();
    assert!(sock.exists(), "SIGKILL cannot run cleanup");
    // status reports the dead process instead of claiming filtering is active.
    let o = out(bin().arg("status").arg("--socket").arg(&sock));
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("NOT RUNNING"));
    // A new instance proves the socket is the dead one's and takes it over.
    // (spawn_run returns as soon as a state file exists, so wait for the new
    // instance's own.)
    let child = spawn_run(&up.path, &sock, &[ECDSA_CI_FP]);
    let state = sigsieve::socket::RuntimeSocket::state_path_for(&sock);
    let start = Instant::now();
    while !fs::read_to_string(&state)
        .unwrap_or_default()
        .contains(&format!("pid={}\n", child.id()))
    {
        assert!(start.elapsed() < Duration::from_secs(10), "no new state");
        thread::sleep(Duration::from_millis(20));
    }
    let o = out(bin().arg("status").arg("--socket").arg(&sock));
    assert!(o.status.success(), "{}", stdout(&o));
    assert!(stdout(&o).contains(&format!("running (pid {})", child.id())));
    signal(&child, libc::SIGTERM);
    let o = child.finish();
    assert!(
        stderr(&o).contains(&format!("stale socket left by SigSieve process {dead}")),
        "{}",
        stderr(&o)
    );
    assert!(!sock.exists());
}

#[test]
fn doctor_reports_without_revealing_hidden_identities() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let o = out(bin()
        .args(["doctor", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP]));
    let text = stdout(&o);
    assert!(o.status.success(), "{text}");
    assert!(text.contains("Upstream agent:     reachable (3 identities)"));
    assert!(text.contains("Approved identities: 1/1 available"));
    assert!(text.contains(ECDSA_CI_FP));
    assert!(text.contains("Hidden identities:  2 (not shown)"));
    assert!(text.contains("Filtering:          verified"));
    for hidden in [
        ED_ADMIN_FP,
        ED_ADMIN_COMMENT,
        ED_PERSONAL_FP,
        ED_PERSONAL_COMMENT,
    ] {
        assert!(!text.contains(hidden), "doctor leaked {hidden}");
        assert!(!stderr(&o).contains(hidden), "doctor leaked {hidden}");
    }
    // The self-test's sign probe never reached the upstream agent.
    assert!(up.sign_requests().is_empty());
}

#[test]
fn doctor_fails_on_missing_identity_unreachable_upstream_and_bad_config() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let o = out(bin()
        .args(["doctor", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", RSA_LEGACY_FP]));
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("missing    ".to_string().as_str()));

    let o = out(bin().args([
        "doctor",
        "--upstream",
        "/nonexistent/agent.sock",
        "--allow-fingerprint",
        ECDSA_CI_FP,
    ]));
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("Upstream agent:     FAIL"));

    let o = out(bin().args(["doctor", "--upstream", "/x", "--allow-fingerprint", "nope"]));
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn doctor_checks_filtered_socket_permissions() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let sock = dir.path().join("f.sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o666)).unwrap();
    let o = out(bin()
        .args(["doctor", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--socket"])
        .arg(&sock));
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("Filtered socket:    FAIL"));
}

#[test]
fn status_reports_live_state() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let sock = dir.path().join("f.sock");
    let child = spawn_run(&up.path, &sock, &[ECDSA_CI_FP]);
    let o = out(bin().arg("status").env("SSH_AUTH_SOCK", &sock));
    let text = stdout(&o);
    assert!(o.status.success(), "{text}");
    assert!(text.contains(&format!("SigSieve process:   running (pid {})", child.id())));
    assert!(text.contains("Exposed identities: 1"));
    assert!(text.contains(ECDSA_CI_FP));
    assert!(text.contains("Filtering:          active"));
    assert!(!text.contains(ED_ADMIN_FP));
    signal(&child, libc::SIGTERM);
    let _ = child.finish();
}

#[test]
fn status_does_not_vouch_for_an_unfiltered_agent() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let o = out(bin().arg("status").arg("--socket").arg(&up.path));
    let text = stdout(&o);
    assert_eq!(o.status.code(), Some(1));
    assert!(text.contains("Exposed identities: 3"));
    assert!(text.contains("NOT VERIFIED"));
    // Without SigSieve state it lists counts only, never key details.
    assert!(!text.contains(ED_ADMIN_FP));
}

/// A stand-in `ssh` that records how it was invoked. In `-G` mode it prints
/// an effective configuration like real ssh (`forwardagent` from our `-o`,
/// unless overridden, plus `extra_g` lines), or for a `-W` proxy hop that of
/// a plain stdio relay; otherwise it lists the identities reachable through
/// the forwarded socket using the real `ssh-add`.
fn fake_ssh(dir: &Path, forward_override: Option<&str>, extra_g: &str) -> PathBuf {
    let script = dir.join("ssh");
    let fwd = match forward_override {
        Some(v) => format!("echo 'forwardagent {v}'"),
        None => "echo \"forwardagent $fa\"".to_string(),
    };
    let body = format!(
        r#"#!/bin/sh
out="{out}"
fa=""
ia=""
caf=""
x11="yes"
relay=""
for a in "$@"; do
  case "$a" in
    ForwardAgent=*) fa="${{a#ForwardAgent=}}";;
    IdentityAgent=*) ia=1;;
    ClearAllForwardings=yes) caf=1;;
    ForwardX11=no) x11=no;;
    -W) relay=1;;
  esac
done
if [ "$1" = "-G" ] && [ -n "$relay" ]; then
  echo "sessiontype none"
  echo "clearallforwardings yes"
  echo "proxycommand none"
  exit 0
fi
if [ "$1" = "-G" ]; then
  {fwd}
  echo "controlmaster false"
  echo "forwardx11 $x11"
  [ -n "$ia" ] && echo "identityagent $SIGSIEVE_LOGIN_AGENT"
  [ -n "$caf" ] && echo "clearallforwardings yes"
  printf '%s' "{extra_g}"
  exit 0
fi
echo "$@" > "$out/args"
echo "$SSH_AUTH_SOCK" > "$out/auth_sock"
echo "$SIGSIEVE_LOGIN_AGENT" > "$out/login_agent"
echo "$fa" > "$out/forwarded"
SSH_AUTH_SOCK="$fa" ssh-add -l > "$out/listing" 2>&1
exit 7
"#,
        out = dir.display()
    );
    fs::write(&script, body).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    script
}

/// `path` written relative to $HOME as `~/…`, or as is if outside $HOME.
fn tilde(path: &Path) -> String {
    let p = path.display().to_string();
    match std::env::var("HOME") {
        Ok(h) if p.starts_with(&h) => format!("~{}", &p[h.len()..]),
        _ => p,
    }
}

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn connect_forwards_only_the_filtered_socket_and_cleans_up() {
    if !have("ssh-add") {
        eprintln!("skipping: ssh-add not installed");
        return;
    }
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let ssh = fake_ssh(dir.path(), None, "");
    let o = out(bin()
        .env("SSH_AUTH_SOCK", "/original/login/agent.sock")
        .args(["connect", "ci-host", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
        .arg(&ssh)
        .args(["--", "-p", "2222", "uptime"]));
    assert_eq!(o.status.code(), Some(7), "{}", stderr(&o));
    let read = |n: &str| fs::read_to_string(dir.path().join(n)).unwrap();
    let listing = read("listing");
    assert!(listing.contains(ECDSA_CI_FP), "{listing}");
    assert!(!listing.contains(ED_ADMIN_FP) && !listing.contains(ED_PERSONAL_FP));
    assert_eq!(listing.lines().count(), 1, "{listing}");
    // Login authentication still uses the user's own agent, but via
    // IdentityAgent; ssh and its children see SSH_AUTH_SOCK = filtered socket.
    let forwarded = PathBuf::from(read("forwarded").trim());
    assert_eq!(PathBuf::from(read("auth_sock").trim()), forwarded);
    assert_eq!(read("login_agent").trim(), "/original/login/agent.sock");
    assert_ne!(forwarded, up.path);
    assert_eq!(
        read("args").trim(),
        format!(
            "-o ForwardAgent={} -o ControlPath=none -o ControlMaster=no \
             -o ForwardX11=no -o ClearAllForwardings=yes -o IdentityAgent=${{SIGSIEVE_LOGIN_AGENT}} \
             ci-host -p 2222 uptime",
            forwarded.display()
        )
    );
    // The temporary socket and its directory are gone after the session.
    assert!(!forwarded.exists());
    assert!(!forwarded.parent().unwrap().exists());
}

#[test]
fn connect_without_login_agent_adds_no_identity_agent() {
    if !have("ssh-add") {
        eprintln!("skipping: ssh-add not installed");
        return;
    }
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let ssh = fake_ssh(dir.path(), None, "");
    let o = out(bin()
        .args(["connect", "ci-host", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
        .arg(&ssh));
    assert_eq!(o.status.code(), Some(7), "{}", stderr(&o));
    let args = fs::read_to_string(dir.path().join("args")).unwrap();
    assert!(!args.contains("IdentityAgent"), "{args}");
    // Not set when unused, so ProxyCommand children never see it.
    let login = fs::read_to_string(dir.path().join("login_agent")).unwrap();
    assert_eq!(login.trim(), "");
}

#[test]
fn connect_refuses_unsafe_effective_ssh_configuration() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let upstream = up.path.display().to_string();
    let cases: Vec<(Option<&str>, String, &str)> =
        vec![
        // ssh too old / overridden: forwards something else.
        (Some("yes"), String::new(), "instead of the filtered socket"),
        (
            Some("/some/other/agent.sock"),
            String::new(),
            "instead of the filtered socket",
        ),
        // Connection sharing still active: a master would forward its own agent.
        (
            None,
            "controlpath /home/u/.ssh/cm-%r@%h:%p\n".into(),
            "ControlPath",
        ),
        // A forwarding that survived ClearAllForwardings (any spelling).
        (None, format!("remoteforward /home/u/a.sock {upstream}\n"), "remoteforward"),
        (None, "remoteforward /r/x b//a.sock\n".into(), "remoteforward"),
        (None, "localforward 8080 [localhost]:80\n".into(), "localforward"),
        // Nested ssh session in ProxyCommand (could forward its own agent).
        (None, "proxycommand ssh -A bastion nc %h %p\n".into(), "ProxyCommand"),
        (None, "proxycommand /usr/bin/ssh bastion nc %h %p\n".into(), "ProxyCommand"),
        // Wrapped / indirect nested ssh (round-3 review): must fail closed.
        (None, "proxycommand /usr/bin/env ssh -A bastion nc %h %p\n".into(), "ProxyCommand"),
        (None, "proxycommand sh -c 'ssh -A bastion nc %h %p'\n".into(), "ProxyCommand"),
        (None, "proxycommand ssh -A bastion nc %h %p # -W\n".into(), "ProxyCommand"),
        (None, "proxycommand cloudflared access ssh --hostname %h\n".into(), "ProxyCommand"),
        // LocalCommand would receive the unfiltered login agent.
        (None, "permitlocalcommand yes\n".into(), "PermitLocalCommand"),
        // `~` spelling of the upstream path in some other option.
        (None, format!("localcommand cat {}\n", tilde(&up.path)), "localcommand"),
        // ProxyCommand mentioning the login agent.
        (
            None,
            "proxycommand env SSH_AUTH_SOCK=/original/login/agent.sock ssh -A bastion -W %h:%p\n"
                .into(),
            "ProxyCommand",
        ),
    ];
    for (fwd, extra, expect) in cases {
        let dir = private_tempdir();
        let ssh = fake_ssh(dir.path(), fwd, &extra);
        let o = out(bin()
            .env("SSH_AUTH_SOCK", "/original/login/agent.sock")
            .args(["connect", "ci-host", "--upstream"])
            .arg(&up.path)
            .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
            .arg(&ssh));
        assert_eq!(o.status.code(), Some(1), "{extra}");
        let err = stderr(&o);
        assert!(
            err.contains("refusing to connect") && err.contains(expect),
            "{err}"
        );
        assert!(!dir.path().join("args").exists(), "ssh session was started");
    }
}

#[test]
fn connect_allows_relay_only_proxy_commands() {
    if !have("ssh-add") {
        eprintln!("skipping: ssh-add not installed");
        return;
    }
    let up = MockAgent::start(three_identities(), Mode::Normal);
    // The relay must name the ssh connect runs (here the fake one).
    for pc in ["{ssh} -W %h:%p bastion", "{ssh} -W [%h]:%p -l me bastion"] {
        let dir = private_tempdir();
        let pc = pc.replace("{ssh}", &dir.path().join("ssh").display().to_string());
        let ssh = fake_ssh(dir.path(), None, &format!("proxycommand {pc}\n"));
        let o = out(bin()
            .args(["connect", "ci-host", "--upstream"])
            .arg(&up.path)
            .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
            .arg(&ssh));
        assert_eq!(o.status.code(), Some(7), "{pc}: {}", stderr(&o));
    }
}

#[test]
fn connect_never_starts_ssh_without_a_working_filter() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let ssh = fake_ssh(dir.path(), None, "");
    let run = |args: &[&str], upstream: &Path| {
        out(bin()
            .args(["connect"])
            .args(args)
            .arg("--upstream")
            .arg(upstream)
            .arg("--ssh")
            .arg(&ssh))
    };
    // Upstream down.
    let o = run(
        &["ci-host", "--allow-fingerprint", ECDSA_CI_FP],
        Path::new("/nonexistent/a.sock"),
    );
    assert_eq!(o.status.code(), Some(1));
    // Empty allowlist.
    let o = run(&["ci-host"], &up.path);
    assert_eq!(o.status.code(), Some(2));
    // Approved key absent upstream.
    let o = run(&["ci-host", "--allow-fingerprint", RSA_LEGACY_FP], &up.path);
    assert_eq!(o.status.code(), Some(1));
    // Option injection through the destination.
    let o = run(
        &[
            "--allow-fingerprint",
            ECDSA_CI_FP,
            "--",
            "-oProxyCommand=evil",
        ],
        &up.path,
    );
    assert_ne!(o.status.code(), Some(0));
    assert!(!dir.path().join("args").exists(), "ssh session was started");
}

#[test]
fn run_prints_shell_quoted_socket_path() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let sock = dir.path().join("it's.sock");
    let child = spawn_run(&up.path, &sock, &[ECDSA_CI_FP]);
    signal(&child, libc::SIGTERM);
    let o = child.finish();
    let line = stdout(&o);
    let canonical = fs::canonicalize(dir.path()).unwrap().join("it's.sock");
    let quoted = canonical.display().to_string().replace('\'', "'\\''");
    assert!(
        line.contains(&format!("SSH_AUTH_SOCK='{quoted}';")),
        "{line}"
    );
}

#[test]
fn doctor_escapes_control_characters_in_comments() {
    let ids = vec![(blob(ECDSA_CI), "evil\u{1b}]0;pwned\u{7}".to_string())];
    let up = MockAgent::start(ids, Mode::Normal);
    let o = out(bin()
        .args(["doctor", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP]));
    let text = stdout(&o);
    assert!(o.status.success(), "{text}");
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{7}'),
        "{text:?}"
    );
    assert!(text.contains("evil\\u{1b}]0;pwned\\u{7}"), "{text}");
}

/// A fake ssh that crashes (SIGKILL) or hangs until terminated.
fn crashing_ssh(dir: &Path, behaviour: &str) -> PathBuf {
    let script = dir.join("ssh");
    let body = format!(
        r#"#!/bin/sh
fa=""
for a in "$@"; do case "$a" in ForwardAgent=*) fa="${{a#ForwardAgent=}}";; ClearAllForwardings=yes) caf=1;; esac; done
if [ "$1" = "-G" ]; then echo "forwardagent $fa"; echo "controlmaster false"; echo "forwardx11 no"; [ -n "$caf" ] && echo "clearallforwardings yes"; exit 0; fi
echo "$fa" > "{out}/forwarded"
echo $$ > "{out}/ssh.pid"
{behaviour}
"#,
        out = dir.display()
    );
    fs::write(&script, body).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    script
}

#[test]
fn ssh_crash_still_cleans_up_and_reports_failure() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let ssh = crashing_ssh(dir.path(), "kill -9 $$");
    let o = out(bin()
        .args(["connect", "ci-host", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
        .arg(&ssh));
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let forwarded = PathBuf::from(
        fs::read_to_string(dir.path().join("forwarded"))
            .unwrap()
            .trim(),
    );
    assert!(!forwarded.exists() && !forwarded.parent().unwrap().exists());
}

#[test]
fn terminating_connect_stops_ssh_and_cleans_up() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let ssh = crashing_ssh(
        dir.path(),
        "trap 'exit 143' TERM; while :; do sleep 0.1; done",
    );
    let child = bin()
        .args(["connect", "ci-host", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
        .arg(&ssh)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let guard = RunGuard(Some(child));
    wait_for(&dir.path().join("ssh.pid"));
    let ssh_pid: i32 = fs::read_to_string(dir.path().join("ssh.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    signal(&guard, libc::SIGTERM);
    let o = guard.finish();
    assert_eq!(o.status.code(), Some(143), "{}", stderr(&o));
    // ssh was stopped and the filtered socket removed.
    // SAFETY: signal 0 only checks for existence.
    assert_ne!(unsafe { libc::kill(ssh_pid, 0) }, 0, "ssh still running");
    let forwarded = PathBuf::from(
        fs::read_to_string(dir.path().join("forwarded"))
            .unwrap()
            .trim(),
    );
    assert!(!forwarded.exists() && !forwarded.parent().unwrap().exists());
}

#[test]
fn connect_dry_run_checks_everything_but_never_starts_ssh() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let dir = private_tempdir();
    let relay = format!("{} -W %h:%p bastion", dir.path().join("ssh").display());
    let ssh = fake_ssh(dir.path(), None, &format!("proxycommand {relay}\n"));
    let o = out(bin()
        .env("SSH_AUTH_SOCK", "/original/login/agent.sock")
        .args(["connect", "ci-host", "--dry-run", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
        .arg(&ssh));
    let text = stdout(&o);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert!(!dir.path().join("args").exists(), "dry run started ssh");
    assert!(
        text.contains("Forwarded agent:     filtered socket only"),
        "{text}"
    );
    assert!(
        text.contains("Login agent:         your SSH_AUTH_SOCK agent"),
        "{text}"
    );
    assert!(text.contains(&format!("ProxyCommand {relay}")), "{text}");
    assert!(text.contains("Destination binding: not enforced"), "{text}");
    assert!(text.contains("Would run: ssh -o ForwardAgent="), "{text}");
    for hidden in [ED_ADMIN_FP, ED_PERSONAL_FP] {
        assert!(!text.contains(hidden));
    }
    // A configuration connect would refuse also fails the dry run.
    let bad = private_tempdir();
    let ssh = fake_ssh(bad.path(), None, "proxycommand sh -c 'ssh -A b nc %h %p'\n");
    let o = out(bin()
        .args(["connect", "ci-host", "--dry-run", "--upstream"])
        .arg(&up.path)
        .args(["--allow-fingerprint", ECDSA_CI_FP, "--ssh"])
        .arg(&ssh));
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("refusing to connect"));
}

#[test]
fn doctor_verifies_destination_binding_without_reaching_the_agent() {
    // Regression (fresh-context review LOW-1): in destination-binding mode the
    // self-test must prove an allowed key is refused without a binding.
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let o = out(bin().args(["doctor", "--upstream"]).arg(&up.path).args([
        "--allow-fingerprint",
        ECDSA_CI_FP,
        "--allow-destination",
        ED_ADMIN_FP,
    ]));
    let text = stdout(&o);
    assert!(o.status.success(), "{text}");
    assert!(
        text.contains("destination binding verified: unbound sign refused"),
        "{text}"
    );
    assert!(text.contains("Destination binding: enforced"), "{text}");
    // Refused inside SigSieve: the upstream agent saw no sign request at all.
    assert!(up.sign_requests().is_empty());
}
