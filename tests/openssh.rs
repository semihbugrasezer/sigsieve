//! Compatibility tests against the real OpenSSH tools (`ssh-agent`,
//! `ssh-add`, `ssh-keygen`, `ssh`). The full sshd forwarding path is in
//! `tests/e2e_sshd.rs`. Keys are generated
//! fresh in a temp directory; `SSH_AUTH_SOCK` is always set explicitly so the
//! developer's own agent is never touched. Skipped if the tools are missing.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::{private_tempdir, start_proxy};

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().unwrap()
}

fn ok(cmd: &mut Command) -> String {
    let o = run(cmd);
    assert!(o.status.success(), "{cmd:?} failed: {o:?}");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn fingerprint(pubkey: &Path) -> String {
    let out = ok(Command::new("ssh-keygen").arg("-lf").arg(pubkey));
    out.split_whitespace().nth(1).unwrap().to_string()
}

struct Agent {
    child: Child,
    sock: PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout waiting for {path:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    agent: Agent,
    /// name -> public key path (in a directory without private keys)
    pubs: Vec<(String, PathBuf)>,
}

fn fixture() -> Option<Fixture> {
    if !["ssh-agent", "ssh-add", "ssh-keygen"]
        .iter()
        .all(|c| have(c))
    {
        eprintln!("skipping: OpenSSH tools not installed");
        return None;
    }
    let dir = private_tempdir();
    let keys = dir.path().join("k");
    let pubdir = dir.path().join("p");
    fs::create_dir(&keys).unwrap();
    fs::create_dir(&pubdir).unwrap();
    let sock = dir.path().join("a.sock");
    let child = Command::new("ssh-agent")
        .args(["-D", "-a"])
        .arg(&sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let agent = Agent { child, sock };
    wait_for(&agent.sock);
    let mut pubs = Vec::new();
    for (name, args) in [
        ("ci", &["-t", "ecdsa", "-b", "256"][..]),
        ("admin", &["-t", "ed25519"][..]),
        ("legacy", &["-t", "rsa", "-b", "2048"][..]),
    ] {
        let k = keys.join(name);
        ok(Command::new("ssh-keygen")
            .args(["-q", "-N", "", "-C", &format!("{name}@test")])
            .args(args)
            .arg("-f")
            .arg(&k));
        ok(Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", &agent.sock)
            .arg(&k));
        let p = pubdir.join(format!("{name}.pub"));
        fs::copy(k.with_extension("pub"), &p).unwrap();
        pubs.push((name.to_string(), p));
    }
    Some(Fixture { dir, agent, pubs })
}

impl Fixture {
    fn pubkey(&self, name: &str) -> &Path {
        &self.pubs.iter().find(|(n, _)| n == name).unwrap().1
    }
}

#[test]
fn real_ssh_agent_listing_signing_and_mutations() {
    let Some(fx) = fixture() else { return };
    let ci_fp = fingerprint(fx.pubkey("ci"));
    let legacy_fp = fingerprint(fx.pubkey("legacy"));
    let admin_fp = fingerprint(fx.pubkey("admin"));
    let p = start_proxy(&fx.agent.sock, &[&ci_fp, &legacy_fp]);
    let via_proxy = |c: &mut Command| -> Output { run(c.env("SSH_AUTH_SOCK", &p.path)) };

    // Listing: exactly the two approved keys.
    let o = via_proxy(Command::new("ssh-add").arg("-l"));
    let listing = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{o:?}");
    assert_eq!(listing.lines().count(), 2, "{listing}");
    assert!(listing.contains(&ci_fp) && listing.contains(&legacy_fp));
    assert!(!listing.contains(&admin_fp));

    // Signing with approved ECDSA and RSA (rsa-sha2-512 flag) keys works and
    // verifies; signing with the hidden key fails.
    let msg = fx.dir.path().join("msg");
    fs::write(&msg, b"sigsieve compatibility test").unwrap();
    for name in ["ci", "legacy"] {
        let sig = msg.with_extension("sig");
        let _ = fs::remove_file(&sig);
        let o = via_proxy(
            Command::new("ssh-keygen")
                .args(["-Y", "sign", "-n", "test", "-f"])
                .arg(fx.pubkey(name))
                .arg(&msg),
        );
        assert!(o.status.success(), "{name}: {o:?}");
        let check = Command::new("ssh-keygen")
            .args(["-Y", "check-novalidate", "-n", "test", "-f"])
            .arg(fx.pubkey(name))
            .arg("-s")
            .arg(&sig)
            .stdin(fs::File::open(&msg).unwrap())
            .output()
            .unwrap();
        assert!(check.status.success(), "{name}: {check:?}");
    }
    let sig = msg.with_extension("sig");
    let _ = fs::remove_file(&sig);
    let o = via_proxy(
        Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "test", "-f"])
            .arg(fx.pubkey("admin"))
            .arg(&msg),
    );
    assert!(!o.status.success(), "hidden key signed through proxy");
    assert!(!sig.exists());

    // Mutations through the proxy fail and leave the upstream intact.
    assert!(!via_proxy(Command::new("ssh-add").arg("-D"))
        .status
        .success());
    assert!(
        !via_proxy(Command::new("ssh-add").arg("-d").arg(fx.pubkey("ci")))
            .status
            .success()
    );
    let extra = fx.dir.path().join("extra");
    ok(Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-t", "ed25519", "-f"])
        .arg(&extra));
    assert!(!via_proxy(Command::new("ssh-add").arg(&extra))
        .status
        .success());
    let upstream = ok(Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &fx.agent.sock));
    assert_eq!(upstream.lines().count(), 3, "{upstream}");
}

/// Real OpenSSH tools still sign with RSA/SHA-1 (`ssh-rsa`) when asked:
/// `ssh-keygen -s -U -t` makes the agent sign a certificate with exactly the
/// named algorithm. The upstream agent accepts all three; through SigSieve
/// only the SHA-2 algorithms work.
#[test]
fn rsa_sha1_signing_is_refused_while_sha2_works() {
    let Some(fx) = fixture() else { return };
    let legacy_fp = fingerprint(fx.pubkey("legacy"));
    let p = start_proxy(&fx.agent.sock, &[&legacy_fp]);
    let user = fx.dir.path().join("user");
    ok(Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-t", "ed25519", "-f"])
        .arg(&user));
    let cert = fx.dir.path().join("user-cert.pub");
    let certify = |sock: &Path, alg: &str| -> bool {
        let _ = fs::remove_file(&cert);
        let o = run(Command::new("ssh-keygen")
            .env("SSH_AUTH_SOCK", sock)
            .args(["-q", "-U", "-s"])
            .arg(fx.pubkey("legacy"))
            .args(["-t", alg, "-I", "sigsieve-test", "-n", "test"])
            .arg(user.with_extension("pub")));
        if !o.status.success() {
            return false;
        }
        let shown = ok(Command::new("ssh-keygen").arg("-Lf").arg(&cert));
        assert!(shown.contains(&format!("(using {alg})")), "{shown}");
        true
    };
    for alg in ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"] {
        assert!(certify(&fx.agent.sock, alg), "upstream control: {alg}");
    }
    assert!(certify(&p.path, "rsa-sha2-256"));
    assert!(certify(&p.path, "rsa-sha2-512"));
    assert!(
        !certify(&p.path, "ssh-rsa"),
        "SHA-1 signed through SigSieve"
    );
    assert!(!cert.exists());
}

/// Regression (from security review): keys added with `ssh-add -h` are
/// destination-constrained. Requests through SigSieve carry no session
/// binding, and OpenSSH's agent refuses constrained keys on unbound
/// connections, so the constraint is never bypassed (fails closed).
#[test]
fn destination_constrained_keys_fail_closed_through_proxy() {
    let Some(fx) = fixture() else { return };
    let d = fx.dir.path();
    let k = d.join("k").join("constrained");
    ok(Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-t", "ed25519", "-f"])
        .arg(&k));
    let hostkey = d.join("constraint-hostkey");
    ok(Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-t", "ed25519", "-f"])
        .arg(&hostkey));
    let known = d.join("constraint-known-hosts");
    fs::write(
        &known,
        format!(
            "only-this-host.example {}",
            fs::read_to_string(hostkey.with_extension("pub")).unwrap()
        ),
    )
    .unwrap();
    ok(Command::new("ssh-add")
        .env("SSH_AUTH_SOCK", &fx.agent.sock)
        .arg("-H")
        .arg(&known)
        .args(["-h", "only-this-host.example"])
        .arg(&k));
    let pubkey = d.join("p").join("constrained.pub");
    fs::copy(k.with_extension("pub"), &pubkey).unwrap();
    let fp = fingerprint(&pubkey);
    let ci_fp = fingerprint(fx.pubkey("ci"));
    let p = start_proxy(&fx.agent.sock, &[&fp, &ci_fp]);
    let msg = d.join("msg2");
    fs::write(&msg, b"x").unwrap();
    let sign = |pk: &Path| {
        Command::new("ssh-keygen")
            .env("SSH_AUTH_SOCK", &p.path)
            .args(["-Y", "sign", "-n", "test", "-f"])
            .arg(pk)
            .arg(&msg)
            .output()
            .unwrap()
    };
    assert!(
        !sign(&pubkey).status.success(),
        "constrained key signed via proxy"
    );
    let _ = fs::remove_file(msg.with_extension("sig"));
    // Positive control: an unconstrained allowlisted key signs.
    assert!(sign(fx.pubkey("ci")).status.success());
}

/// `connect` with the real ssh client and hostile ssh_config files. The
/// destination is 127.0.0.1 port 1, so no network connection is made.
#[test]
fn connect_with_real_ssh_config_overrides() {
    if !have("ssh") {
        eprintln!("skipping: ssh not installed");
        return;
    }
    let up = common::MockAgent::start(common::three_identities(), common::Mode::Normal);
    let dir = private_tempdir();
    let d = dir.path();
    let connect = |cfg: &Path| {
        Command::new(env!("CARGO_BIN_EXE_sigsieve"))
            .env("SSH_AUTH_SOCK", &up.path)
            .args(["connect", "127.0.0.1", "--upstream"])
            .arg(&up.path)
            .args(["--allow-fingerprint", common::ECDSA_CI_FP, "--"])
            .arg("-F")
            .arg(cfg)
            .args([
                "-p",
                "1",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=2",
                "true",
            ])
            .output()
            .unwrap()
    };

    // Connection sharing + ForwardAgent yes in config: SigSieve disables
    // sharing, ssh runs (and fails to connect), no control socket appears.
    let cfg = d.join("cfg-mux");
    fs::write(
        &cfg,
        format!(
            "Host *\n  ControlMaster auto\n  ControlPath {}/cm-%C\n  ControlPersist yes\n  ForwardAgent yes\n",
            d.display()
        ),
    )
    .unwrap();
    let o = connect(&cfg);
    assert_eq!(o.status.code(), Some(255), "{o:?}");
    assert!(
        !fs::read_dir(d).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("cm-")),
        "control socket created"
    );

    // RemoteForward of the upstream agent (odd spelling): cleared by
    // ClearAllForwardings, so ssh runs without it (and fails to connect).
    let cfg = d.join("cfg-rfwd");
    fs::write(
        &cfg,
        format!(
            "Host *\n  RemoteForward /tmp/remote-agent.sock {}\n",
            up.path.display().to_string().replacen('/', "//", 1)
        ),
    )
    .unwrap();
    let o = connect(&cfg);
    assert_eq!(o.status.code(), Some(255), "{o:?}");
    assert!(!String::from_utf8_lossy(&o.stderr).contains("refusing"));

    // `IdentityAgent ${SSH_AUTH_SOCK}` in config keeps working (login agent
    // passed explicitly; SSH_AUTH_SOCK points at the filtered socket).
    let cfg = d.join("cfg-ia");
    fs::write(&cfg, "Host *\n  IdentityAgent ${SSH_AUTH_SOCK}\n").unwrap();
    let o = connect(&cfg);
    assert_eq!(o.status.code(), Some(255), "{o:?}");

    // A ProxyCommand running a nested ssh session is refused, including
    // indirect forms, and so is PermitLocalCommand.
    for (i, line) in [
        "ProxyCommand ssh -A bastion.invalid nc %h %p",
        "ProxyCommand /usr/bin/env ssh -A bastion.invalid nc %h %p",
        "ProxyCommand sh -c 'ssh -A bastion.invalid nc %h %p'",
        "PermitLocalCommand yes\n  LocalCommand true",
    ]
    .iter()
    .enumerate()
    {
        let cfg = d.join(format!("cfg-pc{i}"));
        fs::write(&cfg, format!("Host *\n  {line}\n")).unwrap();
        let o = connect(&cfg);
        assert_eq!(o.status.code(), Some(1), "{line}: {o:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("refusing to connect"));
    }

    // Port forwardings from config are dropped visibly, not silently.
    let cfg = d.join("cfg-lf");
    fs::write(&cfg, "Host *\n  LocalForward 18080 localhost:80\n").unwrap();
    let o = connect(&cfg);
    assert_eq!(o.status.code(), Some(255), "{o:?}");
    assert!(String::from_utf8_lossy(&o.stderr).contains("port forwardings are disabled"));
}

/// Regression (C-1): every proxy hop runs its own ssh, which reads ssh_config
/// for that host and inherits the session environment but not connect's `-o`
/// options. A wrapper or local command anywhere in the chain must be refused
/// (and never run), however the chain is spelled; plain relays still work.
/// Real `ssh -G` with temporary `-F` configs; every host is 127.0.0.1 port 1.
#[test]
fn connect_verifies_every_proxy_hop() {
    if !have("ssh") {
        eprintln!("skipping: ssh not installed");
        return;
    }
    let up = common::MockAgent::start(common::three_identities(), common::Mode::Normal);
    let dir = private_tempdir();
    let d = dir.path();
    let ran = d.join("wrapper-ran");
    let wrapper = d.join("wrapper.sh");
    fs::write(
        &wrapper,
        format!("#!/bin/sh\ntouch {}\nexit 1\n", ran.display()),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let w = format!("{} %h %p", wrapper.display());
    // ssh refuses group-writable config files (umask 002).
    let write_cfg = |path: &Path, text: &str| {
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    };
    let connect = |name: &str, hosts: &str, dry_run: bool| {
        let cfg = d.join(name);
        write_cfg(
            &cfg,
            &format!("{hosts}Host *\n  HostName 127.0.0.1\n  Port 1\n  BatchMode yes\n"),
        );
        let mut c = Command::new(env!("CARGO_BIN_EXE_sigsieve"));
        c.env("SSH_AUTH_SOCK", &up.path)
            .args(["connect", "target", "--upstream"])
            .arg(&up.path)
            .args(["--allow-fingerprint", common::ECDSA_CI_FP]);
        if dry_run {
            c.arg("--dry-run");
        }
        c.arg("--").arg("-F").arg(&cfg);
        if !dry_run {
            c.args(["-o", "ConnectTimeout=2", "true"]);
        }
        c.output().unwrap()
    };
    let refused = |name: &str, hosts: String, why: &str| {
        for dry_run in [true, false] {
            let o = connect(name, &hosts, dry_run);
            let err = String::from_utf8_lossy(&o.stderr);
            assert_eq!(
                o.status.code(),
                Some(1),
                "{name} (dry run {dry_run}): {err}"
            );
            assert!(err.contains("refusing to connect"), "{name}: {err}");
            assert!(err.contains(why), "{name}: expected {why:?} in {err}");
            assert!(!ran.exists(), "{name}: the wrapper ran");
        }
    };

    // The audit's reproduction: a wrapper on the ProxyJump hop.
    refused(
        "jump",
        format!("Host target\n  ProxyJump bastion\nHost bastion\n  ProxyCommand {w}\n"),
        "on proxy hop",
    );
    // The same wrapper directly on the destination.
    refused(
        "direct",
        format!("Host target\n  ProxyCommand {w}\n"),
        "cannot be verified",
    );
    // Multi-hop lists: the wrapper on the first, or on the last, hop.
    refused(
        "multi-first",
        format!("Host target\n  ProxyJump a,b\nHost a\n  ProxyCommand {w}\n"),
        "on proxy hop",
    );
    // On the last hop of a list, ssh starts `ssh -J a … b`, and the `-J`
    // overrides b's own ProxyCommand: verification passes and, as with plain
    // ssh, the wrapper never runs.
    let o = connect(
        "multi-last",
        &format!("Host target\n  ProxyJump a,b\nHost b\n  ProxyCommand {w}\n"),
        true,
    );
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let o = connect(
        "multi-last",
        &format!("Host target\n  ProxyJump a,b\nHost b\n  ProxyCommand {w}\n"),
        false,
    );
    assert_ne!(o.status.code(), Some(0));
    assert!(!ran.exists(), "the overridden wrapper ran");
    // A hop whose own configuration adds a further hop.
    refused(
        "nested",
        format!("Host target\n  ProxyJump a\nHost a\n  ProxyJump c\nHost c\n  ProxyCommand {w}\n"),
        "on proxy hop",
    );
    // A relay ProxyCommand whose host has a wrapper.
    let cfg = d.join("relay");
    refused(
        "relay",
        format!(
            "Host target\n  ProxyCommand ssh -F {} -W %h:%p bastion\nHost bastion\n  ProxyCommand {w}\n",
            cfg.display()
        ),
        "on proxy hop",
    );
    // Include and Match host.
    write_cfg(
        &d.join("inc"),
        &format!("Match host bastion\n  ProxyCommand {w}\n"),
    );
    refused(
        "include",
        format!(
            "Include {}\nHost target\n  ProxyJump bastion\n",
            d.join("inc").display()
        ),
        "on proxy hop",
    );
    // Local commands on a hop.
    refused(
        "hop-localcommand",
        format!(
            "Host target\n  ProxyJump bastion\nHost bastion\n  PermitLocalCommand yes\n  LocalCommand {w}\n"
        ),
        "PermitLocalCommand is enabled on proxy hop",
    );
    refused(
        "hop-knownhostscommand",
        format!("Host target\n  ProxyJump bastion\nHost bastion\n  KnownHostsCommand {w}\n"),
        "KnownHostsCommand is set on proxy hop",
    );
    refused(
        "knownhostscommand",
        format!("Host target\n  KnownHostsCommand {w}\n"),
        "KnownHostsCommand is set",
    );
    refused(
        "canonicalize",
        "Host target\n  CanonicalizeHostname yes\n".into(),
        "CanonicalizeHostname",
    );
    refused(
        "hop-canonicalize",
        "Host target\n  ProxyJump bastion\nHost bastion\n  CanonicalizeHostname yes\n".into(),
        "CanonicalizeHostname",
    );
    for setting in ["no", "off", "false"] {
        refused(
            &format!("unsafe-hostkey-{setting}"),
            format!("Host target\n  StrictHostKeyChecking {setting}\n"),
            "StrictHostKeyChecking",
        );
    }
    refused(
        "unsafe-hop-hostkey",
        "Host target\n  ProxyJump bastion\nHost bastion\n  StrictHostKeyChecking no\n".into(),
        "StrictHostKeyChecking",
    );
    refused(
        "match-final",
        "Match final all\n  User test\n".into(),
        "state-dependent Match",
    );
    // Match exec runs a program while ssh evaluates its configuration.
    refused(
        "match-exec",
        format!("Match exec \"{}\"\n  ForwardX11 no\n", wrapper.display()),
        "Match exec",
    );
    // ... also when included, or in a relay hop's own -F file: the command
    // must not run during verification (the marker check in `refused`).
    write_cfg(
        &d.join("inc-exec"),
        &format!("Match exec \"{}\"\n", wrapper.display()),
    );
    refused(
        "match-exec-include",
        format!("Include {}\n", d.join("inc-exec").display()),
        "Match exec",
    );
    refused(
        "quoted-match-keyword",
        format!("\"Match\"exec \"{}\"\n", wrapper.display()),
        "quoted or escaped keyword",
    );
    refused(
        "quoted-include-keyword",
        format!("\"Include\"{}\n", d.join("inc-exec").display()),
        "quoted or escaped keyword",
    );
    for (name, directive) in [
        ("cr-include-keyword", "Include\r"),
        ("cr-include-argument", "Include \r"),
        ("cr-include-equals", "Include = \r"),
    ] {
        refused(
            name,
            format!("{directive}{}\n", d.join("inc-exec").display()),
            "unsupported control character",
        );
    }
    write_cfg(
        &d.join("inc=payload"),
        &format!("Match exec \"{}\"\n", wrapper.display()),
    );
    refused(
        "include-equals-in-path",
        format!("Include {}\n", d.join("inc=payload").display()),
        "Match exec",
    );
    refused(
        "match-exec-relay",
        format!(
            "Host target\n  ProxyCommand ssh -F {} -W %h:%p bastion\n",
            d.join("inc-exec").display()
        ),
        "Match exec",
    );
    // A loop of hops, and a relay where -W is only an option argument.
    refused(
        "loop",
        "Host target\n  ProxyJump a\nHost a\n  ProxyJump b\nHost b\n  ProxyJump a\n".into(),
        "loop",
    );
    // A relay whose `ssh` is another program than the ssh connect runs.
    let other_ssh = d.join("ssh");
    fs::copy(&wrapper, &other_ssh).unwrap();
    refused(
        "other-ssh",
        format!(
            "Host target\n  ProxyCommand {} -W %h:%p bastion\n",
            other_ssh.display()
        ),
        "not the ssh connect runs",
    );
    refused(
        "fake-relay",
        "Host target\n  ProxyCommand ssh -l -W bastion nc %h %p\n".into(),
        "not a plain relay",
    );

    // Review G1: a relay's own -F file governs its nested hops, not connect's.
    write_cfg(
        &d.join("other"),
        &format!(
            "Host bastion\n  ProxyJump bastion2\nHost bastion2\n  ProxyCommand {w}\n\
             Host *\n  HostName 127.0.0.1\n  Port 1\n"
        ),
    );
    refused(
        "relay-own-config",
        format!(
            "Host target\n  ProxyCommand ssh -F {} -W %h:%p bastion\n",
            d.join("other").display()
        ),
        "on proxy hop",
    );
    // Review G3: a hop that keeps forwardings (RemoteForward of the agent).
    refused(
        "hop-forward",
        format!(
            "Host target\n  ProxyJump bastion\nHost bastion\n  ClearAllForwardings no\n  \
             RemoteForward /tmp/remote-agent.sock {}\n",
            up.path.display()
        ),
        "keeps port forwardings",
    );
    // Review G5: quoting cannot hide Match exec, directly or in a relay's -F.
    refused(
        "match-exec-quoted",
        format!("Match e'x'ec \"{}\"\n", wrapper.display()),
        "Match exec",
    );
    write_cfg(
        &d.join("quoted-exec"),
        &format!("Match \"ex\"ec \"{}\"\n", wrapper.display()),
    );
    refused(
        "match-exec-quoted-relay",
        format!(
            "Host target\n  ProxyCommand ssh -F {} -W %h:%p bastion\n",
            d.join("quoted-exec").display()
        ),
        "Match exec",
    );
    // Review G4: X11 forwarding (ssh runs xauth with the login agent).
    write_cfg(&d.join("x11"), "Host *\n  HostName 127.0.0.1\n  Port 1\n");
    let o = Command::new(env!("CARGO_BIN_EXE_sigsieve"))
        .env("SSH_AUTH_SOCK", &up.path)
        .args(["connect", "target", "--upstream"])
        .arg(&up.path)
        .args([
            "--allow-fingerprint",
            common::ECDSA_CI_FP,
            "--dry-run",
            "--",
            "-F",
        ])
        .arg(d.join("x11"))
        .arg("-X")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("X11 forwarding"));
    // Review G2: ssh pastes -F unquoted into its ProxyJump shell command.
    let odd = d.join("e$x");
    fs::create_dir(&odd).unwrap();
    fs::set_permissions(&odd, fs::Permissions::from_mode(0o700)).unwrap();
    write_cfg(
        &odd.join("cfg"),
        "Host target\n  ProxyJump bastion\nHost *\n  HostName 127.0.0.1\n  Port 1\n",
    );
    let o = Command::new(env!("CARGO_BIN_EXE_sigsieve"))
        .env("SSH_AUTH_SOCK", &up.path)
        .args(["connect", "target", "--upstream"])
        .arg(&up.path)
        .args([
            "--allow-fingerprint",
            common::ECDSA_CI_FP,
            "--dry-run",
            "--",
            "-F",
        ])
        .arg(odd.join("cfg"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("use a simple path"));

    // Safe configurations still pass verification.
    let relay = d.join("ok-relay");
    for (name, hosts) in [
        ("ok-direct", String::new()),
        ("ok-jump", "Host target\n  ProxyJump bastion\n".to_string()),
        (
            "ok-jump-user-port",
            "Host target\n  ProxyJump me@bastion:2222\n".into(),
        ),
        ("ok-multi", "Host target\n  ProxyJump a,b\n".into()),
        (
            "ok-relay",
            format!(
                "Host target\n  ProxyCommand ssh -F {} -W %h:%p bastion\n",
                relay.display()
            ),
        ),
    ] {
        let o = connect(name, &hosts, true);
        let text = String::from_utf8_lossy(&o.stdout);
        assert_eq!(
            o.status.code(),
            Some(0),
            "{name}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(text.contains("all checks passed"), "{name}: {text}");
    }
}

/// A throwaway GnuPG agent with SSH support, confined to its own home
/// directory (never `~/.gnupg`). Dropping it stops every GnuPG daemon of
/// that home before the directory is removed.
struct GpgAgent {
    home: tempfile::TempDir,
}

impl Drop for GpgAgent {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", self.home.path())
            .arg("--homedir")
            .arg(self.home.path())
            .args(["--kill", "all"])
            .output();
    }
}

impl GpgAgent {
    fn cmd(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.env("GNUPGHOME", self.home.path())
            .arg("--homedir")
            .arg(self.home.path());
        c
    }
}

/// gpg-agent (`enable-ssh-support`) as the upstream agent: unprotected
/// synthetic Ed25519, ECDSA P-256 and RSA authentication keys. Skipped when
/// GnuPG is not installed, unless `SIGSIEVE_REQUIRE_GPG_AGENT=1`.
#[test]
fn gpg_agent_upstream_filtering_signing_and_mutations() {
    if !["gpg", "gpg-agent", "gpgconf", "ssh-add", "ssh-keygen"]
        .iter()
        .all(|c| have(c))
    {
        if std::env::var_os("SIGSIEVE_REQUIRE_GPG_AGENT").is_some_and(|v| v == "1") {
            panic!("GnuPG tools required for the gpg-agent test");
        }
        eprintln!("skipping gpg-agent test: GnuPG tools not installed");
        return;
    }
    let gpg = GpgAgent {
        home: private_tempdir(),
    };
    let h = gpg.home.path();
    fs::write(h.join("gpg-agent.conf"), "enable-ssh-support\n").unwrap();
    // The daemon keeps inherited pipes open, so do not capture its output.
    let started = gpg
        .cmd("gpg-agent")
        .arg("--daemon")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(started.success(), "gpg-agent did not start");
    let quiet = ["--batch", "--pinentry-mode", "loopback", "--passphrase", ""];
    ok(gpg.cmd("gpg").args(quiet).args([
        "--quick-gen-key",
        "sigsieve test",
        "ed25519",
        "auth",
        "never",
    ]));
    let colons = ok(gpg.cmd("gpg").args(["--list-keys", "--with-colons"]));
    let fpr = colons
        .lines()
        .find_map(|l| l.strip_prefix("fpr:::::::::"))
        .unwrap()
        .trim_end_matches(':')
        .to_string();
    for algo in ["nistp256", "rsa2048"] {
        ok(gpg
            .cmd("gpg")
            .args(quiet)
            .args(["--quick-add-key", &fpr, algo, "auth", "never"]));
    }
    let grips: String = ok(gpg
        .cmd("gpg")
        .args(["--list-keys", "--with-keygrip", "--with-colons"]))
    .lines()
    .filter_map(|l| l.strip_prefix("grp:::::::::"))
    .map(|g| format!("{}\n", g.trim_end_matches(':')))
    .collect();
    fs::write(h.join("sshcontrol"), grips).unwrap();
    let sock =
        PathBuf::from(ok(gpg.cmd("gpgconf").args(["--list-dirs", "agent-ssh-socket"])).trim());

    // Public keys as gpg-agent presents them over the SSH agent protocol.
    let listing = ok(Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", &sock));
    let pubdir = h.join("p");
    fs::create_dir(&pubdir).unwrap();
    let pubkey = |prefix: &str, name: &str| -> PathBuf {
        let line = listing
            .lines()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix} missing from gpg-agent:\n{listing}"));
        let p = pubdir.join(format!("{name}.pub"));
        fs::write(&p, format!("{line}\n")).unwrap();
        p
    };
    let (ed, ec, rsa) = (
        pubkey("ssh-ed25519 ", "ed"),
        pubkey("ecdsa-sha2-nistp256 ", "ec"),
        pubkey("ssh-rsa ", "rsa"),
    );
    let (ed_fp, ec_fp, rsa_fp) = (fingerprint(&ed), fingerprint(&ec), fingerprint(&rsa));
    let p = start_proxy(&sock, &[&ec_fp, &rsa_fp]);
    let via = |c: &mut Command| -> Output { run(c.env("SSH_AUTH_SOCK", &p.path)) };

    // Listing: only the two allowlisted keys.
    let o = via(Command::new("ssh-add").arg("-l"));
    let shown = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(o.status.success(), "{o:?}");
    assert_eq!(shown.lines().count(), 2, "{shown}");
    assert!(shown.contains(&ec_fp) && shown.contains(&rsa_fp) && !shown.contains(&ed_fp));

    // SSHSIG signing: allowlisted keys sign and verify, the hidden key fails.
    let msg = h.join("msg");
    fs::write(&msg, b"sigsieve gpg-agent test").unwrap();
    let sig = msg.with_extension("sig");
    for (key, allowed) in [(&ec, true), (&rsa, true), (&ed, false)] {
        let _ = fs::remove_file(&sig);
        let o = via(Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "test", "-f"])
            .arg(key)
            .arg(&msg));
        assert_eq!(o.status.success(), allowed, "{key:?}: {o:?}");
        if allowed {
            let check = Command::new("ssh-keygen")
                .args(["-Y", "check-novalidate", "-n", "test", "-f"])
                .arg(key)
                .arg("-s")
                .arg(&sig)
                .stdin(fs::File::open(&msg).unwrap())
                .output()
                .unwrap();
            assert!(check.status.success(), "{key:?}: {check:?}");
        } else {
            assert!(!sig.exists());
        }
    }

    // RSA hash selection: gpg-agent honours the SHA-2 flags; SHA-1 is
    // refused by SigSieve.
    let user = h.join("user");
    ok(Command::new("ssh-keygen")
        .args(["-q", "-N", "", "-t", "ed25519", "-f"])
        .arg(&user));
    let cert = h.join("user-cert.pub");
    for (alg, expect) in [
        ("rsa-sha2-256", true),
        ("rsa-sha2-512", true),
        ("ssh-rsa", false),
    ] {
        let _ = fs::remove_file(&cert);
        let o = via(Command::new("ssh-keygen")
            .args(["-q", "-U", "-s"])
            .arg(&rsa)
            .args(["-t", alg, "-I", "sigsieve-test", "-n", "test"])
            .arg(user.with_extension("pub")));
        assert_eq!(o.status.success(), expect, "{alg}: {o:?}");
        if expect {
            let shown = ok(Command::new("ssh-keygen").arg("-Lf").arg(&cert));
            assert!(shown.contains(&format!("(using {alg})")), "{shown}");
        } else {
            assert!(!cert.exists(), "{alg}");
        }
    }

    // Mutations fail; gpg-agent still holds all three keys.
    assert!(!via(Command::new("ssh-add").arg("-D")).status.success());
    assert!(!via(Command::new("ssh-add").arg("-d").arg(&ec))
        .status
        .success());
    let after = ok(Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", &sock));
    assert_eq!(after.lines().count(), 3, "{after}");
}
