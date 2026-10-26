//! Command-line interface: `run`, `doctor`, `status`, `connect`.
//!
//! Exit codes: 0 success, 1 runtime failure or failed check, 2 invalid usage
//! or configuration. `connect` returns the ssh client's exit code once ssh
//! has started.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};

use crate::ssh::{
    hop_config_file, ssh_config_file, ssh_effective_config, ssh_safe_path, verify_proxy_chain,
    verify_ssh_plan, LOGIN_AGENT_VAR,
};

use sigsieve::keys::{parse_public_key, Fingerprint};
use sigsieve::policy::Policy;
use sigsieve::protocol::{self, SSH_AGENTC_SIGN_REQUEST};
use sigsieve::proxy::{self, Limits, Proxy};
use sigsieve::socket::{self, RuntimeSocket};
use sigsieve::upstream::{Identity, Upstream};

const EXIT_OK: i32 = 0;
const EXIT_FAIL: i32 = 1;
const EXIT_CONFIG: i32 = 2;

const SECRETIVE_SOCKET: &str =
    "Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh";

#[derive(Parser)]
#[command(
    name = "sigsieve",
    version,
    about = "SSH agent filtering proxy. Your keys. Your rules.",
    long_about = "SigSieve sits between an SSH agent (e.g. Secretive) and its clients and \
                  exposes only explicitly allowlisted identities. Signature requests for any \
                  other key are rejected, and agent mutations and extensions are never \
                  forwarded.\n\nEXPERIMENTAL: not independently audited."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a filtered agent socket in the foreground.
    Run(RunArgs),
    /// Check upstream reachability, the allowlist and filtering behaviour.
    Doctor(DoctorArgs),
    /// Inspect a running filtered socket (default: $SSH_AUTH_SOCK).
    Status(StatusArgs),
    /// Start ssh with only a filtered agent forwarded, then clean up.
    Connect(ConnectArgs),
}

#[derive(Args)]
struct PolicyArgs {
    /// Upstream agent socket to filter.
    #[arg(
        long,
        env = "SIGSIEVE_UPSTREAM",
        value_name = "PATH",
        conflicts_with = "secretive"
    )]
    upstream: Option<PathBuf>,

    /// Use Secretive's default socket (~/Library/Containers/…/socket.ssh).
    #[arg(long)]
    secretive: bool,

    /// Allow the key with this SHA256 fingerprint (repeatable). Default: none.
    #[arg(
        long = "allow-fingerprint",
        env = "SIGSIEVE_ALLOW",
        value_name = "SHA256:…",
        value_delimiter = ','
    )]
    allow: Vec<String>,

    /// Seconds to wait for the upstream agent (covers Touch ID prompts).
    #[arg(long, default_value_t = 120, value_name = "SECS",
          value_parser = clap::value_parser!(u64).range(1..=3600))]
    upstream_timeout: u64,

    /// Enforce destination binding: allowed keys may then only sign SSH user
    /// authentication requests for sessions cryptographically bound to a
    /// server with one of these host key fingerprints (repeatable).
    #[arg(
        long = "allow-destination",
        env = "SIGSIEVE_DESTINATIONS",
        value_name = "SHA256:…",
        value_delimiter = ','
    )]
    destinations: Vec<String>,
}

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    policy: PolicyArgs,

    /// Socket path to create (its directory must be private to you).
    /// Default: a fresh 0700 directory under $TMPDIR.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct DoctorArgs {
    #[command(flatten)]
    policy: PolicyArgs,

    /// Also check this filtered socket path.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct StatusArgs {
    /// Filtered socket to inspect.
    #[arg(long, env = "SSH_AUTH_SOCK", value_name = "PATH")]
    socket: Option<PathBuf>,
}

#[derive(Args)]
struct ConnectArgs {
    /// SSH destination (host alias or user@host).
    host: String,

    #[command(flatten)]
    policy: PolicyArgs,

    /// ssh client binary.
    #[arg(long, default_value = "ssh", value_name = "PATH")]
    ssh: PathBuf,

    /// Run every check (upstream, filtered-agent self-test, effective ssh
    /// configuration) and print the plan, but do not start ssh.
    #[arg(long)]
    dry_run: bool,

    /// Extra arguments passed to ssh after the destination (after `--`).
    #[arg(last = true, value_name = "SSH_ARGS")]
    ssh_args: Vec<String>,
}

pub fn main() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Run(a) => run(a),
        Cmd::Doctor(a) => doctor(a),
        Cmd::Status(a) => status(a),
        Cmd::Connect(a) => connect(a),
    }
}

fn error(msg: impl std::fmt::Display) {
    eprintln!("sigsieve: error: {msg}");
}

fn warn(msg: impl std::fmt::Display) {
    eprintln!("sigsieve: warning: {msg}");
}

/// Resolve the upstream and allowlist. Errors are configuration errors.
fn load(args: &PolicyArgs) -> Result<(Policy, Upstream), String> {
    let path = if args.secretive {
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        PathBuf::from(home).join(SECRETIVE_SOCKET)
    } else {
        args.upstream.clone().ok_or(
            "no upstream agent: pass --upstream PATH, --secretive, or set SIGSIEVE_UPSTREAM",
        )?
    };
    if path.to_string_lossy().contains('\n') {
        return Err("upstream path must not contain a newline".into());
    }
    let (policy, dups) = Policy::from_fingerprints(&args.allow).map_err(|e| e.to_string())?;
    for d in dups {
        warn(format_args!("duplicate allowlist entry {d} ignored"));
    }
    let policy = policy
        .with_destinations(&args.destinations)
        .map_err(|e| format!("--allow-destination: {e}"))?;
    Ok((
        policy,
        Upstream::new(path, Duration::from_secs(args.upstream_timeout)),
    ))
}

fn shutdown_flag(signals: &[i32]) -> Result<Arc<AtomicBool>, String> {
    let flag = Arc::new(AtomicBool::new(false));
    for &sig in signals {
        signal_hook::flag::register(sig, Arc::clone(&flag))
            .map_err(|e| format!("cannot install signal handler: {e}"))?;
    }
    Ok(flag)
}

fn describe(id: &Identity) -> String {
    let kind = parse_public_key(&id.blob)
        .map(|k| k.name())
        .unwrap_or("UNKNOWN");
    // Comments come from the upstream agent: neutralise terminal escapes.
    let comment: String = String::from_utf8_lossy(&id.comment)
        .chars()
        .flat_map(|c| {
            let esc: Vec<char> = if c.is_control() {
                c.escape_default().collect()
            } else {
                vec![c]
            };
            esc
        })
        .collect();
    format!("{kind} {} {comment}", Fingerprint::of_blob(&id.blob))
}

/// Quote a value for POSIX `sh` (single quotes, embedded quotes escaped).
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn describe_binding(policy: &Policy) -> String {
    match policy.destinations() {
        Some(d) => format!(
            "enforced: allowed keys may only authenticate to {} destination host key(s)",
            d.len()
        ),
        None => "not enforced: identity filtering only (an allowed key can be used \
                 for any destination while forwarding is active)"
            .into(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A started proxy on its own socket, serving on a background thread.
struct Running {
    rt: RuntimeSocket,
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Running {
    fn start(proxy: Proxy, socket_path: Option<&Path>) -> Result<Running, String> {
        let (listener, rt) = RuntimeSocket::bind(socket_path).map_err(|e| e.to_string())?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let thread = thread::Builder::new()
            .name("sigsieve-accept".into())
            .spawn(move || {
                if let Err(e) = proxy::serve(&listener, Arc::new(proxy), &flag) {
                    error(format_args!("server stopped: {e}"));
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Running {
            rt,
            shutdown,
            thread: Some(thread),
        })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        // `rt` is dropped after this, removing the socket and directory.
    }
}

fn run(args: RunArgs) -> i32 {
    let (policy, upstream) = match load(&args.policy) {
        Ok(v) => v,
        Err(e) => {
            error(e);
            return EXIT_CONFIG;
        }
    };
    if args
        .socket
        .as_ref()
        .is_some_and(|p| p.to_string_lossy().contains('\n'))
    {
        error("socket path must not contain a newline");
        return EXIT_CONFIG;
    }
    if policy.is_empty() {
        warn("allowlist is empty: the filtered agent will expose no identities");
    }
    let signals = match shutdown_flag(&[
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]) {
        Ok(f) => f,
        Err(e) => {
            error(e);
            return EXIT_FAIL;
        }
    };
    if let Err(e) = upstream.identities_cancellable(&signals) {
        if signals.load(Ordering::SeqCst) {
            error("cancelled before starting the proxy");
            return EXIT_FAIL;
        }
        warn(format_args!(
            "{e} (requests will fail until it is available)"
        ));
    }
    let mut state = format!(
        "pid={}\nupstream={}\nstarted={}\n",
        std::process::id(),
        upstream.path().display(),
        unix_now()
    );
    for fp in policy.fingerprints() {
        state.push_str(&format!("allow={fp}\n"));
    }
    for fp in policy.destinations().into_iter().flatten() {
        state.push_str(&format!("destination={fp}\n"));
    }
    let n = policy.len();
    let proxy = Proxy::new(policy, upstream, Limits::default());
    let mut running = match Running::start(proxy, args.socket.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            error(e);
            return EXIT_FAIL;
        }
    };
    if let Some(pid) = running.rt.recovered_from() {
        warn(format_args!(
            "replaced the stale socket left by SigSieve process {pid}, which exited without cleanup"
        ));
    }
    if let Err(e) = running
        .rt
        .write_state(&format!("socket={}\n{state}", running.rt.path().display()))
    {
        warn(format_args!(
            "cannot write state file (status will be limited): {e}"
        ));
    }
    eprintln!(
        "sigsieve: filtered agent listening ({n} allowlisted fingerprint(s)); Ctrl-C to stop"
    );
    println!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
        shell_quote(&running.rt.path().to_string_lossy())
    );
    while !signals.load(Ordering::SeqCst) {
        if running.thread.as_ref().is_some_and(|t| t.is_finished()) {
            error("server thread exited");
            return EXIT_FAIL;
        }
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!("sigsieve: shutting down");
    drop(running);
    EXIT_OK
}

/// Ask the filtered socket for identities and try signing with a synthetic,
/// non-allowlisted key. Returns the exposed identities on success.
fn self_test(socket_path: &Path, policy: &Policy) -> Result<Vec<Identity>, String> {
    let client = Upstream::new(socket_path, Duration::from_secs(10));
    let ids = client
        .identities()
        .map_err(|e| format!("filtered socket did not answer: {e}"))?;
    for id in &ids {
        if !policy.allows(&id.blob) {
            return Err(format!(
                "filtered socket exposed a non-allowlisted identity {}",
                Fingerprint::of_blob(&id.blob)
            ));
        }
    }
    // A syntactically valid Ed25519 key that is never on the allowlist.
    let mut blob = Vec::new();
    protocol::put_string(&mut blob, b"ssh-ed25519");
    protocol::put_string(&mut blob, &[0x5a; 32]);
    if policy.allows(&blob) {
        return Err("synthetic probe key unexpectedly allowlisted".into());
    }
    let mut req = vec![SSH_AGENTC_SIGN_REQUEST];
    protocol::put_string(&mut req, &blob);
    protocol::put_string(&mut req, b"sigsieve self-test");
    protocol::put_u32(&mut req, 0);
    match client.request(&req) {
        Ok(r) if r == [protocol::SSH_AGENT_FAILURE] => {}
        Ok(_) => {
            return Err("filtered socket did not reject a non-allowlisted sign request".into())
        }
        Err(e) => return Err(format!("sign probe failed: {e}")),
    }
    // With destination binding, an allowlisted key must also be refused on a
    // connection without a verified binding. This is denied before the
    // upstream agent is contacted, so it never causes a Touch ID prompt.
    if policy.destinations().is_some() {
        if let Some(id) = ids.first() {
            let mut req = vec![SSH_AGENTC_SIGN_REQUEST];
            protocol::put_string(&mut req, &id.blob);
            protocol::put_string(&mut req, b"sigsieve self-test: unbound");
            protocol::put_u32(&mut req, 0);
            match client.request(&req) {
                Ok(r) if r == [protocol::SSH_AGENT_FAILURE] => {}
                Ok(_) => {
                    return Err(
                        "destination binding is not enforced: an unbound sign request was signed"
                            .into(),
                    )
                }
                Err(e) => return Err(format!("binding probe failed: {e}")),
            }
        }
    }
    Ok(ids)
}

fn doctor(args: DoctorArgs) -> i32 {
    println!("SigSieve Doctor\n");
    let (policy, upstream) = match load(&args.policy) {
        Ok(v) => v,
        Err(e) => {
            println!("Configuration:      INVALID ({e})");
            return EXIT_CONFIG;
        }
    };
    let mut ok = true;
    println!("Allowlist:          {} valid fingerprint(s)", policy.len());
    println!("Destination binding: {}", describe_binding(&policy));
    if policy.is_empty() {
        println!("                    (empty: nothing would be exposed)");
    }

    println!("Upstream socket:    {}", upstream.path().display());
    let stop = match shutdown_flag(&[
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]) {
        Ok(flag) => flag,
        Err(e) => {
            error(e);
            return EXIT_FAIL;
        }
    };
    let ids = match upstream.identities_cancellable(&stop) {
        Ok(ids) => {
            println!("Upstream agent:     reachable ({} identities)", ids.len());
            Some(ids)
        }
        Err(e) => {
            println!("Upstream agent:     FAIL ({e})");
            ok = false;
            None
        }
    };

    if let Some(ids) = &ids {
        let present: HashSet<Fingerprint> = ids
            .iter()
            .filter(|id| policy.allows(&id.blob))
            .map(|id| Fingerprint::of_blob(&id.blob))
            .collect();
        println!(
            "Approved identities: {}/{} available",
            present.len(),
            policy.len()
        );
        for id in ids.iter().filter(|id| policy.allows(&id.blob)) {
            println!("  available  {}", describe(id));
        }
        for fp in policy.fingerprints().filter(|fp| !present.contains(fp)) {
            println!("  missing    {fp}");
            ok = false;
        }
        let hidden = ids.iter().filter(|id| !policy.allows(&id.blob)).count();
        println!("Hidden identities:  {hidden} (not shown)");

        let proxy = Proxy::new(policy.clone(), upstream.clone(), Limits::default());
        match Running::start(proxy, None).and_then(|r| {
            let res = self_test(r.rt.path(), &policy);
            drop(r);
            res
        }) {
            Ok(exposed) => println!(
                "Filtering:          verified (temporary socket exposed {} identit{}, \
                 non-allowlisted sign request rejected{})",
                exposed.len(),
                if exposed.len() == 1 { "y" } else { "ies" },
                if policy.destinations().is_some() && !exposed.is_empty() {
                    "; destination binding verified: unbound sign refused"
                } else {
                    ""
                }
            ),
            Err(e) => {
                println!("Filtering:          FAIL ({e})");
                ok = false;
            }
        }
    }

    if let Some(sock) = &args.socket {
        match socket::check_socket(sock) {
            Ok(()) => println!("Filtered socket:    secure ({})", sock.display()),
            Err(e) => {
                println!("Filtered socket:    FAIL ({e})");
                ok = false;
            }
        }
    }
    println!();
    if ok {
        println!("Result: all checks passed");
        EXIT_OK
    } else {
        println!("Result: some checks failed");
        EXIT_FAIL
    }
}

struct State {
    pid: u32,
    upstream: String,
    allow: Vec<Fingerprint>,
    destinations: Vec<Fingerprint>,
}

fn read_state(socket_path: &Path) -> Result<Option<State>, String> {
    let path = RuntimeSocket::state_path_for(socket_path);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if !meta.is_file()
        || meta.uid() != socket::current_uid()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err(format!("{} is not a private regular file", path.display()));
    }
    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut st = State {
        pid: 0,
        upstream: String::new(),
        allow: Vec::new(),
        destinations: Vec::new(),
    };
    for line in text.lines() {
        match line.split_once('=') {
            Some(("pid", v)) => st.pid = v.parse().map_err(|_| "bad pid in state file")?,
            Some(("upstream", v)) => st.upstream = v.to_string(),
            Some(("allow", v)) => st.allow.push(v.parse().map_err(|e| format!("{e}"))?),
            Some(("destination", v)) => {
                st.destinations.push(v.parse().map_err(|e| format!("{e}"))?)
            }
            _ => {}
        }
    }
    Ok(Some(st))
}

fn status(args: StatusArgs) -> i32 {
    let Some(sock) = args.socket else {
        error("no socket: pass --socket PATH or set SSH_AUTH_SOCK");
        return EXIT_CONFIG;
    };
    println!("SigSieve Status\n");
    println!("Socket:             {}", sock.display());
    let mut ok = true;
    match socket::check_socket(&sock) {
        Ok(()) => println!("Permissions:        secure"),
        Err(e) => {
            println!("Permissions:        FAIL ({e})");
            ok = false;
        }
    }
    let state = match read_state(&sock) {
        Ok(s) => s,
        Err(e) => {
            println!("State file:         FAIL ({e})");
            ok = false;
            None
        }
    };
    match &state {
        Some(st) if socket::pid_alive(st.pid) => {
            println!("SigSieve process:   running (pid {})", st.pid);
            println!("Upstream:           {}", st.upstream);
            println!("Allowlist:          {} fingerprint(s)", st.allow.len());
            if st.destinations.is_empty() {
                println!("Destination binding: not enforced (identity filtering only)");
            } else {
                println!(
                    "Destination binding: enforced ({} destination host key(s))",
                    st.destinations.len()
                );
            }
        }
        Some(st) => {
            println!(
                "SigSieve process:   NOT RUNNING (stale state, pid {})",
                st.pid
            );
            ok = false;
        }
        None => {
            println!("SigSieve process:   unknown (no SigSieve state file next to this socket)");
            ok = false;
        }
    }
    match Upstream::new(&sock, Duration::from_secs(10)).identities() {
        Ok(ids) => {
            println!("Exposed identities: {}", ids.len());
            if let Some(st) = &state {
                for id in &ids {
                    let fp = Fingerprint::of_blob(&id.blob);
                    if st.allow.contains(&fp) {
                        println!("  {}", describe(id));
                    } else {
                        println!("  UNEXPECTED {fp} (not in recorded allowlist)");
                        ok = false;
                    }
                }
            }
        }
        Err(e) => {
            println!("Exposed identities: FAIL ({e})");
            ok = false;
        }
    }
    println!(
        "Filtering:          {}",
        if ok { "active" } else { "NOT VERIFIED" }
    );
    if ok {
        EXIT_OK
    } else {
        EXIT_FAIL
    }
}

/// Ask ssh to stop, then force it after a grace period.
fn stop_child(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    socket::terminate(child.id());
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(st)) = child.try_wait() {
            return Some(st);
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    child.wait().ok()
}

fn connect(args: ConnectArgs) -> i32 {
    if args.host.starts_with('-') || args.host.is_empty() {
        error("destination must not be empty or start with '-'");
        return EXIT_CONFIG;
    }
    let (policy, upstream) = match load(&args.policy) {
        Ok(v) => v,
        Err(e) => {
            error(e);
            return EXIT_CONFIG;
        }
    };
    if policy.is_empty() {
        error("allowlist is empty: nothing to forward (use ssh without agent forwarding)");
        return EXIT_CONFIG;
    }

    // Install handlers before starting anything so cleanup always runs.
    // Before ssh starts, any of these aborts. Afterwards SIGINT is left to ssh
    // (it receives terminal signals itself) and SIGTERM/SIGHUP stop ssh.
    let terminate =
        match shutdown_flag(&[signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP]) {
            Ok(f) => f,
            Err(e) => {
                error(e);
                return EXIT_FAIL;
            }
        };
    let interrupt = match shutdown_flag(&[signal_hook::consts::SIGINT]) {
        Ok(f) => f,
        Err(e) => {
            error(e);
            return EXIT_FAIL;
        }
    };

    let preflight_stop = match shutdown_flag(&[
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ]) {
        Ok(flag) => flag,
        Err(e) => {
            error(e);
            return EXIT_FAIL;
        }
    };
    let ids = match upstream.identities_cancellable(&preflight_stop) {
        Ok(ids) => ids,
        Err(e) => {
            error(e);
            return EXIT_FAIL;
        }
    };
    if !ids.iter().any(|id| policy.allows(&id.blob)) {
        error("none of the allowlisted identities is present in the upstream agent");
        return EXIT_FAIL;
    }

    let login_agent = std::env::var_os("SSH_AUTH_SOCK").filter(|v| !v.is_empty());
    let mut unfiltered: Vec<String> = vec![upstream.path().to_string_lossy().into_owned()];
    if let Ok(c) = fs::canonicalize(upstream.path()) {
        unfiltered.push(c.to_string_lossy().into_owned());
    }
    if let Some(a) = &login_agent {
        unfiltered.push(a.to_string_lossy().into_owned());
    }
    // Also match `~/…` spellings, as ssh prints config values unexpanded.
    if let Some(home) = std::env::var_os("HOME").map(|h| h.to_string_lossy().into_owned()) {
        let tilde: Vec<String> = unfiltered
            .iter()
            .filter_map(|p| p.strip_prefix(&home).map(|rest| format!("~{rest}")))
            .collect();
        unfiltered.extend(tilde);
    }

    eprintln!("sigsieve: {}", describe_binding(&policy));
    let check_policy = policy.clone();
    let running = match Running::start(Proxy::new(policy, upstream, Limits::default()), None) {
        Ok(r) => r,
        Err(e) => {
            error(e);
            return EXIT_FAIL;
        }
    };
    let Some(sock) = ssh_safe_path(running.rt.path()).map(str::to_owned) else {
        error(format_args!(
            "runtime socket path {} contains characters ssh would expand; set TMPDIR to a simple path",
            running.rt.path().display()
        ));
        return EXIT_FAIL;
    };
    match self_test(running.rt.path(), &check_policy) {
        Ok(exposed) => eprintln!(
            "sigsieve: forwarding filtered agent with {} identit{}",
            exposed.len(),
            if exposed.len() == 1 { "y" } else { "ies" }
        ),
        Err(e) => {
            error(format_args!("filtered agent self-test failed: {e}"));
            return EXIT_FAIL;
        }
    }

    // Our -o options come first; ssh uses the first value it obtains for an
    // option, so they win over ssh_config and over later -A / -o options.
    let mut ssh_opts: Vec<String> = [
        &format!("ForwardAgent={sock}"),
        "ControlPath=none",
        "ControlMaster=no",
        "ForwardX11=no",
    ]
    .iter()
    .flat_map(|o| ["-o".to_string(), o.to_string()])
    .collect();

    // If login authentication relies on SSH_AUTH_SOCK, pass that agent via
    // IdentityAgent instead; SSH_AUTH_SOCK itself is then pointed at the
    // filtered socket, so anything that uses it implicitly (ProxyCommand
    // children, `${SSH_AUTH_SOCK}` in ssh_config) gets the filtered agent.
    // The probe runs without ClearAllForwardings so we can tell the user which
    // forwardings are being disabled instead of dropping them silently.
    // An explicit IdentityAgent in ssh_config is kept as is.
    // ssh -G runs `Match exec` commands while it evaluates the configuration,
    // so refuse those before asking ssh anything.
    if let Err(e) = ssh_config_file(&args.ssh_args)
        .and_then(|f| sigsieve::sshconfig::check_no_match_exec(f.as_deref()))
    {
        error(format_args!("refusing to connect: {e}"));
        return EXIT_FAIL;
    }
    let probe = ssh_effective_config(
        Command::new(&args.ssh)
            .args(["-G", "-v"])
            .args(&ssh_opts)
            .arg(&args.host)
            .args(&args.ssh_args),
    );
    let identity_agent = match probe {
        Ok(cfg) => {
            let forwards: Vec<String> = cfg
                .iter()
                .filter(|(k, _)| {
                    matches!(
                        k.as_str(),
                        "remoteforward" | "localforward" | "dynamicforward"
                    )
                })
                .map(|(k, v)| format!("{k} {v}"))
                .collect();
            if !forwards.is_empty() {
                warn(format_args!(
                    "port forwardings are disabled in `sigsieve connect` sessions; ignoring: {}",
                    forwards.join(", ")
                ));
            }
            cfg.into_iter()
                .find(|(k, _)| k == "identityagent")
                .map(|(_, v)| v)
        }
        Err(e) => {
            error(format_args!("refusing to connect: {e}"));
            return EXIT_FAIL;
        }
    };
    let pass_login_agent = login_agent
        .as_ref()
        .filter(|a| match identity_agent.as_deref() {
            None | Some("SSH_AUTH_SOCK" | "$SSH_AUTH_SOCK" | "${SSH_AUTH_SOCK}") => true,
            Some(v) => a.to_str() == Some(v),
        });
    // All forwardings are cleared: RemoteForward is the only way to expose a
    // local socket to the remote, and clearing (rather than inspecting) is
    // immune to path spellings and to Match blocks that `ssh -G` evaluates
    // differently from a real connection.
    ssh_opts.push("-o".into());
    ssh_opts.push("ClearAllForwardings=yes".into());
    if pass_login_agent.is_some() {
        ssh_opts.push("-o".into());
        ssh_opts.push(format!("IdentityAgent=${{{LOGIN_AGENT_VAR}}}"));
    }
    // The environment ssh, and every process it starts (proxy hops included),
    // runs with.
    let session_env = |mut c: Command| {
        c.env("SSH_AUTH_SOCK", &sock).env_remove(LOGIN_AGENT_VAR);
        if let Some(a) = pass_login_agent {
            c.env(LOGIN_AGENT_VAR, a);
        }
        c
    };
    let ssh_command = |dump_config: bool| {
        let mut c = Command::new(&args.ssh);
        if dump_config {
            c.args(["-G", "-v"]);
        }
        c.args(&ssh_opts).arg(&args.host).args(&args.ssh_args);
        session_env(c)
    };
    let probe_hop = |argv: &[String]| {
        let file = hop_config_file(&argv[2..])?;
        sigsieve::sshconfig::check_no_match_exec(file.as_deref())?;
        let mut c = Command::new(&args.ssh);
        c.args(argv);
        ssh_effective_config(&mut session_env(c))
    };

    // Verify the exact invocation (same arguments and environment), then
    // every proxy hop it starts.
    let final_cfg = match ssh_effective_config(&mut ssh_command(true))
        .and_then(|cfg| verify_ssh_plan(&cfg, &sock, &unfiltered).map(|()| cfg))
        .and_then(|cfg| {
            let file = ssh_config_file(&args.ssh_args)?;
            verify_proxy_chain(&cfg, &args.ssh, file.as_deref(), &probe_hop).map(|_| cfg)
        }) {
        Ok(cfg) => cfg,
        Err(e) => {
            error(format_args!("refusing to connect: {e}"));
            return EXIT_FAIL;
        }
    };
    if args.dry_run {
        let value = |k: &str| {
            final_cfg
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        let mut planned = vec!["ssh".to_string()];
        planned.extend(ssh_opts.iter().cloned());
        planned.push(args.host.clone());
        planned.extend(args.ssh_args.iter().cloned());
        println!("SigSieve connect dry run (ssh not started)\n");
        println!("Destination binding: {}", describe_binding(&check_policy));
        println!("Forwarded agent:     filtered socket only (verified with ssh -G)");
        println!(
            "Login agent:         {}",
            match (pass_login_agent, value("identityagent")) {
                (Some(_), _) => "your SSH_AUTH_SOCK agent, passed as IdentityAgent".to_string(),
                (None, Some(v)) => format!("IdentityAgent from ssh_config: {v}"),
                (None, None) => "none configured (ssh may use the filtered agent)".to_string(),
            }
        );
        println!("Connection sharing:  disabled for this session");
        println!("Port forwardings:    disabled for this session");
        println!(
            "Proxy:               {}",
            match (value("proxyjump"), value("proxycommand")) {
                (Some(j), _) => {
                    format!("ProxyJump {j} (ssh -W relays; every hop verified with ssh -G)")
                }
                (None, Some(c)) if c != "none" => {
                    format!("ProxyCommand {c} (plain ssh -W relay; hop verified with ssh -G)")
                }
                _ => "none".to_string(),
            }
        );
        let shkc = value("stricthostkeychecking").unwrap_or_else(|| "?".into());
        let note = match shkc.as_str() {
            "yes" | "true" => "unknown or changed host keys are refused",
            "ask" => "unknown host keys prompt interactively; pass `-- -o StrictHostKeyChecking=yes` to refuse them",
            "accept-new" => "WARNING: unknown host keys are accepted on first use",
            "no" | "false" | "off" => "WARNING: host keys are not verified",
            _ => "unknown setting",
        };
        println!("Host key checking:   StrictHostKeyChecking={shkc} ({note})");
        println!("\nWould run: {}", planned.join(" "));
        println!("Result: all checks passed");
        return EXIT_OK;
    }
    if terminate.load(Ordering::SeqCst) || interrupt.load(Ordering::SeqCst) {
        error("interrupted before ssh started");
        return EXIT_FAIL;
    }

    let mut child = match ssh_command(false).spawn() {
        Ok(c) => c,
        Err(e) => {
            error(format_args!("cannot start {}: {e}", args.ssh.display()));
            return EXIT_FAIL;
        }
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(e) => {
                error(format_args!("waiting for ssh failed: {e}"));
                break stop_child(&mut child);
            }
        }
        if terminate.load(Ordering::SeqCst) {
            break stop_child(&mut child);
        }
        thread::sleep(Duration::from_millis(100));
    };
    drop(running);
    match status.and_then(|s| s.code()) {
        Some(code) => code,
        None => EXIT_FAIL,
    }
}
