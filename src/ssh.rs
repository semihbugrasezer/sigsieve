//! Verify the effective SSH invocation and every proxy hop before connecting.
//! Unknown command forms fail closed; this module never starts a session.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Paths are passed to ssh's config parser, which expands `~`, `%` and `$`;
/// accept only characters that need no quoting or expansion.
pub(crate) fn ssh_safe_path(p: &Path) -> Option<&str> {
    let s = p.to_str()?;
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
        .then_some(s)
}

/// Environment variable through which `connect` hands the login agent to ssh
/// (as `IdentityAgent=${...}`) so that `SSH_AUTH_SOCK` can point at the
/// filtered socket for ssh and its ProxyCommand. (ssh re-exports the login
/// agent to LocalCommand, which is why PermitLocalCommand is refused.)
pub(crate) const LOGIN_AGENT_VAR: &str = "SIGSIEVE_LOGIN_AGENT";

/// `ssh -G` output as (lowercase key, value) pairs.
type SshConfig = Vec<(String, String)>;

/// Evaluates an ssh argument vector with `ssh -G` (see `verify_proxy_chain`).
type SshProbe<'a> = dyn Fn(&[String]) -> Result<SshConfig, String> + 'a;

/// Run `ssh -G -v …` and return its `key value` lines. `-v` makes ssh log
/// every `Match exec` command it runs ("Executing command: …"); such commands
/// run arbitrary programs with the session's environment, so they are refused.
pub(crate) fn ssh_effective_config(cmd: &mut Command) -> Result<SshConfig, String> {
    let out = cmd.output().map_err(|e| format!("cannot run ssh: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`ssh -G` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if let Some(line) = String::from_utf8_lossy(&out.stderr)
        .lines()
        .find(|l| l.contains("Executing command:"))
    {
        return Err(format!(
            "ssh_config runs a `Match exec` command ({}); it cannot be verified \
             not to use or forward an unfiltered agent",
            line.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect())
}

/// Whether a ProxyCommand is a plain `ssh … -W …` relay (what ProxyJump
/// generates). A `-W` relay opens no session, so it cannot forward an agent.
/// Anything else (other programs, shell syntax, wrappers) cannot be verified:
/// a nested ssh started indirectly reads ssh_config and may forward the
/// unfiltered agent via IdentityAgent, so `connect` refuses it (fail closed).
fn proxycommand_is_ssh_relay(cmd: &str) -> bool {
    if cmd.chars().any(|c| ";|&$`'\"#()<>\\*?{}!\n".contains(c)) {
        return false;
    }
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let is_ssh = words
        .first()
        .is_some_and(|w| *w == "ssh" || w.ends_with("/ssh"));
    is_ssh && words.iter().any(|w| w.starts_with("-W"))
}

/// Check the effective configuration of the exact ssh invocation:
/// - the only forwarded agent is the filtered socket,
/// - connection sharing is off (a shared master would forward its own agent),
/// - all port/socket forwardings are cleared (no RemoteForward of an agent),
/// - any ProxyCommand is a plain `ssh -W` relay, and LocalCommand is off,
/// - no other option mentions an unfiltered agent socket (heuristic; only
///   `identityagent`, used for login authentication, may).
pub(crate) fn verify_ssh_plan(
    cfg: &[(String, String)],
    sock: &str,
    unfiltered: &[String],
) -> Result<(), String> {
    let get = |key: &str| -> Vec<&str> {
        cfg.iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    };
    match get("forwardagent").as_slice() {
        [v] if *v == sock => {}
        [v] => {
            return Err(format!(
            "ssh would forward {v:?} instead of the filtered socket (ssh too old, or overridden)"
        ))
        }
        _ => return Err("could not determine ssh's effective ForwardAgent setting".into()),
    }
    if get("controlpath").iter().any(|v| *v != "none") {
        return Err("ssh connection sharing (ControlPath) is still active".into());
    }
    if get("controlmaster")
        .iter()
        .any(|v| *v != "false" && *v != "no")
    {
        return Err("ssh connection sharing (ControlMaster) is still active".into());
    }
    if get("clearallforwardings").as_slice() != ["yes"] {
        return Err("ssh port forwardings could not be cleared".into());
    }
    if get("forwardx11").as_slice() != ["no"] {
        return Err(
            "X11 forwarding is enabled (-X/-Y?); ssh runs xauth with the unfiltered \
             login agent in SSH_AUTH_SOCK, so it is off in connect sessions"
                .into(),
        );
    }
    if let Some((k, _)) = cfg.iter().find(|(k, _)| {
        matches!(
            k.as_str(),
            "remoteforward" | "localforward" | "dynamicforward"
        )
    }) {
        return Err(format!("ssh still has a `{k}` forwarding"));
    }
    if let Some(cmd) = get("proxycommand").into_iter().find(|v| *v != "none") {
        if !proxycommand_is_ssh_relay(cmd) {
            return Err(format!(
                "ProxyCommand {cmd:?} cannot be verified not to forward an unfiltered \
                 agent; only plain `ssh -W` relays are allowed (use ProxyJump, or \
                 `sigsieve run` with ssh manually)"
            ));
        }
    }
    check_no_local_commands(cfg, "")?;
    for (k, v) in cfg {
        if k == "identityagent" || k == "forwardagent" {
            continue;
        }
        if let Some(path) = unfiltered
            .iter()
            .find(|p| !p.is_empty() && v.contains(p.as_str()))
        {
            return Err(format!(
                "ssh option `{k}` references the unfiltered agent socket {path}"
            ));
        }
    }
    Ok(())
}

/// LocalCommand and KnownHostsCommand run arbitrary programs with the
/// session's environment (ssh re-exports the login agent to LocalCommand), so
/// neither may be enabled on the destination or on any proxy hop.
fn check_no_local_commands(cfg: &[(String, String)], hop: &str) -> Result<(), String> {
    let has = |key: &str, ok: &[&str]| {
        cfg.iter()
            .any(|(k, v)| k == key && !ok.contains(&v.as_str()))
    };
    if has("permitlocalcommand", &["no", "false"]) {
        return Err(format!(
            "PermitLocalCommand is enabled{hop}; LocalCommand runs with the unfiltered \
             login agent in SSH_AUTH_SOCK"
        ));
    }
    if has("knownhostscommand", &["none"]) {
        return Err(format!(
            "KnownHostsCommand is set{hop}; it runs a program that cannot be verified \
             not to use or forward an unfiltered agent"
        ));
    }
    Ok(())
}

/// ssh(1) options that take an argument (OpenSSH getopt string).
const SSH_OPTS_WITH_ARG: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// ssh options as (letter, argument), the argument empty for flags.
type SshOpts = Vec<(char, String)>;

/// Split ssh arguments as ssh's getopt does: options (flag clusters expanded,
/// `-Fx` and `-F x` alike) up to the first operand or `--`, then operands.
fn ssh_getopt(args: &[String]) -> Result<(SshOpts, &[String]), String> {
    let mut opts = Vec::new();
    let mut i = 0;
    while let Some(a) = args.get(i) {
        if a == "--" {
            i += 1;
            break;
        }
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            break;
        };
        for (j, c) in flags.char_indices() {
            if SSH_OPTS_WITH_ARG.contains(c) {
                let rest = &flags[j + c.len_utf8()..];
                let val = if rest.is_empty() {
                    i += 1;
                    args.get(i)
                        .ok_or_else(|| format!("ssh option -{c} needs an argument"))?
                        .clone()
                } else {
                    rest.to_string()
                };
                opts.push((c, val));
                break;
            }
            opts.push((c, String::new()));
        }
        i += 1;
    }
    Ok((opts, &args[i.min(args.len())..]))
}

/// The `-F` file among options (the last `-F` wins). For connect's ssh
/// arguments, which follow the destination, the first operand starts the
/// remote command.
pub(crate) fn ssh_config_file(ssh_args: &[String]) -> Result<Option<String>, String> {
    let (opts, _) = ssh_getopt(ssh_args)?;
    Ok(last_config_file(opts))
}

/// The `-F` file of a complete ssh argument vector: options, destination,
/// then options again (ssh parses both).
pub(crate) fn hop_config_file(argv: &[String]) -> Result<Option<String>, String> {
    let (mut opts, rest) = ssh_getopt(argv)?;
    if let Some((_, after)) = rest.split_first() {
        opts.extend(ssh_getopt(after)?.0);
    }
    Ok(last_config_file(opts))
}

fn last_config_file(opts: SshOpts) -> Option<String> {
    opts.into_iter()
        .rev()
        .find(|(c, _)| *c == 'F')
        .map(|(_, v)| v)
}

/// Characters allowed in a hop's user and host: ssh would refuse the rest,
/// and a leading `-` must never be read as an option.
fn hop_word_ok(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-:%".contains(c))
}

/// Parse one ProxyJump element, `[ssh://][user@]host[:port]` (IPv6 hosts in
/// brackets), into (user, host, port).
fn parse_jump_hop(spec: &str) -> Result<(Option<&str>, &str, Option<&str>), String> {
    let bad = || format!("cannot verify ProxyJump host {spec:?}");
    let s = spec.strip_prefix("ssh://").unwrap_or(spec);
    let (user, hostport) = match s.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, s),
    };
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(bad)?;
        match after {
            "" => (h, None),
            p => (h, Some(p.strip_prefix(':').ok_or_else(bad)?)),
        }
    } else {
        match hostport.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if !hop_word_ok(host) || !user.is_none_or(hop_word_ok) || !port_ok {
        return Err(bad());
    }
    Ok((user, host, port))
}

/// Resolve a command name as the shell would (PATH lookup for bare names).
fn resolve_program(p: &Path) -> Option<PathBuf> {
    if p.components().count() > 1 {
        return fs::canonicalize(p).ok();
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(p))
        .find(|c| c.is_file())
        .and_then(|c| fs::canonicalize(c).ok())
}

/// Whether two command names resolve to the same executable file.
fn same_program(a: &Path, b: &Path) -> bool {
    matches!((resolve_program(a), resolve_program(b)), (Some(x), Some(y)) if x == y)
}

/// Maximum number of proxy hops `connect` verifies; longer chains are refused.
const MAX_PROXY_HOPS: usize = 8;

/// Verify every proxy hop of a connection whose effective configuration is
/// `cfg`. Each ProxyJump hop and each `ssh … -W` ProxyCommand starts another
/// ssh that reads ssh_config for its own host, does not receive our `-o`
/// options and inherits the session environment. For each such hop, rebuild
/// the exact command ssh runs (OpenSSH ssh.c for ProxyJump; the ProxyCommand
/// words for relays), evaluate it with `probe` (`ssh -G -v` with the session
/// environment) and require: a stdio relay (`sessiontype none`), no local
/// commands, and recursively verified proxies of its own. Anything that cannot
/// be modelled exactly is refused.
pub(crate) fn verify_proxy_chain(
    cfg: &[(String, String)],
    ssh: &Path,
    config_file: Option<&str>,
    probe: &SshProbe,
) -> Result<usize, String> {
    let mut seen = Vec::new();
    verify_hops(cfg, ssh, config_file, probe, &mut seen)?;
    Ok(seen.len())
}

fn verify_hops(
    cfg: &[(String, String)],
    ssh: &Path,
    config_file: Option<&str>,
    probe: &SshProbe,
    seen: &mut Vec<Vec<String>>,
) -> Result<(), String> {
    let get = |key: &str| {
        cfg.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| *v != "none")
    };
    let target = format!(
        "[{}]:{}",
        get("hostname").unwrap_or_default(),
        get("port").unwrap_or("22")
    );
    let mut argv: Vec<String> = vec!["-G".into(), "-v".into()];
    // The -F file the hop's own ssh reads: ProxyJump hops get their parent's
    // (ssh passes it on), a relay only the one on its own command line.
    let child_file: Option<String>;
    match (get("proxyjump"), get("proxycommand")) {
        (None, None) => return Ok(()),
        (Some(_), Some(_)) => return Err("both ProxyJump and ProxyCommand are set".into()),
        (Some(jump), None) => {
            // ssh.c: `ssh [-l user] [-p port] [-J rest] [-F file] -W '[%h]:%p' host`
            // for the last element; earlier elements become its own -J.
            let (rest, last) = match jump.rsplit_once(',') {
                Some((r, l)) => (Some(r), l),
                None => (None, jump),
            };
            let (user, host, port) = parse_jump_hop(last)?;
            if let Some(u) = user {
                argv.extend(["-l".into(), u.into()]);
            }
            if let Some(p) = port {
                argv.extend(["-p".into(), p.into()]);
            }
            if let Some(r) = rest {
                argv.extend(["-J".into(), r.into()]);
            }
            if let Some(f) = config_file {
                // ssh pastes it unquoted into the shell command it builds.
                if ssh_safe_path(Path::new(f)).is_none() {
                    return Err(format!(
                        "config file path {f:?} contains characters the shell would \
                         interpret in ssh's ProxyJump command; use a simple path"
                    ));
                }
                argv.extend(["-F".into(), f.into()]);
            }
            argv.extend(["-W".into(), target, host.into()]);
            child_file = config_file.map(str::to_owned);
        }
        (None, Some(cmd)) => {
            if !proxycommand_is_ssh_relay(cmd) {
                return Err(format!(
                    "ProxyCommand {cmd:?} cannot be verified not to forward an unfiltered \
                     agent; only plain `ssh -W` relays are allowed (use ProxyJump, or \
                     `sigsieve run` with ssh manually)"
                ));
            }
            // The relay's ssh is verified with connect's ssh, so it must be
            // the same program (ProxyJump hops always are: ssh uses argv[0]).
            let relay_bin = cmd.split_whitespace().next().unwrap_or_default();
            if !same_program(Path::new(relay_bin), ssh) {
                return Err(format!(
                    "cannot verify ProxyCommand {cmd:?} (its ssh is not the ssh connect runs)"
                ));
            }
            // ssh parses options, the destination, options again, then the
            // remote command, which a relay must not have.
            let words: Vec<String> = cmd
                .split_whitespace()
                .skip(1)
                .map(|w| {
                    w.replace("%%", "\0")
                        .replace("%h", get("hostname").unwrap_or_default())
                        .replace("%p", get("port").unwrap_or("22"))
                        .replace("%r", get("user").unwrap_or_default())
                })
                .collect();
            if words.iter().any(|w| w.contains('%')) {
                return Err(format!(
                    "cannot verify ProxyCommand {cmd:?} (unsupported % token)"
                ));
            }
            let words: Vec<String> = words.iter().map(|w| w.replace('\0', "%")).collect();
            let (opts, rest) = ssh_getopt(&words)?;
            let (host, after) = rest
                .split_first()
                .ok_or_else(|| format!("cannot verify ProxyCommand {cmd:?} (no host)"))?;
            let (more, command) = ssh_getopt(after)?;
            if !command.is_empty() || !hop_word_ok(host.rsplit('@').next().unwrap_or(host)) {
                return Err(format!(
                    "cannot verify ProxyCommand {cmd:?} (not a plain relay)"
                ));
            }
            if !opts.iter().chain(&more).any(|(c, _)| *c == 'W') {
                return Err(format!("cannot verify ProxyCommand {cmd:?} (no -W relay)"));
            }
            child_file = last_config_file(opts.into_iter().chain(more).collect());
            argv.extend(words);
        }
    }
    if seen.contains(&argv) {
        return Err("proxy hops form a loop".into());
    }
    if seen.len() >= MAX_PROXY_HOPS {
        return Err(format!("more than {MAX_PROXY_HOPS} proxy hops"));
    }
    seen.push(argv.clone());
    let hop_cfg =
        probe(&argv).map_err(|e| format!("proxy hop `ssh {}`: {e}", argv[2..].join(" ")))?;
    let hop = format!(" on proxy hop `ssh {}`", argv[2..].join(" "));
    if !hop_cfg
        .iter()
        .any(|(k, v)| k == "sessiontype" && v == "none")
    {
        return Err(format!("proxy hop is not a plain stdio relay{hop}"));
    }
    // A relay opens no session, but its own forwardings (e.g. RemoteForward
    // of an agent socket) would still be set up unless cleared.
    let forwards = hop_cfg.iter().any(|(k, _)| {
        matches!(
            k.as_str(),
            "remoteforward" | "localforward" | "dynamicforward"
        )
    });
    if forwards
        || !hop_cfg
            .iter()
            .any(|(k, v)| k == "clearallforwardings" && v == "yes")
    {
        return Err(format!("proxy hop keeps port forwardings{hop}"));
    }
    check_no_local_commands(&hop_cfg, &hop)?;
    verify_hops(&hop_cfg, ssh, child_file.as_deref(), probe, seen).map_err(|e| format!("{e}{hop}"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::Builder;

    use super::proxycommand_is_ssh_relay as relay;
    use super::same_program;

    #[test]
    fn only_plain_ssh_w_relays_are_accepted() {
        assert!(relay("ssh -W %h:%p bastion"));
        assert!(relay("/usr/bin/ssh -W [%h]:%p -l me bastion"));
        assert!(relay("ssh -W%h:%p bastion"));
        for bad in [
            "ssh -A bastion nc %h %p",
            "/usr/bin/ssh bastion nc %h %p",
            "/usr/bin/env ssh -A bastion nc %h %p",
            "env ssh -W %h:%p bastion",
            "sh -c 'ssh -A bastion nc %h %p'",
            "ssh -A bastion nc %h %p # -W",
            "ssh -W %h:%p bastion; ssh -A other",
            "ssh -W %h:%p $BASTION",
            "cloudflared access ssh --hostname %h",
            "nc -X connect -x proxy:8080 %h %p",
            "",
        ] {
            assert!(!relay(bad), "{bad:?}");
        }
    }

    #[test]
    fn same_program_compares_resolved_paths() {
        let dir = Builder::new().tempdir_in(".").unwrap();
        let dir_path = dir.path();

        let file1 = dir_path.join("file1");
        let file2 = dir_path.join("file2");
        let sym1 = dir_path.join("sym1");

        // Create two distinct files
        fs::write(&file1, "1").unwrap();
        fs::write(&file2, "2").unwrap();

        // Create a symlink to file1
        symlink("file1", &sym1).unwrap();

        // Absolute and relative path to the same file
        assert!(same_program(&file1, &file1.canonicalize().unwrap()));
        // Symlink and the file it points to
        assert!(same_program(&sym1, &file1));
        // Two distinct files
        assert!(!same_program(&file1, &file2));
        // Missing paths
        let missing = dir_path.join("missing");
        assert!(!same_program(&file1, &missing));
    }
}
