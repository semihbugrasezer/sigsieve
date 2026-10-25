//! Refuse `Match exec` in the user's ssh configuration *before* ssh runs.
//!
//! `ssh -G` evaluates `Match exec` by running the command, so `connect` cannot
//! ask ssh about a configuration that contains one without executing it. This
//! is a deliberately over-approximating scan, not an ssh_config parser: with
//! all quotes and backslashes removed (ssh's own argument splitting can only
//! join characters, never invent them), every `Match` line with a word `exec`
//! is refused, every `Include` is followed, and anything the scan cannot
//! resolve exactly as ssh would (quoted or tokenised include paths, `~user`,
//! wildcards outside the last path component, unreadable files, nesting
//! deeper than ssh allows) is refused.
//!
//! Scope: the configuration the user controls, i.e. the `-F` file or
//! `~/.ssh/config`, and everything they include. The system-wide file
//! (root-owned, location chosen when ssh was built) is trusted.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::socket::home_dir;

/// ssh's own include depth limit (readconf.c READCONF_MAX_DEPTH).
const MAX_DEPTH: usize = 16;

/// Check the configuration ssh reads for an invocation with `-F config_file`
/// (`None`: no `-F`, so `~/.ssh/config`).
pub fn check_no_match_exec(config_file: Option<&str>) -> Result<(), String> {
    let home = home_dir().ok_or("cannot determine the home directory")?;
    let file = match config_file {
        Some("none") => return Ok(()),
        Some(f) => PathBuf::from(f),
        None => home.join(".ssh/config"),
    };
    scan(&file, &home, 0)
}

fn scan(file: &Path, home: &Path, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{}: includes nested too deeply", file.display()));
    }
    let text = match fs::read(file) {
        Ok(t) => t,
        // ssh skips missing files too.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read {}: {e}", file.display())),
    };
    let text = std::str::from_utf8(&text)
        .map_err(|_| format!("{}: cannot verify non-UTF-8 configuration", file.display()))?;
    for (n, line) in text.lines().enumerate() {
        let at = || format!("{}:{}", file.display(), n + 1);
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // OpenSSH ends a quoted keyword at its closing quote even when the
        // argument immediately follows it (e.g. `"Match"exec`).
        let raw_keyword = line.split([' ', '\t', '=']).next().unwrap_or_default();
        if raw_keyword.contains(['"', '\'', '\\']) {
            return Err(format!(
                "{}: cannot verify a quoted or escaped keyword",
                at()
            ));
        }
        let bare: String = line
            .chars()
            .filter(|c| !"\"'\\".contains(*c))
            .collect::<String>()
            .to_ascii_lowercase();
        let mut words = bare
            .split(|c: char| c.is_whitespace() || c == '=')
            .filter(|w| !w.is_empty());
        let keyword = words.next();
        let mentions_exec = bare
            .split(|c: char| c.is_whitespace() || "=,!".contains(c))
            .any(|w| w == "exec");
        match keyword {
            Some("match") if mentions_exec => {
                return Err(format!(
                    "{}: `Match exec` would run a command while ssh evaluates its \
                     configuration",
                    at()
                ));
            }
            Some("include") => {
                if line.contains(['"', '\'', '\\']) {
                    return Err(format!("{}: cannot verify a quoted Include", at()));
                }
                let args = line[raw_keyword.len()..].trim_start_matches([' ', '\t']);
                let args = args
                    .strip_prefix('=')
                    .unwrap_or(args)
                    .trim_start_matches([' ', '\t']);
                // OpenSSH's argv_split separates Include paths on space/tab,
                // not '=' or Rust's broader Unicode whitespace class.
                for arg in args.split([' ', '\t']).filter(|a| !a.is_empty()) {
                    for f in resolve_include(arg, home).map_err(|e| format!("{}: {e}", at()))? {
                        scan(&f, home, depth + 1)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The files an `Include` argument names, as ssh's glob(3) would find them
/// (a superset: hidden files are included). Relative paths are in `~/.ssh`.
fn resolve_include(arg: &str, home: &Path) -> Result<Vec<PathBuf>, String> {
    if arg.chars().any(|c| "$%[{\\".contains(c)) {
        return Err(format!("cannot verify Include {arg:?}"));
    }
    let path = if let Some(rest) = arg.strip_prefix("~/") {
        home.join(rest)
    } else if arg.starts_with('~') {
        return Err(format!("cannot verify Include {arg:?}"));
    } else if arg.starts_with('/') {
        PathBuf::from(arg)
    } else {
        home.join(".ssh").join(arg)
    };
    let wild = |s: &str| s.contains(['*', '?']);
    let (dir, name) = match (path.parent(), path.file_name().and_then(|n| n.to_str())) {
        (Some(d), Some(n)) => (d, n),
        _ => return Err(format!("cannot verify Include {arg:?}")),
    };
    if wild(&dir.to_string_lossy()) {
        return Err(format!(
            "cannot verify Include {arg:?} (wildcard in a directory)"
        ));
    }
    if !wild(name) {
        return Ok(vec![path]);
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot list {}: {e}", dir.display())),
    };
    let mut found = Vec::new();
    for e in entries {
        let e = e.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        if glob_match(name.as_bytes(), e.file_name().as_encoded_bytes()) {
            found.push(e.path());
        }
    }
    found.sort();
    Ok(found)
}

/// `*` and `?` matching of one path component.
fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob_match(&pat[1..], s) || (!s.is_empty() && glob_match(pat, &s[1..])),
        (Some(b'?'), Some(_)) => glob_match(&pat[1..], &s[1..]),
        (Some(p), Some(c)) if p == c => glob_match(&pat[1..], &s[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(files: &[(&str, &str)]) -> Result<(), String> {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let p = dir.path().join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, text.replace("{d}", &dir.path().display().to_string())).unwrap();
        }
        scan(&dir.path().join(files[0].0), dir.path(), 0)
    }

    #[test]
    fn match_exec_is_refused_in_every_spelling() {
        for text in [
            "Match exec true\n",
            "  match host x EXEC \"true\"\n",
            "Match=exec true\n",
            "Match !exec true\n",
            "\"Match\" \"exec\" true\n",
            "Host a\n  User b\nMatch host c exec \"x\"\n",
            "Match e'x'ec true\n",
            "Match e\\xec true\n",
            "Match \"ex\"ec true\n",
            "Match host x,y exec true\n",
            "Match !\"exec\" true\n",
        ] {
            assert!(check(&[("cfg", text)]).is_err(), "{text:?}");
        }
    }

    #[test]
    fn quoted_keywords_cannot_hide_commands_or_includes() {
        for text in ["\"Match\"exec true\n", "\"Include\"{d}/inc\n"] {
            assert!(
                check(&[("cfg", text), ("inc", "Match exec true\n")]).is_err(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn includes_are_followed() {
        assert!(check(&[("cfg", "Include {d}/inc\n"), ("inc", "Match exec x\n")]).is_err());
        assert!(check(&[
            ("cfg", "Include {d}/a\n"),
            ("a", "Include {d}/b\n"),
            ("b", "Match exec x\n")
        ])
        .is_err());
        assert!(check(&[
            ("cfg", "Include {d}/conf.d/*.conf\n"),
            ("conf.d/1.conf", "Host x\n"),
            ("conf.d/2.conf", "Match exec x\n")
        ])
        .is_err());
        // Relative includes live in ~/.ssh (here the temp dir is "home").
        assert!(check(&[("cfg", "Include rel\n"), (".ssh/rel", "Match exec x\n")]).is_err());
        assert!(check(&[("cfg", "Include ~/x\n"), ("x", "Match exec x\n")]).is_err());
        for include in [
            "Include {d}/inc=payload\n",
            "Include={d}/inc=payload\n",
            "Include = {d}/inc=payload\n",
        ] {
            assert!(check(&[("cfg", include), ("inc=payload", "Match exec true\n")]).is_err());
        }
        for separator in ['\u{a0}', '\r', '\u{b}', '\u{c}'] {
            let name = format!("inc{separator}payload");
            let include = format!("Include {{d}}/{name}\n");
            assert!(check(&[("cfg", &include), (&name, "Match exec true\n")]).is_err());
        }
        // Includes ssh would skip are skipped; an include loop hits the depth limit.
        assert!(check(&[("cfg", "Include {d}/missing {d}/none-*\n")]).is_ok());
        assert!(check(&[("cfg", "Include {d}/cfg\n")]).is_err());
    }

    #[test]
    fn unverifiable_includes_are_refused() {
        for inc in [
            "Include \"{d}/a b\"\n",
            "Include ${HOME}/x\n",
            "Include %d/x\n",
            "Include ~root/x\n",
            "Include {d}/*/x\n",
            "Include {d}/[ab]\n",
            "Include '{d}/x'\n",
            "Include {d}/a\\ b\n",
        ] {
            assert!(check(&[("cfg", inc)]).is_err(), "{inc:?}");
        }
    }

    #[test]
    fn ordinary_configurations_pass() {
        assert!(check(&[
            (
                "cfg",
                "# Match exec in a comment\nHost bastion\n  ProxyJump a,b\nMatch host x user y\n  \
             ForwardAgent no\nMatch host executor.example.com\n  User x\nInclude {d}/inc\n"
            ),
            ("inc", "Host *\n  ServerAliveInterval 30\n")
        ])
        .is_ok());
        assert!(check_no_match_exec(Some("none")).is_ok());
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match(b"*.conf", b"a.conf"));
        assert!(glob_match(b"?.c*", b"x.conf"));
        assert!(!glob_match(b"*.conf", b"a.conf.bak"));
        assert!(glob_match(b"*", b""));
    }
}
