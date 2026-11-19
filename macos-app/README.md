<p align="center">
  <img src="App/Resources/Assets.xcassets/AppIcon.appiconset/icon_256x256.png" width="96" alt="SigSieve icon">
</p>

<h1 align="center">SigSieve for macOS</h1>

> **Preview, not released.** The app is not part of SigSieve v1.0.0, the
> Homebrew formula or the release archives. Build it from source; it is ad hoc
> signed, not notarized and not distributed. The released product is the
> `sigsieve` CLI.

A SwiftUI menu bar app for the `sigsieve` command line tool. You pick an SSH
server, choose which agent keys it may use, run the CLI's check, and connect in
Terminal. The design is in `DESIGN.md`.

The app is a convenience layer. The Rust CLI enforces: all filtering, key
binding and the setup checks happen in `sigsieve`, which re-checks when it
connects. The app has no copy of those checks, and a passing check in the
window is not a guarantee the connection will be allowed.

## What you see

- **Main window.** A server list with search. Only the selected server shows
  its check state, as a dot; other servers show none.
- The server header has the agent menu and the key count. Below it is the
  protection line. In filtering mode it shows "Forwarded key can sign for any
  server while connected", once, before and after Check.
- Then the forwarded keys and the Check result. Its Details are collapsed. They
  hold one two-column list per step (`sigsieve doctor`,
  `sigsieve connect --dry-run`), the copyable command after a pass, and the raw
  output folded under "Raw output".
- **Settings window.** A sidebar with Agent, Command Line and Files (⌘1, ⌘2,
  ⌘3). The socket path and the CLI path are saved only with Use or Save;
  Return never saves.
- **Menu bar panel.** The app icon, the server, its check state and the first
  blocking error in full. Open ↩, Settings… ⌘,, Quit ⌘Q. The menu bar icon is
  the app's fingerprint mark, with a dot when there is a blocking error.

## Requirements

- macOS 13 or newer; Apple Silicon first.
- Xcode 26 or newer (the tests use Swift 6.2 exit tests).
- The `sigsieve` 1.x CLI. The app uses the first of these paths that exists:
  the path set in Settings → Command Line, `/opt/homebrew/bin/sigsieve`,
  `/usr/local/bin/sigsieve`, then each directory in the app's own `PATH`. A
  path set in Settings is never replaced by another binary, and a broken
  candidate is reported, not skipped. Settings → Command Line shows the
  version it found.
- To use the CLI built below (Rust 1.99.1, see `rust-toolchain.toml`), enter
  its absolute path in Settings → Command Line (the field does no shell
  expansion; from the repository root, `echo "$PWD/target/release/sigsieve"`
  prints it). Otherwise a Homebrew CLI, if installed, is used. Release-archive
  (`~/.local/bin`) and `cargo install` (`~/.cargo/bin`) installs also need to
  be set there when the app is started from Finder (its PATH does not include
  them).

## Build and run

From the repository root:

```bash
cargo build --release --locked
xcodebuild -project macos-app/SigSieve.xcodeproj -scheme SigSieve \
  -configuration Release -derivedDataPath macos-app/build build
open macos-app/build/Build/Products/Release/SigSieve.app
```

The app is ad hoc signed for local runs. It has no Developer ID, is not
notarized and is not distributed.

## Copyable command

The copyable command is for POSIX shells (sh, bash, zsh). fish and csh/tcsh
are not supported; open `/bin/sh` first and paste it there.

## Known_hosts limits

When you bind a server to its host key, the app lists keys from your known_hosts
file. What it can and cannot see:

- Only ASCII lines are read. A line with a non-ASCII byte is dropped and not
  offered.
- A key on an `@revoked` or `@cert-authority` line is never offered, even when
  it also appears on an unmarked line of another host.
- A non-ASCII byte in an `@revoked` or `@cert-authority` line empties the whole
  list, because that exclusion could not be applied.
- Only `~/.ssh/known_hosts` is offered. Marked lines are also read from
  `/etc/ssh/ssh_known_hosts`, `/etc/ssh/ssh_known_hosts2` and
  `~/.ssh/known_hosts2` (for `@revoked` and `@cert-authority` only).
- A custom `UserKnownHostsFile`, `GlobalKnownHostsFile`, `KnownHostsCommand` or
  `RevokedHostKeys` is not read, so an empty revocation result does not mean
  every source was checked.
- A listed key means only that it was found in local files, not that it was
  verified.

## Security status

The tests are not a substitute for an independent external security audit. That
audit is still outstanding.

## Accepted risks (for external review)

- **Signal after the CLI is reaped (review F6).** On a timeout or cancel the app
  sends SIGTERM and, 2 seconds later, SIGKILL to the CLI's process group. The
  app never signals once it has seen the CLI exit: the exit flag is checked
  and the signal sent under one lock. The flag is set both in the
  `terminationHandler` and after `waitUntilExit()` returns, because Apple's
  `Process` API documents no ordering between the two. This closes our own
  check-then-kill window, a timeout or cancel that arrives after we observed
  a normal exit, and the earlier window of up to the step timeout (150 s). It
  narrows the risk; it does not remove it. Residual: Foundation reaps the CLI
  on its own queue outside that lock, so the remaining window lasts from
  Foundation reaping the child until our termination handler takes the lock;
  its length depends on thread scheduling and system load. Reuse inside it
  needs the kernel to wrap the pid space (PID_MAX 99999) within that window
  and, for `killpg`, a new group leader with that id. Closing it needs our own
  reaping (`posix_spawn` plus `waitpid` under the signalling lock), which
  conflicts with the plan rule "posix_spawn appears nowhere"; that redesign is
  an owner decision and is not opened now. Impact: a same-user signal only, no
  privilege gain, no cross-user effect. Trade-off: a same-group descendant
  still alive after the CLI is reaped is no longer killed at timeout or
  cancel; it is abandoned after the bounded pipe drain, like the
  already-accepted `setsid` case. See `ProcessRunner.terminate()`.
- **SSH config change detection on some filesystems.** A passed check is
  invalidated when a file it depended on changes, using size, times, inode and
  ctime. On filesystems with whole-second times (HFS+, FAT, exFAT) a same-size
  rewrite within the same second can be missed, and filesystems without real
  inode or ctime semantics (some network or FUSE volumes) can miss changes.
  This only affects whether an old check result stays visible; the CLI and
  OpenSSH check again when you connect.

## Tests

The Swift package `Packages/SigSieveKit` holds the app's logic. Its
integration tests run the real CLI against a throwaway `ssh-agent` with
synthetic keys; they never touch `~/.ssh`, your agent or your keys. From the
repository root:

```bash
cargo build --release --locked
SIGSIEVE_TEST_CLI=$PWD/target/release/sigsieve \
  swift test --package-path macos-app/Packages/SigSieveKit
```

Without `SIGSIEVE_TEST_CLI` the tests that need the CLI are skipped. With
`CI` set, a missing or non-executable `SIGSIEVE_TEST_CLI` fails the run.

## CI

`.github/workflows/macos-app.yml` runs on pushes and pull requests that change
`macos-app/`, the workflow itself, or the CLI it builds (`src/`, `Cargo.toml`,
`Cargo.lock`, `rust-toolchain.toml`). On
`macos-26` it selects Xcode 26.6 by path (the job fails on any other version),
checks the project opens under it, builds the CLI with Rust 1.99.1, runs the
package tests against that CLI, builds the app and lints its `Info.plist`. It
uploads nothing and uses no secrets.

CI builds with Xcode 26.6; local development has used Xcode 27.2. First run:
2026-11-18 on the pull-request merge commit of `1ef6c96` into `3dd1e24` (run
44309255824, macos-26 arm64, Xcode 26.6, Rust 1.99.1): 293 tests, only the fish
test skipped, Release build succeeded. Latest recorded run: 2026-11-18 on `main`
at `ac5e26d`, the merge of the redesigned UI (run 44423798526, Xcode 26.6): 319
tests, only the fish test skipped, Release build succeeded.

## Manual checklist

Things no automated test here can see. Run on a real Mac before a release.

The 2026-11-18 run used the owner's own account. Real keys and servers were not
used: only a new Secretive test key, `.invalid` server names (Check does not
connect), and `touch` instead of editing `~/.ssh/config`.

| # | Check | Status |
|---|-------|--------|
| 1 | With 500 keys in a throwaway agent selected in Settings, scrolling and typing in the key search (which now lives in the Edit Keys sheet) show no visible stall. | passed (2026-11-18, macOS 27.2.1): scrolling and typing `k49` showed no stall. Re-run on the redesigned UI: not run |
| 2 | Light and Dark Mode both readable. | passed (2026-11-18, macOS 27.2.1). Re-run on the redesigned UI: not run |
| 3 | Check with Secretive: the Touch ID wait shows "Waiting for agent…". | not observed (2026-11-18, macOS 27.2.1): the check passed with a Touch ID-protected Secretive key, but no Touch ID prompt appeared, because `doctor` and `--dry-run` request no signature. Needs a real connection to a test server |
| 4 | Connect opens Terminal with the session; no Automation prompt appears; the launcher directory is gone afterwards. | not run (2026-11-18): no dedicated test server |
| 5 | Pasting the copyable command into another terminal connects the same way. | not run (2026-11-18): no dedicated test server |
| 6 | Editing the profile while a session is open does not affect it; the window says "applies to new connections". | not run (2026-11-18): needs an open session, so a test server |
| 7 | Editing `~/.ssh/config` after a passed check disables Connect on the next window open or when Connect is pressed. | passed (2026-11-18, macOS 27.2.1): after a passed check, `touch ~/.ssh/config` (content unchanged, ctime changed) and reopening the window removed the result and Connect. Re-run on the redesigned UI: not run |
| M1 | Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server. After a passed check, open Edit Keys, untick a key and press Cancel: the result and Connect are unchanged. Open the sheet again, untick and press Save: the result clears and Connect is disabled. Run Check until it passes, open the sheet, change nothing and press Save: the passed result, its time and an enabled Connect all stay. Also close the sheet with Esc without Save (nothing changes). Also open Edit Keys while a key is "Not in the agent", press Save without changes, and confirm the row is still there. | not run |
| M1b | Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server. In the Edit Keys sheet, type in the search field and press Return. Expected: Return does nothing except search; the sheet stays open and nothing is saved (Save is not the default button). Only the Save button saves. | not run |
| M2 | Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server. With a throwaway OpenSSH agent (as in item 1) holding one synthetic key, forward it and run a check. `ssh-add -d` that key and reopen the window: the result is cleared and Connect is disabled, the row reads "Not in the agent" with no comment, and Edit Keys lists it ticked. `ssh-add` the same key file again and reopen: the row shows the key normally. Then add a second synthetic key with the same comment: it does not match the forwarded row, because the match is by fingerprint, not by name. | not run |
| M2b | Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server. Must never be run against a real server: it exists to prove Connect does NOT open Terminal, and a bug could open a real ssh session. After a passed check, `ssh-add -d` the forwarded key without reopening the window, then press Connect in Terminal. No Terminal opens; the result is cleared and Connect is disabled. | not run |
| M3 | Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server. In filtering mode, "Forwarded key can sign for any server while connected" is visible in the protection line before any check and after a pass, and is not repeated in the passed result. Every warning is visible while Details is closed. Read every warning in the real window with Details closed, in light and dark mode. | not run |
| M4a | With the window open, SigSieve is in the Dock and in ⌘Tab. After closing the window it is in neither, and the menu bar icon stays. | not run |
| M4b | "Open SigSieve" works with the window closed, behind other windows, and when it is already in front. It also restores a minimised main window, and the menu panel closes when it is pressed. | not run |
| M4c | ⌘, and the menu's "Settings…" open one Settings window. Closing Settings leaves the main window and the Dock state unchanged. Settings comes to the front from the menu bar while the app is menu-bar-only. The Settings window ends at its content (no empty band), the sidebar has no square focus ring, switching panes does not resize the window, and ⌘1, ⌘2 and ⌘3 switch panes. ⌘, does nothing while the app is menu-bar-only: a known limit, "Settings…" in the menu bar covers it. | not run |
| M4d | Quit and relaunch: the last selected server is selected again, and its check is "Not checked". Quit while the main window is closed, then relaunch: the main window opens. | not run |
| M4e | Quit, run `defaults write dev.sigsieve.macos selectedServer no-such-server.invalid`, and relaunch. Nothing is selected and there is no error. Repeat with the value `-bad`. | not run |
| M4f | Close the main window while Settings is open. Settings stays usable, and the Dock icon goes away (M4c covers only the reverse). | not run |
| M4g | Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server. Click "Open SigSieve" in the menu bar while a sheet is open on the main window, and again while a check is running. The window comes to the front, and the sheet and the running check are not disturbed. | not run |
| M5 | Rendering and runtime details. (a) Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server: it proves Connect does NOT open Terminal, and a bug could open a real ssh session. The disabled Connect button shows no accent tint, in light and dark mode; after a pass, pressing Return in the sidebar search field does not start "Connect in Terminal". (b) At the 640 pt minimum width with a wide sidebar, the warnings wrap rather than get cut off. (c) "Not in the agent" is never cut off. (d) The host-key detail shows what it should at minimum width. (e) With a long agent name, the key count stays visible next to it. (f) The menu bar responds right after the app switches into the Dock. (g) The menu panel shows current state when reopened while the main window is closed. | not run |
| M6 | Menu panel. Return opens SigSieve, ⌘, opens Settings and ⌘Q quits. The hover highlight does not stick after the panel closes and reopens. A long blocking error wraps in full. | not run |
| M7 | Details. Uses a server with a `.invalid` name and the throwaway agent from item 1, never a real server. After a check, Details shows untruncated labels, values aligned left, the two step headings, the command with Copy, and "Raw output" collapsed with the full CLI text inside. | not run |
| M8 | Sidebar dot. Only the selected server shows a dot. It turns green only after a passed check (when Connect is enabled) and red after a failed one. Selecting another server shows "Not checked" (a hollow ring). | not run |

A throwaway agent for item 1:

```bash
d=$(mktemp -d) && { /usr/bin/ssh-agent -D -a "$d/a.sock" >/dev/null & pid=$!; }
for i in $(seq 1 500); do ssh-keygen -q -t ed25519 -N '' -C "k$i" -f "$d/k$i"; done
SSH_AUTH_SOCK="$d/a.sock" ssh-add -q "$d"/k*[0-9]   # the 500 private keys, not the .pub files
# select $d/a.sock in Settings; afterwards:
kill "$pid"; rm -rf "$d"
```
