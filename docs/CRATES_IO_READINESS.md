# crates.io readiness assessment

Status on 2026-10-29: **not published, and not ready to publish.** Nothing in
this assessment uploaded a crate, reserved a name or used a registry token.
SigSieve remains an experimental, unaudited alpha. A crates.io release would
not change that.

Assessed revision: `main` at `2edffc8` (package version `0.1.0-alpha.2`),
using the Homebrew-provided cargo 1.99.1.

## Commands run

| Command | Exit | Result |
|---|---|---|
| `cargo package --locked --list` | 0 | 71 files (list reviewed below) |
| `cargo package --locked --no-verify` | 0 | `Packaged 71 files, 618.0KiB (181.5KiB compressed)` |
| `cargo publish --dry-run --locked` (no token in the environment) | 0 | Packaged, verified with a `dev` build of the packaged sources, then `warning: aborting upload due to dry run` |
| `cargo check --tests --locked --offline` in the unpacked `.crate` | 101 | `couldn't read src/../fuzz/seeds/session_bind/sequence` (lib test) and `tests/../fuzz/seeds/session_bind/sequence` (`tests/proxy.rs`) |
| `GET https://crates.io/api/v1/crates/sigsieve` (read-only) | HTTP 404 | Name not registered. `cargo search sigsieve` returned no results |

The dry run's verify step only **builds** the packaged crate. It does not run
`cargo test`. A passing dry run does not mean the published source can run
its own tests. The `cargo check --tests` row shows that it cannot
(blocker 1).

## Findings

### Package contents

- **`fuzz/` is excluded.** It has its own `Cargo.toml`, so cargo treats it as
  a separate package and leaves it out. An unpacked `.crate` has no
  `fuzz/seeds`. But three tests need those seeds:
  `src/fuzzing.rs` (a `#[cfg(test)]` `include_bytes!("../fuzz/seeds/...")`),
  `tests/proxy.rs` (the same `include_bytes!`), and `tests/fuzz_corpus.rs`,
  which reads `fuzz/seeds` at runtime. As a result, `cargo test` on the
  published source **fails to compile** (shown above with `cargo check --tests`), which hurts distribution packagers
  and reviewers who work from the crate.
- **Unneeded files are shipped.** These are `.github/` (issue templates and
  all workflows), `.gitignore`, `deny.toml`, `rust-toolchain.toml`, and
  `scripts/*.py` / `scripts/*.sh`. None contains a secret or key material.
  They make the crate larger to review and are not needed to build it.
- Size is small: 181.5 KiB compressed, well under the crates.io limit. No
  build outputs, sockets or key files are present (`.gitignore` excludes them
  and the list confirms it).
- `Cargo.lock` is included. `cargo install` uses it only with `--locked`.
  Without `--locked`, users resolve the newest compatible dependency versions.
  For a security tool, that means code nobody has reviewed. Install
  instructions must say `cargo install --locked`.

### Metadata (`Cargo.toml`)

| Field | State |
|---|---|
| `license` | `MIT`, present, `LICENSE` packaged |
| `readme` | `README.md`, packaged |
| `repository` | present |
| `description` | present |
| `keywords` | 4, all valid (at most 5, ASCII, at most 20 characters) |
| `categories` | `command-line-utilities`, `cryptography` (valid slugs) |
| `rust-version` | **missing**. No MSRV is declared |
| `include` / `exclude` | **missing**, so the whole Git tree is shipped (minus `fuzz/`) |

The README has 35 repository-relative links (`docs/...`, `examples/...`).
crates.io can only resolve these against the `repository` URL, not the
release commit. The release-archive packaging already rewrites them to the
source commit. Check how they render before publishing (not verified here).
The packaged README must not point readers to newer `main` documentation as
if it described the release.

### Toolchain and MSRV

`rust-toolchain.toml` pins 1.99.1 for CI and releases. Neither `cargo install`
from crates.io nor a non-rustup toolchain (such as Homebrew's) honours it.
Users build with whatever compiler they have. Without `rust-version`, an
older compiler fails with dependency or language errors, not a clear MSRV
message. A declared MSRV needs a CI job that tests it.

### Provenance

GitHub build-provenance attestations cover only the release archives. A
`.crate` uploaded by `cargo publish` gets no `gh attestation`. It is a source
tarball built on the publisher's machine, and users cannot check that it was
built from the tag. crates.io trusted publishing (OIDC from a GitHub
workflow) would show *which workflow uploaded* the crate. It would not prove
the contents match the tag, and it would need its own reviewed workflow and
repository settings. Neither exists.

### Library API exposure

The package is a library plus a binary (`src/lib.rs` declares nine `pub mod`,
including the `#[doc(hidden)] fuzzing`). Publishing puts that API under
semver expectations, and docs.rs would build and display it. The project has
not decided whether the library is a supported interface.

### Name, yanking and permanence

- `sigsieve` is unregistered today. The first `cargo publish` claims it
  permanently for the publishing account.
- Published versions cannot be deleted or overwritten. `cargo yank` only stops
  new lockfiles from selecting a version. Existing `Cargo.lock` files still
  resolve it. No yanking policy exists. For
  example: yank on a security fix that a release supersedes, and announce it in
  `SECURITY.md` and the release notes.
- Pre-release versions (`0.1.0-alpha.N`) are allowed. Install instructions
  should name the exact version (`cargo install --locked sigsieve --version
  0.1.0-alpha.2`) instead of relying on cargo's default version selection.

### Governance

No crates.io owner, team or token policy is defined. Before publishing,
decide who owns the crate (and whether a second owner exists to prevent
lock-out), require 2FA on the GitHub account behind crates.io, and decide how
tokens are scoped and stored (scoped, short-lived, never in CI unless trusted
publishing is reviewed). Each publish also needs the same maintainer approval
and release-checklist evidence as a GitHub release.

## Blockers

1. The packaged source cannot run its own tests because `fuzz/seeds` is
   missing. Fix this by moving the seeds that tests use (for example to
   `tests/data/`) or by restructuring so the files are packaged. Then check
   with `cargo package` and `cargo test` run in the unpacked crate.
2. There is no `include`/`exclude` allowlist, so CI and release tooling ship
   in the crate.
3. No `rust-version` (MSRV) is declared and no CI job tests one.
4. No provenance story for the `.crate`, and no reviewed trusted-publishing
   workflow.
5. No decision on whether the `pub` library API is supported (semver,
   docs.rs).
6. Missing governance: owners, 2FA, token handling, a yanking policy, and a
   crates.io step in `docs/RELEASE_CHECKLIST.md`.
7. Packaged README links are not pinned to the release commit as the
   release archives' links are.

## Recommendation

Do not publish to crates.io for the `0.1.0-alpha.*` series. Keep GitHub
pre-releases (attested binaries) and tagged source builds as the supported
channels. If the maintainer later wants a crates.io release, fix blockers 1
to 3 in an ordinary reviewed change, decide 4 to 6 explicitly, and then run
`cargo publish --dry-run --locked` on the exact release commit. Publishing
claims the name permanently and cannot be undone, so the actual publish
(and any name reservation) requires explicit maintainer approval.
