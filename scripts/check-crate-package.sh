#!/usr/bin/env bash
# Check the crates.io package without publishing anything:
#   1. `cargo package --locked` (builds the .crate, verifies it compiles).
#   2. The file list ships no CI, release tooling or sub-packages, and
#      contains the fuzz seeds byte-identical to fuzz/seeds.
#   3. `cargo test --locked --offline` passes inside the unpacked .crate.
#
# Run from a clean checkout (cargo package refuses a dirty tree). Honours
# CARGO_TARGET_DIR. SIGSIEVE_REQUIRE_SSHD is passed through unchanged: set it
# to 1 where OpenSSH is installed so the sshd tests cannot skip.
#
# Usage: scripts/check-crate-package.sh

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

fail() { echo "check-crate-package: $*" >&2; exit 1; }

pkgid=$(cargo pkgid --offline)
# path+file:///dir#name@version, or path+file:///name#version
frag=${pkgid##*#}
if [[ $frag == *@* ]]; then name=${frag%@*}; else name=${pkgid%#*}; name=${name##*/}; fi
version=${frag##*@}
[ -n "$name" ] && [ -n "$version" ] || fail "cannot parse pkgid: $pkgid"

target_dir=${CARGO_TARGET_DIR:-$root/target}
cargo package --locked
crate="$target_dir/package/$name-$version.crate"
[ -f "$crate" ] || fail "missing $crate"

# Unpack where no parent directory has a Cargo.toml (or workspace).
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$crate" -C "$work"
# .crate entries carry a fixed 2006 mtime; refresh them so cargo never treats
# artifacts from an earlier unpacked copy as up to date.
find "$work" -exec touch {} +
pkg="$work/$name-$version"
[ -f "$pkg/Cargo.toml" ] || fail "unpacked crate has no Cargo.toml"

list=$(cd "$pkg" && find . -type f | sed 's#^\./##' | LC_ALL=C sort)

forbidden='^(\.github/|scripts/|fuzz/|target/|deny\.toml$|rust-toolchain\.toml$|\.gitignore$)'
if bad=$(grep -E "$forbidden" <<<"$list"); then
  fail "forbidden files in package:"$'\n'"$bad"
fi
for f in Cargo.toml Cargo.lock README.md LICENSE src/lib.rs src/main.rs; do
  grep -qxF "$f" <<<"$list" || fail "missing from package: $f"
done

# The seeds must arrive as real files, identical to the committed corpus.
expected=$(cd fuzz/seeds && find . -type f | LC_ALL=C sort)
packaged=$(cd "$pkg/tests/data/fuzz-seeds" 2>/dev/null && find . -type f | LC_ALL=C sort) ||
  fail "package has no tests/data/fuzz-seeds directory"
[ -n "$expected" ] || fail "fuzz/seeds is empty"
[ "$expected" = "$packaged" ] || fail "packaged seed list differs from fuzz/seeds"
while IFS= read -r f; do
  cmp -s "fuzz/seeds/$f" "$pkg/tests/data/fuzz-seeds/$f" || fail "seed differs: $f"
done <<<"$expected"
echo "check-crate-package: file list ok ($(wc -l <<<"$list" | tr -d ' ') files, $(wc -l <<<"$expected" | tr -d ' ') seeds)"

# Own subdirectory of the target dir: the unpacked crate builds units with the
# same hashes as the repo, so sharing one directory would let either reuse the
# other's stale binaries (with a different CARGO_MANIFEST_DIR baked in).
(cd "$pkg" && CARGO_TARGET_DIR="$target_dir/check-crate-package" cargo test --locked --offline -- --nocapture)
echo "check-crate-package: ok"
