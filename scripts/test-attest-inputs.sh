#!/usr/bin/env bash
# Regression test for F-42: runs the release attest job's input-binding shell
# steps, extracted from .github/workflows/release.yml, against synthetic
# artifacts. The positive case must pass; every tampering case must fail with
# its specific error. `gh` is replaced by a stub that prints a fixture
# artifact listing; downloads are simulated by placing zips where
# download-artifact would. Needs bash, ruby, python3, shasum, unzip and GNU
# find (gfind on macOS).
#
#   bash scripts/test-attest-inputs.sh
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The two `run:` scripts that consume the producing jobs' outputs.
extract() {
    ruby -ryaml -e '
      steps = YAML.load_file(ARGV[0], aliases: true)["jobs"]["attest"]["steps"]
      s = steps.select { |x| x["name"] == ARGV[1] }
      abort "step not found exactly once: #{ARGV[1]}" unless s.size == 1
      print s[0]["run"]' "$repo/.github/workflows/release.yml" "$1"
}
extract "Artifacts in this run are exactly the ones the producing jobs uploaded" > "$work/bind.sh"
extract "Exactly the expected files per artifact, with matching checksums" > "$work/files.sh"

mkdir "$work/bin"
cat > "$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
# Stub: the attest step calls `gh api --paginate .../runs/<id>/artifacts ...`.
case "$*" in
    "api --paginate repos/o/r/actions/runs/111/artifacts?per_page=100 --jq "*) cat "$FAKE_LISTING" ;;
    *) echo "unexpected gh call: $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$work/bin/gh"
if ! find --version 2>/dev/null | grep -q GNU; then
    ln -s "$(command -v gfind)" "$work/bin/find"
fi
export PATH="$work/bin:$PATH" GITHUB_REF_NAME=v9.9.9 GITHUB_RUN_ID=111 GITHUB_REPOSITORY=o/r

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
# zip_of out.zip file... : zip the given files (flat), like upload-artifact.
zip_of() {
    python3 -I -c 'import sys, zipfile, os
with zipfile.ZipFile(sys.argv[1], "w") as z:
    for f in sys.argv[2:]: z.write(f, os.path.basename(f))' "$@"
}

# Genuine build outputs: one archive (+ .sha256) per target, one SBOM artifact.
src=$work/src
mkdir -p "$src/aarch64-apple-darwin" "$src/x86_64-unknown-linux-gnu" "$src/sbom" "$src/evil"
sbomfiles=()
for t in aarch64-apple-darwin x86_64-unknown-linux-gnu; do
    n="sigsieve-v9.9.9-$t"
    printf 'genuine %s\n' "$t" > "$src/$t/$n.tar.gz"
    (cd "$src/$t" && shasum -a 256 "$n.tar.gz" > "$n.tar.gz.sha256")
    zip_of "$src/$t.zip" "$src/$t/$n.tar.gz" "$src/$t/$n.tar.gz.sha256"
    printf '{"sbom":"%s"}\n' "$t" > "$src/sbom/$n.cdx.json"
    (cd "$src/sbom" && shasum -a 256 "$n.cdx.json" > "$n.cdx.json.sha256")
    sbomfiles+=("$src/sbom/$n.cdx.json" "$src/sbom/$n.cdx.json.sha256")
done
zip_of "$src/sbom.zip" "${sbomfiles[@]}"
# A replacement aarch64 archive with a self-consistent .sha256.
n=sigsieve-v9.9.9-aarch64-apple-darwin
printf 'replaced\n' > "$src/evil/$n.tar.gz"
(cd "$src/evil" && shasum -a 256 "$n.tar.gz" > "$n.tar.gz.sha256")
zip_of "$src/evil.zip" "$src/evil/$n.tar.gz" "$src/evil/$n.tar.gz.sha256"

A_ID=1001 X_ID=1002 S_ID=1003 E_ID=1004
A_DIG=$(sha "$src/aarch64-apple-darwin.zip")
X_DIG=$(sha "$src/x86_64-unknown-linux-gnu.zip")
S_DIG=$(sha "$src/sbom.zip")
E_DIG=$(sha "$src/evil.zip")
export src E_ID E_DIG
A_SHA=$(sha "$src/aarch64-apple-darwin/sigsieve-v9.9.9-aarch64-apple-darwin.tar.gz")
X_SHA=$(sha "$src/x86_64-unknown-linux-gnu/sigsieve-v9.9.9-x86_64-unknown-linux-gnu.tar.gz")

row() { printf '%s\t%s\tsha256:%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-111}" "${5:-false}"; }
genuine_listing() {
    row sigsieve-aarch64-apple-darwin "$A_ID" "$A_DIG"
    row sigsieve-x86_64-unknown-linux-gnu "$X_ID" "$X_DIG"
    row sigsieve-sbom "$S_ID" "$S_DIG"
}

# edit AWK: rewrite the fixture listing (tab-separated) with an awk program
# run before printing each row; used by `tamper` hooks.
edit() {
    awk -F '\t' -v OFS='\t' "$1"' { print }' "$FAKE_LISTING" > "$FAKE_LISTING.new"
    mv "$FAKE_LISTING.new" "$FAKE_LISTING"
}
export -f edit

pass=0 failed=0
# run_case NAME EXPECT [VAR=value ...]: fresh workspace with the genuine
# outputs, listing and downloads, unless the case overrides them via
# variables or the hook function `tamper` (run inside the workspace).
# EXPECT is "ok" or a substring the failing step must print.
run_case() {
    local name=$1 expect=$2; shift 2
    local d="$work/case" out rc
    rm -rf "$d"; mkdir -p "$d/zip/aarch64-apple-darwin" "$d/zip/x86_64-unknown-linux-gnu" "$d/zip/sbom"
    cp "$src/aarch64-apple-darwin.zip" "$d/zip/aarch64-apple-darwin/artifact.zip"
    cp "$src/x86_64-unknown-linux-gnu.zip" "$d/zip/x86_64-unknown-linux-gnu/artifact.zip"
    cp "$src/sbom.zip" "$d/zip/sbom/artifact.zip"
    genuine_listing > "$d/listing"
    set +e
    out=$(cd "$d" && env FAKE_LISTING="$d/listing" \
        AARCH64_ID="$A_ID" AARCH64_DIGEST="$A_DIG" AARCH64_SHA256="$A_SHA" \
        X86_64_ID="$X_ID" X86_64_DIGEST="$X_DIG" X86_64_SHA256="$X_SHA" \
        SBOM_ID="$S_ID" SBOM_DIGEST="$S_DIG" "$@" \
        bash -c 'if declare -F tamper >/dev/null; then tamper || { echo "tamper hook failed"; exit 99; }; fi
                 bash -eo pipefail "$0" && bash -eo pipefail "$1"' "$work/bind.sh" "$work/files.sh" </dev/null 2>&1)
    rc=$?
    set -e
    if [ "$expect" = ok ]; then
        if [ $rc -eq 0 ]; then echo "PASS  $name (accepted)"; pass=$((pass + 1))
        else echo "FAIL  $name: expected success, exit $rc"; printf '%s\n' "$out" | sed 's/^/      /'; failed=$((failed + 1)); fi
    elif [ $rc -ne 0 ] && printf '%s\n' "$out" | grep -qF -- "$expect"; then
        echo "PASS  $name (rejected: $(printf '%s\n' "$out" | grep -m1 '::error::'))"; pass=$((pass + 1))
    else
        echo "FAIL  $name: expected rejection with '$expect', exit $rc"; printf '%s\n' "$out" | sed 's/^/      /'; failed=$((failed + 1))
    fi
    unset -f tamper
}

run_case "positive: IDs, digests and archive hashes all match" ok

run_case "wrong artifact ID from the build job" "is not the one its producing job uploaded" AARCH64_ID=1005

run_case "artifact digest output differs from the run's artifact" \
    "is not the one its producing job uploaded" X86_64_DIGEST="$(printf '0%.0s' {1..64})"

# Listing and outputs agree (as if both were forged) but the downloaded bytes
# are different: the zip hash against the producing job's digest catches it.
tamper() { cp "$src/evil.zip" zip/aarch64-apple-darwin/artifact.zip; }
export -f tamper
run_case "downloaded zip differs from the producing job's digest" "downloaded zip digest"

# Archive and a self-consistent .sha256 replaced. The ID and zip digest point
# at the replacement too, so only the archive-hash layer is left to catch it.
tamper() {
    cp "$src/evil.zip" zip/aarch64-apple-darwin/artifact.zip
    edit '$1 == "sigsieve-aarch64-apple-darwin" { $2 = ENVIRON["E_ID"]; $3 = "sha256:" ENVIRON["E_DIG"] }'
}
export -f tamper
run_case "archive replaced with self-consistent .sha256" "from its build job" AARCH64_ID="$E_ID" AARCH64_DIGEST="$E_DIG"

tamper() { printf 'sigsieve-aarch64-apple-darwin\t%s\tsha256:%s\t111\tfalse\n' "$E_ID" "$E_DIG" >> "$FAKE_LISTING"; }
export -f tamper
run_case "extra artifact with the same name in the run" "2 artifacts of that name"

tamper() { edit '$1 == "sigsieve-sbom" { next }'; }
export -f tamper
run_case "expected artifact missing from the run" "0 artifacts of that name"

for v in AARCH64_ID AARCH64_DIGEST AARCH64_SHA256 X86_64_ID X86_64_DIGEST X86_64_SHA256 SBOM_ID SBOM_DIGEST; do
    run_case "empty output $v" "$v from the producing job is missing or malformed" "$v="
done
run_case "malformed ID output" "AARCH64_ID from the producing job is missing or malformed" "AARCH64_ID=1001,1002"
run_case "uppercase/prefixed digest output" "SBOM_DIGEST from the producing job is missing or malformed" "SBOM_DIGEST=sha256:$S_DIG"

run_case "aarch64 outputs taken from the x86_64 job (other leg)" \
    "is not the one its producing job uploaded" AARCH64_ID="$X_ID" AARCH64_DIGEST="$X_DIG" AARCH64_SHA256="$X_SHA"

tamper() { edit '{ $4 = 222 }'; }
export -f tamper
run_case "artifact belongs to another workflow run" "is not the one its producing job uploaded"

tamper() { edit '$1 == "sigsieve-sbom" { $5 = "true" }'; }
export -f tamper
run_case "artifact expired" "is not the one its producing job uploaded"

tamper() { cp zip/sbom/artifact.zip zip/sbom/second.zip; }
export -f tamper
run_case "two files where one downloaded zip is expected" "expected exactly one downloaded zip file"

tamper() { rm zip/x86_64-unknown-linux-gnu/artifact.zip; }
export -f tamper
run_case "no downloaded zip" "expected exactly one downloaded zip file"

# R-3: the SBOM job runs third-party tooling, so its zip is untrusted even
# when it is the one the job uploaded. Each crafted zip holds the four
# genuine SBOM files plus one bad entry (or lacks one); the listing and the
# SBOM digest output point at it, so only the entry check can reject it.
craft() { # out.zip kind
    python3 -I - "$@" "$src/sbom" <<'EOF'
import os, sys, zipfile
out, kind, sbom = sys.argv[1:]
files = sorted(os.listdir(sbom))
def entry(z, name, mode, data=b"x"):
    zi = zipfile.ZipInfo("placeholder")
    zi.filename = name  # set after construction: keeps a NUL byte
    zi.external_attr = mode << 16
    z.writestr(zi, data)
with zipfile.ZipFile(out, "w") as z:
    for f in files[:-1] if kind == "missing" else files:
        z.write(os.path.join(sbom, f), f)
    reg = 0o100644
    if kind == "symlink":
        entry(z, "link", 0o120777, b"../../etc/passwd")
    elif kind == "dotdot":
        entry(z, "../escape", reg)
    elif kind == "absolute":
        entry(z, "/tmp/escape", reg)
    elif kind == "directory":
        entry(z, "sub/", 0o040755, b"")
    elif kind == "subdir":
        entry(z, "sub/" + files[0], reg)
    elif kind == "unexpected":
        entry(z, "extra.txt", reg)
    elif kind == "duplicate":
        import warnings; warnings.simplefilter("ignore")
        entry(z, files[0], reg)
    elif kind == "nul":
        entry(z, files[0] + "\0../escape", reg)
    elif kind == "no-mode":
        entry(z, "nomode", 0)
EOF
}
bad_sbom() { # kind expected-error
    local z="$src/bad-$1.zip" dig
    craft "$z" "$1"
    dig=$(sha "$z")
    tamper() {
        cp "$BAD_ZIP" zip/sbom/artifact.zip
        edit '$1 == "sigsieve-sbom" { $3 = "sha256:" ENVIRON["SBOM_DIGEST"] }'
    }
    export -f tamper
    run_case "SBOM zip with $1 entry" "$2" BAD_ZIP="$z" SBOM_DIGEST="$dig"
}
bad_sbom symlink "sbom: symlink entry 'link'"
bad_sbom dotdot "sbom: '..' in entry name '../escape'"
bad_sbom absolute "sbom: absolute path entry '/tmp/escape'"
bad_sbom directory "sbom: directory entry 'sub/'"
bad_sbom subdir "sbom: path separator in entry name 'sub/"
bad_sbom unexpected "sbom: unexpected entry 'extra.txt'"
bad_sbom duplicate "sbom: duplicate entry 'sigsieve-v9.9.9-"
bad_sbom nul "sbom: NUL in entry name"
# zipfile stores a zero mode as 0600 with no file type bits.
bad_sbom no-mode "sbom: entry 'nomode' is not a regular file (mode 600)"
bad_sbom missing "sbom: missing entries"

# Nothing may be extracted when the entry check fails (the last case's
# workspace is still in place).
if [ -e "$work/case/in/sbom" ]; then
    echo "FAIL  rejected SBOM zip was extracted"; failed=$((failed + 1))
else
    echo "PASS  rejected SBOM zip was not extracted"; pass=$((pass + 1))
fi

echo "$pass passed, $failed failed"
[ "$failed" -eq 0 ]
