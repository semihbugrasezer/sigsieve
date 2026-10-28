#!/bin/sh
# Verify the artifacts of a SigSieve release.yml run before attaching them to
# a GitHub pre-release (docs/RELEASE_CHECKLIST.md, publication step 4).
#
# Usage: verify-release.sh RUN_ID [TAG]     (TAG default: v0.1.0-alpha.2)
#
# Exit 0 (PASS) only when every check, including the native smoke test of the
# archive for this host, passed. Run it on macOS arm64 and on Linux x86_64:
# each run smoke-tests only its own platform's binary. ALLOW_NO_NATIVE=1 lets
# a run on another platform finish, reporting INCOMPLETE and exiting 3.
#
# Read-only towards GitHub: downloads the run's artifacts, verifies checksums
# and build provenance, inspects the archives and smoke-tests the native
# binary against a throwaway ssh-agent. Creates no tag, release or comment.
# Never talks to your own ssh-agent and never reads ~/.ssh.
set -eu

REPO=semihbugrasezer/sigsieve
WORKFLOW=.github/workflows/release.yml
TARGETS="aarch64-apple-darwin x86_64-unknown-linux-gnu"

[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: $0 RUN_ID [TAG]" >&2; exit 2; }
RUN_ID=$1
TAG=${2:-v0.1.0-alpha.2}
VERSION=${TAG#v}
case $RUN_ID in *[!0-9]* | '') echo "RUN_ID must be numeric" >&2; exit 2 ;; esac
case $TAG in v[0-9]*) ;; *) echo "TAG must look like v0.1.0-alpha.2" >&2; exit 2 ;; esac

work=''
agent_pid=''
done_ok=0
cleanup() {
    rc=$?
    if [ -n "$agent_pid" ]; then kill "$agent_pid" 2>/dev/null || true; fi
    if [ -n "$work" ]; then rm -rf "$work"; fi
    if [ "$done_ok" -ne 1 ] && [ "$rc" -ne 0 ]; then
        echo "RESULT: FAIL (exit $rc)" >&2
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

die() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok    $*"; }

for t in gh tar uname mktemp ssh-agent ssh-add ssh-keygen awk sort file; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"
done
if command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
elif command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; } # same "hash  name" format as shasum
else
    die "missing tool: shasum or sha256sum"
fi

# Keep everything this script starts away from the caller's agent.
unset SSH_AUTH_SOCK SSH_AGENT_PID

work=$(mktemp -d)
chmod 700 "$work"
dl=$work/download
mkdir "$dl"

# 1. The run is a successful release.yml run for TAG at the tag's commit.
run_info=$(gh run view "$RUN_ID" --repo "$REPO" \
    --json workflowName,event,headBranch,headSha,conclusion \
    --jq '[.workflowName, .event, .headBranch, .headSha, .conclusion] | join(" ")')
# Split into fields on purpose; workflowName "Release build" is two words.
# shellcheck disable=SC2086
set -- $run_info
[ "$1 $2" = "Release build" ] || die "run $RUN_ID is workflow '$1 $2', not 'Release build'"
[ "$3" = push ] || die "run event is '$3', not push"
[ "$4" = "$TAG" ] || die "run ref is '$4', not $TAG"
run_sha=$5
[ "${6:-}" = success ] || die "run conclusion is '${6:-in progress}', not success"
tag_sha=$(gh api "repos/$REPO/commits/$TAG" --jq .sha)
[ "$run_sha" = "$tag_sha" ] || die "run commit $run_sha != $TAG commit $tag_sha"
ok "run $RUN_ID: Release build, push of $TAG at $tag_sha, success"

# 1b. Every job (verify-tag, the called CI, both builds and attest) succeeded
# on a GitHub-hosted runner: the attestation is signed by a hosted runner,
# but that alone does not say where the archives were compiled.
jobs=$(gh api --paginate "repos/$REPO/actions/runs/$RUN_ID/jobs" \
    --jq '.jobs[] | [.name, .conclusion, (.runner_group_name // ""), (.labels | join(","))] | join("\t")')
[ -n "$jobs" ] || die "run $RUN_ID has no jobs"
printf '%s\n' "$jobs" | awk -F '\t' '$2 != "success" { print "  job not successful: " $1 " (" $2 ")"; bad = 1 }
    $3 != "GitHub Actions" { print "  job not on a GitHub-hosted runner: " $1 " (group \"" $3 "\")"; bad = 1 }
    END { exit bad }' >&2 || die "run $RUN_ID has unsuccessful or self-hosted jobs"
for want in "build (macos-latest, aarch64-apple-darwin)	macos-latest" \
            "build (ubuntu-24.04, x86_64-unknown-linux-gnu)	ubuntu-24.04"; do
    name=${want%%	*}; label=${want#*	}
    printf '%s\n' "$jobs" | awk -F '\t' -v n="$name" -v l="$label" '$1 == n && $4 == l { f = 1 } END { exit !f }' \
        || die "no successful '$name' job on runner label $label"
done
printf '%s\n' "$jobs" | awk -F '\t' '$1 == "attest" { f = 1 } END { exit !f }' || die "no attest job"
ok "jobs: all successful on GitHub-hosted runners; both build jobs and attest present"

# 2. Exactly the two archives and their checksum files.
gh run download "$RUN_ID" --repo "$REPO" --dir "$dl"
expected=$(for t in $TARGETS; do
    n="sigsieve-$TAG-$t.tar.gz"
    printf '%s\n%s\n' "sigsieve-$t/$n" "sigsieve-$t/$n.sha256"
done | LC_ALL=C sort)
# gh run download puts several artifacts in per-artifact directories; locate
# files by name instead of relying on that layout, and allow nothing else.
[ "$(find "$dl" ! -type d | wc -l | tr -d ' ')" = 4 ] || die "expected 4 artifact files, got:
$(cd "$dl" && find . ! -type d)
expected (any directory):
$expected"
for t in $TARGETS; do
    for f in "sigsieve-$TAG-$t.tar.gz" "sigsieve-$TAG-$t.tar.gz.sha256"; do
        [ "$(find "$dl" -type f -name "$f" | wc -l | tr -d ' ')" = 1 ] || die "missing or duplicate artifact $f"
    done
    mkdir -p "$work/a-$t"
    mv "$(find "$dl" -type f -name "sigsieve-$TAG-$t.tar.gz")" "$(find "$dl" -type f -name "sigsieve-$TAG-$t.tar.gz.sha256")" "$work/a-$t/"
done
dl=$work/a
mkdir "$dl"
for t in $TARGETS; do mv "$work/a-$t" "$dl/sigsieve-$t"; done
ok "artifacts: exactly 2 archives + 2 checksum files named for $TAG"

# 3. Checksums.
for t in $TARGETS; do
    n="sigsieve-$TAG-$t.tar.gz"
    d=$dl/sigsieve-$t
    [ "$(wc -l < "$d/$n.sha256" | tr -d ' ')" = 1 ] || die "$n.sha256 is not one line"
    awk -v n="$n" 'NF != 2 || $2 != n || $1 !~ /^[0-9a-f]{64}$/ { exit 1 }' "$d/$n.sha256" \
        || die "$n.sha256 does not name $n with a SHA-256 digest"
    (cd "$d" && sha256 -c "$n.sha256" >/dev/null) || die "checksum mismatch for $n"
done
ok "checksums match"

# 4. Build provenance, bound to this repository, workflow, tag and commit.
# Every constraint is required; an older gh that lacks one fails instead of
# silently checking less.
help=$(gh attestation verify --help 2>&1 || true)
for flag in signer-workflow source-ref source-digest deny-self-hosted-runners; do
    printf '%s\n' "$help" | grep -q -- "--$flag " || die "gh attestation verify lacks --$flag; upgrade gh"
done
signer="--signer-workflow $REPO/$WORKFLOW"
extra=" --source-ref refs/tags/$TAG --source-digest $tag_sha --deny-self-hosted-runners"
for t in $TARGETS; do
    n="sigsieve-$TAG-$t.tar.gz"
    # $signer and $extra are deliberately word-split; they contain no spaces
    # inside a value.
    # shellcheck disable=SC2086
    gh attestation verify "$dl/sigsieve-$t/$n" --repo "$REPO" $signer $extra \
        >"$work/attest-$t.txt" 2>&1 || { cat "$work/attest-$t.txt" >&2; die "attestation for $n"; }
done
ok "provenance: $signer$extra"

# 5. Archive contents (listed before extracting, so no path can escape).
for t in $TARGETS; do
    n="sigsieve-$TAG-$t"
    want=$(for f in CHANGELOG.md LICENSE README.md THIRD_PARTY_LICENSES.txt sigsieve; do
        echo "$n/$f"; done)
    got=$(tar -tzf "$dl/sigsieve-$t/$n.tar.gz" | LC_ALL=C sort)
    [ "$got" = "$want" ] || die "$n.tar.gz contents:
$got"
    mkdir "$work/x-$t"
    tar -xzf "$dl/sigsieve-$t/$n.tar.gz" -C "$work/x-$t"
    for f in LICENSE THIRD_PARTY_LICENSES.txt; do
        [ -s "$work/x-$t/$n/$f" ] || die "$n/$f is empty"
    done
    [ -x "$work/x-$t/$n/sigsieve" ] || die "$n/sigsieve is not executable"
    # The binary must be built for the target its archive is named after.
    kind=$(file -b "$work/x-$t/$n/sigsieve")
    case "$t:$kind" in
        aarch64-apple-darwin:*Mach-O*arm64*) ;;
        x86_64-unknown-linux-gnu:*ELF*x86-64*) ;;
        *) die "$n/sigsieve is '$kind', not a $t binary" ;;
    esac
done
ok "archive contents: exact file list, non-empty LICENSE and THIRD_PARTY_LICENSES.txt, binary type matches target"

# 6. Smoke test the native binary.
case "$(uname -s) $(uname -m)" in
    "Darwin arm64") host=aarch64-apple-darwin ;;
    "Linux x86_64") host=x86_64-unknown-linux-gnu ;;
    *) host='' ;;
esac
if [ -n "$host" ]; then
    bin=$work/x-$host/sigsieve-$TAG-$host/sigsieve
    v=$("$bin" --version)
    [ "$v" = "sigsieve $VERSION" ] || die "--version printed '$v', want 'sigsieve $VERSION'"
    "$bin" --help >/dev/null || die "--help failed"
    a=$work/agent
    mkdir -m 700 "$a"
    out=$(ssh-agent -s -a "$a/agent.sock") || die "ssh-agent did not start"
    agent_pid=$(printf '%s\n' "$out" | sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p')
    [ -n "$agent_pid" ] || die "could not read the throwaway agent pid"
    ssh-keygen -q -t ed25519 -N '' -C sigsieve-smoke -f "$a/key" </dev/null
    SSH_AUTH_SOCK=$a/agent.sock ssh-add -q "$a/key" 2>/dev/null || die "ssh-add to throwaway agent"
    fp=$(ssh-keygen -lf "$a/key.pub" | awk '{print $2}')
    "$bin" doctor --upstream "$a/agent.sock" --allow-fingerprint "$fp" >"$work/doctor.txt" 2>&1 \
        || { cat "$work/doctor.txt" >&2; die "doctor exited non-zero"; }
    grep -q "Filtering: *verified" "$work/doctor.txt" \
        || { cat "$work/doctor.txt" >&2; die "doctor did not verify filtering"; }
    kill "$agent_pid" 2>/dev/null || true
    agent_pid=''
    ok "native $host: --version, --help, doctor (Filtering: verified) against a throwaway agent"
elif [ "${ALLOW_NO_NATIVE:-0}" = 1 ]; then
    echo "skip  native smoke test: host $(uname -s) $(uname -m) has no release archive (ALLOW_NO_NATIVE=1)"
else
    die "no release archive for host $(uname -s) $(uname -m); run on macOS arm64 or Linux x86_64, or set ALLOW_NO_NATIVE=1 to skip the native smoke test explicitly"
fi

# 7. Summary for the release notes.
echo
if [ -n "$host" ]; then
    echo "RESULT: PASS  $TAG  run $RUN_ID  commit $tag_sha"
else
    echo "RESULT: INCOMPLETE  $TAG  run $RUN_ID  commit $tag_sha  (native smoke test NOT run)"
fi
echo "Native smoke test: ${host:-NOT RUN on $(uname -s) $(uname -m)}"
echo "Other target: run this script on that platform too; a release needs a native PASS for both."
echo "SHA-256:"
for t in $TARGETS; do
    cat "$dl/sigsieve-$t/sigsieve-$TAG-$t.tar.gz.sha256"
done
done_ok=1
# Everything else verified, but not the native binary: not a PASS.
[ -n "$host" ] || exit 3
