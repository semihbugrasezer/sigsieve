#!/bin/sh
# Controlled SigSieve integration check against a real SSH agent (for example
# Secretive). It is meant to be run by the key owner, by hand.
#
# What it does:
#   1. `sigsieve doctor` against the upstream agent.
#   2. Starts a filtered agent in a private temporary directory.
#   3. Checks the filtered listing contains exactly the allowed key.
#   4. For every *other* upstream key, sends a raw SIGN_REQUEST through the
#      filtered socket and expects SSH_AGENT_FAILURE. SigSieve rejects these
#      before contacting the upstream agent, so no Touch ID prompt is
#      expected; a prompt here would indicate a bug (deny it and report).
#   5. Optionally (--sign-allowed) signs a test message with the allowed key
#      and verifies it. Touch ID may prompt, depending on the agent.
#   6. Stops the filtered agent and checks its socket was removed, and that
#      the upstream agent still lists the same number of keys.
#
# It reads public keys only, prints only the allowed key's fingerprint and
# counts of the others, writes only inside a private mktemp directory, and
# changes no SSH, agent or system configuration.
#
# Usage:
#   scripts/agent-integration-check.sh --allow SHA256:... [--upstream PATH]
#                                      [--sign-allowed] [--sigsieve PATH]
# Default upstream: Secretive's socket.

set -eu

ALLOW=""
UPSTREAM="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"
SIGN_ALLOWED=0
SIGSIEVE="${SIGSIEVE:-sigsieve}"

while [ $# -gt 0 ]; do
  case "$1" in
    --allow) ALLOW="$2"; shift 2 ;;
    --upstream) UPSTREAM="$2"; shift 2 ;;
    --sign-allowed) SIGN_ALLOWED=1; shift ;;
    --sigsieve) SIGSIEVE="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$ALLOW" ] || { echo "--allow SHA256:... is required" >&2; exit 2; }
command -v "$SIGSIEVE" >/dev/null 2>&1 || { echo "sigsieve not found: $SIGSIEVE" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required for the raw sign test" >&2; exit 2; }

FAILURES=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/sigsieve-check.XXXXXX")
chmod 700 "$TMP"
RUN_PID=""
cleanup() {
  if [ -n "$RUN_PID" ] && kill -0 "$RUN_PID" 2>/dev/null; then
    kill -TERM "$RUN_PID" 2>/dev/null || true
    wait "$RUN_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

echo "== SigSieve agent integration check"
echo "upstream: $UPSTREAM"
echo "allowed:  $ALLOW"
echo

BEFORE=$(SSH_AUTH_SOCK="$UPSTREAM" ssh-add -l 2>/dev/null | wc -l | tr -d ' ')

# 1. doctor
if "$SIGSIEVE" doctor --upstream "$UPSTREAM" --allow-fingerprint "$ALLOW" > "$TMP/doctor.txt" 2>&1; then
  pass "doctor: all checks passed"
else
  fail "doctor reported problems:"; sed 's/^/      /' "$TMP/doctor.txt"
fi

# 2. filtered agent
SOCK="$TMP/f.sock"
"$SIGSIEVE" run --upstream "$UPSTREAM" --socket "$SOCK" --allow-fingerprint "$ALLOW" \
  > "$TMP/run.out" 2> "$TMP/run.err" &
RUN_PID=$!
i=0
while [ ! -S "$SOCK" ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
[ -S "$SOCK" ] || { fail "filtered agent did not start"; cat "$TMP/run.err"; exit 1; }

# 3. filtered listing
LISTING=$(SSH_AUTH_SOCK="$SOCK" ssh-add -l 2>&1 || true)
COUNT=$(printf '%s\n' "$LISTING" | grep -c 'SHA256:' || true)
if [ "$COUNT" -eq 1 ] && printf '%s' "$LISTING" | grep -qF "$ALLOW"; then
  pass "filtered agent lists exactly the allowed key"
else
  fail "filtered agent lists $COUNT keys (expected exactly the allowed one)"
fi

# 4. raw sign attempts with every hidden key
SSH_AUTH_SOCK="$UPSTREAM" ssh-add -L > "$TMP/upstream.pub" 2>/dev/null || true
HIDDEN=0
REFUSED=0
n=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  n=$((n + 1))
  printf '%s\n' "$line" > "$TMP/k$n.pub"
  fp=$(ssh-keygen -lf "$TMP/k$n.pub" | awk '{print $2}')
  [ "$fp" = "$ALLOW" ] && continue
  HIDDEN=$((HIDDEN + 1))
  t=$(SSH_AUTH_SOCK="$SOCK" python3 - "$TMP/k$n.pub" <<'PY'
import base64, os, socket, struct, sys
blob = base64.b64decode(open(sys.argv[1]).read().split()[1])
def s(b): return struct.pack(">I", len(b)) + b
req = bytes([13]) + s(blob) + s(b"sigsieve-integration-check") + struct.pack(">I", 0)
c = socket.socket(socket.AF_UNIX); c.connect(os.environ["SSH_AUTH_SOCK"])
c.sendall(struct.pack(">I", len(req)) + req)
n = struct.unpack(">I", c.recv(4, socket.MSG_WAITALL))[0]
print(c.recv(n, socket.MSG_WAITALL)[0])
PY
)
  [ "$t" = "5" ] && REFUSED=$((REFUSED + 1))
done < "$TMP/upstream.pub"
if [ "$HIDDEN" -eq "$REFUSED" ]; then
  pass "$HIDDEN hidden key(s): raw sign requests refused (details not shown)"
else
  fail "only $REFUSED of $HIDDEN hidden-key sign requests were refused"
fi

# 5. optional signature with the allowed key
if [ "$SIGN_ALLOWED" -eq 1 ]; then
  n=0
  while IFS= read -r line; do
    n=$((n + 1))
    fp=$(ssh-keygen -lf "$TMP/k$n.pub" | awk '{print $2}')
    [ "$fp" = "$ALLOW" ] && cp "$TMP/k$n.pub" "$TMP/allowed.pub"
  done < "$TMP/upstream.pub"
  echo "sigsieve integration test" > "$TMP/msg"
  echo "      (the upstream agent may now ask for Touch ID / confirmation)"
  if SSH_AUTH_SOCK="$SOCK" ssh-keygen -Y sign -n sigsieve-test -f "$TMP/allowed.pub" "$TMP/msg" >/dev/null 2>&1 \
     && ssh-keygen -Y check-novalidate -n sigsieve-test -f "$TMP/allowed.pub" -s "$TMP/msg.sig" < "$TMP/msg" >/dev/null 2>&1; then
    pass "allowed key signed through the filtered agent and the signature verifies"
  else
    fail "allowed key could not sign through the filtered agent"
  fi
fi

# 6. shutdown and cleanup
kill -TERM "$RUN_PID"
wait "$RUN_PID" 2>/dev/null || true
RUN_PID=""
if [ ! -e "$SOCK" ] && [ ! -e "$SOCK.state" ]; then
  pass "filtered socket removed on shutdown"
else
  fail "filtered socket or state file left behind"
fi
AFTER=$(SSH_AUTH_SOCK="$UPSTREAM" ssh-add -l 2>/dev/null | wc -l | tr -d ' ')
if [ "$BEFORE" = "$AFTER" ]; then
  pass "upstream agent unchanged ($AFTER keys listed before and after)"
else
  fail "upstream key count changed: $BEFORE -> $AFTER"
fi

echo
if [ "$FAILURES" -eq 0 ]; then echo "RESULT: all checks passed"; else echo "RESULT: $FAILURES check(s) failed"; exit 1; fi
