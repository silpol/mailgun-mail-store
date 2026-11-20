#!/usr/bin/env bash
# deploy/tests/e2e_deploy.sh — end-to-end rehearsal of the CD scripts (#48).
#
# Builds a simulated server in a temp dir (app dir with secrets, data and a
# hand-built venv, a fake uWSGI that restarts the app when a reload trigger is
# touched) and drives deploy/receive.sh exactly as CI does over SSH. Checks:
#   first deploy · code-only release removing a file · import error (stopped by
#   the smoke test) · live-only crash (auto-rollback) · dependency change (new
#   venv) · manual rollback x3 down to pre-CD · rollback with nothing left ·
#   secrets/data/foreign files untouched throughout.
# Runs on a throwaway copy, never on your checkout. Needs: git, python3 (+venv,
# pip, network for PyPI), curl, flock. ~1-3 minutes, mostly pip.
#
#   bash deploy/tests/e2e_deploy.sh
#   PYTHON=python3.14 E2E_REVERSE_SORT=0 bash deploy/tests/e2e_deploy.sh
set -uo pipefail
export PIP_DISABLE_PIP_VERSION_CHECK=1

PY="${PYTHON:-python3}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"
H="$T/home"
APP="$H/dmarc-handler"
R="$H/.local/bin/dmarc-deploy-receive"
PORT="$("$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
URL="http://127.0.0.1:$PORT/healthz"
UWSGI_PID=""
fails=0

cleanup() { [ -n "$UWSGI_PID" ] && kill "$UWSGI_PID" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
say() { printf '\n== %s\n' "$*"; }
check() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails + 1)); fi; }
rev() { curl -s --max-time 5 "$URL" | sed -n 's/.*"revision":"\([0-9a-f]\{7\}\).*/\1/p'; }
code() { curl -s -o /dev/null --max-time 5 -w '%{http_code}' "$URL"; }

# The server's sort/comm once disagreed on ordering (uutils); emulate a
# non-standard sort so a regression to order-dependent code fails here.
if [ "${E2E_REVERSE_SORT:-1}" = 1 ]; then
    mkdir -p "$T/bin"
    printf '#!/usr/bin/env bash\nexec %s -r "$@"\n' "$(command -v sort)" >"$T/bin/sort"
    chmod +x "$T/bin/sort"
    export PATH="$T/bin:$PATH"
fi

say "throwaway copy of the committed tree"
# A snapshot of HEAD in a fresh repo: works on shallow or detached CI checkouts
# and never touches your own checkout. Uncommitted changes are not included,
# just as CD only ships committed files.
G() { git -c user.name=e2e -c user.email=e2e@example.invalid "$@"; }
mkdir -p "$T/repo" && git -C "$REPO" archive HEAD | tar -x -C "$T/repo" && cd "$T/repo" || exit 1
git init -q -b e2e . && git add -A && G commit -qm "snapshot of $(git -C "$REPO" rev-parse --short HEAD)"

say "simulated server (pre-CD state)"
mkdir -p "$APP"/{instance,archive,failed,logs}
printf 'MAILGUN_API_KEY="k"\nMAILGUN_DOMAIN="mg.example"\nMAILGUN_RECIPIENT="r@x.example"\n' \
    >"$APP/instance/config.py"
echo keep >"$APP/archive/r1.xml"; echo keep >"$APP/failed/f1.xml"; echo mine >"$APP/notes-local.txt"
cat >"$APP/app.py" <<'PY'
# Stand-in for the pre-CD app: no /healthz route (404), like the real old code.
from flask import Flask
app = Flask(__name__)
@app.route("/")
def index():
    return "pre-cd"
PY
echo "pre-cd legacy file" >"$APP/legacy_tool.py"
"$PY" -m venv "$APP/.venv" && "$APP/.venv/bin/pip" install -q -r requirements.txt || exit 1
cat >"$T/dmarc.ini" <<EOF
[uwsgi]
http-socket = 127.0.0.1:$PORT
lazy-apps = true
touch-reload = $APP/reload.trigger
touch-chain-reload = $APP/reload-chain.trigger
EOF
# fake uWSGI: (re)starts the app from $APP/.venv whenever a trigger changes
cat >"$T/fake-uwsgi.sh" <<'EOF'
#!/usr/bin/env bash
APP=$1; PORT=$2
start() { (cd "$APP" && exec "$APP/.venv/bin/python" -c \
  "from app import app; app.run(host='127.0.0.1', port=$PORT)") >>"$APP/logs/uwsgi.log" 2>&1 & PID=$!; }
sig() { stat -c %y "$APP/reload.trigger" "$APP/reload-chain.trigger" 2>/dev/null | tr '\n' ' '; }
trap 'kill $PID 2>/dev/null; exit 0' TERM
start; last=$(sig)
while true; do sleep 0.3; now=$(sig)
  if [ "$now" != "$last" ]; then last=$now; kill $PID; wait $PID 2>/dev/null; start; fi
done
EOF
chmod +x "$T/fake-uwsgi.sh"
"$T/fake-uwsgi.sh" "$APP" "$PORT" & UWSGI_PID=$!
for _ in $(seq 1 50); do [ "$(code)" != 000 ] && break; sleep 0.2; done
check "pre-CD app answers, /healthz is 404" '[ "$(code)" = 404 ]'

HOME="$H" INI="$T/dmarc.ini" bash deploy/bootstrap.sh \
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2eE2eE2eE2eE2eE2eE2eE2eE2eE2eE2eE2eE2eE2e e2e" >"$T/boot.log" 2>&1
check "bootstrap reports READY" 'grep -q "^READY" "$T/boot.log"'
grep -q '^PYTHON=' "$H/dmarc-deploy/deploy.env" || echo "PYTHON=$PY" >>"$H/dmarc-deploy/deploy.env"

deploy() {  # build the bundle exactly as .github/workflows/deploy.yml does, then deploy
    local sha b="$T/bundle"
    sha="$(git rev-parse HEAD)"
    rm -rf "$b" && mkdir "$b" && git archive --format=tar HEAD | tar -x -C "$b"
    echo "$sha" >"$b/REVISION"
    (cd "$b" && find . -type f ! -name MANIFEST | sed 's|^\./||' | sort >MANIFEST)
    tar -czf "$T/bundle.tar.gz" -C "$b" .
    HOME="$H" SSH_ORIGINAL_COMMAND="deploy $sha" HEALTH_TIMEOUT="${HT:-90}" "$R" \
        <"$T/bundle.tar.gz" >>"$T/deploy.log" 2>&1
}
rollback() { HOME="$H" SSH_ORIGINAL_COMMAND=rollback "$R" >>"$T/deploy.log" 2>&1; }
short() { git rev-parse --short=7 HEAD; }

say "A: first deploy over the hand-built server"
A=$(short); deploy; rc=$?
check "A deploys (rc=$rc), live = $A" '[ $rc -eq 0 ] && [ "$(rev)" = "$A" ]'
check "A: hand-built venv kept for rollback" '[ -d "$APP/.venvs/legacy-pre-cd" ] && [ -L "$APP/.venv" ]'

say "B: code-only release that drops a file"
G rm -q heartbeat.py && G commit -qm B; B=$(short); deploy; rc=$?
check "B deploys (rc=$rc), live = $B" '[ $rc -eq 0 ] && [ "$(rev)" = "$B" ]'
check "B: dropped file removed, foreign files kept" \
    '[ ! -e "$APP/heartbeat.py" ] && [ -e "$APP/notes-local.txt" ] && [ -e "$APP/legacy_tool.py" ]'

say "C: import error is stopped by the smoke test"
echo "import nonexistent_module_e2e" >>app.py && G commit -qam C; deploy; rc=$?
check "C refused (rc=$rc), live still $B" '[ $rc -ne 0 ] && [ "$(rev)" = "$B" ]'
G reset -q --hard HEAD~1

say "D: crash only on the live server -> automatic rollback"
"$PY" - <<'PY'
p = "app.py"; s = open(p).read()
s = s.replace("REVISION = _read_revision()",
              'REVISION = _read_revision()\nif os.path.exists("instance/config.py"):\n'
              '    raise RuntimeError("e2e: crash only in the live dir")', 1)
open(p, "w").write(s)
PY
G commit -qam D; HT=15 deploy; rc=$?
check "D failed (rc=$rc) and rolled back, live still $B" '[ $rc -ne 0 ] && [ "$(rev)" = "$B" ]'
check "D: no crash code left on disk" '! grep -q "e2e: crash" "$APP/app.py"'
G reset -q --hard HEAD~1

say "E: dependency change builds a new venv"
echo "six==1.17.0" >>requirements.txt && G commit -qam E; E=$(short)
# shellcheck disable=SC2034  # used inside the eval'd check strings below
venv_before="$(readlink "$APP/.venv")"; deploy; rc=$?
check "E deploys (rc=$rc), live = $E" '[ $rc -eq 0 ] && [ "$(rev)" = "$E" ]'
check "E: new venv" '[ "$(readlink "$APP/.venv")" != "$venv_before" ]'

say "manual rollbacks: E -> B -> A -> pre-CD -> nothing left"
rollback; check "rollback 1 -> B" '[ "$(rev)" = "$B" ] && [ "$(readlink "$APP/.venv")" = "$venv_before" ]'
rollback; check "rollback 2 -> A" '[ "$(rev)" = "$A" ]'
rollback; rc=$?
check "rollback 3 -> pre-CD (rc=$rc, /healthz 404, legacy venv)" \
    '[ $rc -eq 0 ] && [ "$(code)" = 404 ] && [ "$(readlink "$APP/.venv")" = ".venvs/legacy-pre-cd" ]'
check "pre-CD code restored" 'grep -q "pre-cd" "$APP/app.py" && [ -e "$APP/legacy_tool.py" ]'
rollback; rc=$?
check "rollback 4 refused (rc=$rc): nothing left" '[ $rc -ne 0 ]'

say "server-only state untouched"
check "secrets, archive/, failed/, foreign file intact" \
    '[ "$(cat "$APP/archive/r1.xml" "$APP/failed/f1.xml" "$APP/notes-local.txt")" = "$(printf "keep\nkeep\nmine")" ] && grep -q MAILGUN_API_KEY "$APP/instance/config.py"'

say "guard rails of the forced command"
for c in "bash -i" "deploy ../../etc" "deploy deadbeef; rm -rf ~" ""; do
    HOME="$H" SSH_ORIGINAL_COMMAND="$c" "$R" </dev/null >/dev/null 2>&1; rc=$?
    check "refuses '$c' (rc=$rc)" '[ $rc -ne 0 ]'
done

echo
if [ "$fails" -eq 0 ]; then echo "e2e deploy: all passed"; else
    echo "e2e deploy: $fails failed"; echo "--- deploy.log (tail)"; tail -40 "$T/deploy.log"; exit 1
fi
