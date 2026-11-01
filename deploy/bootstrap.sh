#!/usr/bin/env bash
# deploy/bootstrap.sh — ONE-TIME server setup for CI deploys. Run as the app
# user (doer) on the server; it never uses sudo and is safe to re-run.
#
#   scp deploy/receive.sh deploy/bootstrap.sh testing.tlm:/tmp/
#   ssh testing.tlm bash /tmp/bootstrap.sh "ssh-ed25519 AAAA... ci-deploy@mailgun-mail-store"
#
# It: installs the forced-command receiver, writes ~/dmarc-deploy/deploy.env
# (derived from the live uWSGI .ini), creates the reload trigger files, binds
# the CI public key to the receiver in authorized_keys, and tells you the
# two lines that must be added to the .ini by hand (that part needs sudo).
set -euo pipefail

PUBKEY="${1:-}"
APP="${APP:-$HOME/dmarc-handler}"
INI="${INI:-/etc/uwsgi/apps-enabled/dmarc.ini}"
DEPLOY_ROOT="$HOME/dmarc-deploy"
RECEIVER="$HOME/.local/bin/dmarc-deploy-receive"
HERE="$(cd "$(dirname "$0")" && pwd)"
CHAIN_TRIGGER="$APP/reload-chain.trigger"
FULL_TRIGGER="$APP/reload.trigger"
ok=1

say() { printf '  %s\n' "$*"; }
need() { command -v "$1" >/dev/null || { say "MISSING tool: $1"; ok=0; }; }

echo "== tools"
for t in curl flock tar sha256sum comm head stat find; do need "$t"; done

echo "== app dir"
[ -d "$APP" ] || { say "MISSING $APP"; exit 1; }
[ -f "$APP/instance/config.py" ] && say "instance/config.py present" || { say "MISSING $APP/instance/config.py"; ok=0; }
[ -r "$INI" ] || { say "cannot read $INI"; exit 1; }

echo "== receiver + state dirs"
mkdir -p "$DEPLOY_ROOT"/{incoming,state,backups,tooling} "$HOME/.local/bin"
install -m 0755 "$HERE/receive.sh" "$RECEIVER"
say "installed $RECEIVER"

echo "== deploy.env"
if [ -f "$DEPLOY_ROOT/deploy.env" ]; then
    say "keeping existing $DEPLOY_ROOT/deploy.env"
else
    sock="$(sed -nE 's/^[[:space:]]*http-socket[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/p' "$INI" | head -1)"
    [ -n "$sock" ] || { say "no http-socket in $INI — set HEALTH_URL in deploy.env by hand"; sock="127.0.0.1:9096"; ok=0; }
    py="$(readlink -f "$APP/.venv/bin/python" 2>/dev/null || true)"
    [ -x "$py" ] || py=/usr/bin/python3
    cat >"$DEPLOY_ROOT/deploy.env" <<EOF
# Read by receive.sh and remote_deploy.sh. Server-local; not in git.
APP=$APP
INI=$INI
# Must be the interpreter uWSGI's python plugin was built against (same as the live venv).
PYTHON=$py
HEALTH_URL=http://$sock/healthz
CHAIN_TRIGGER=$CHAIN_TRIGGER
FULL_TRIGGER=$FULL_TRIGGER
KEEP=5
EOF
    say "wrote $DEPLOY_ROOT/deploy.env (PYTHON=$py, HEALTH_URL=http://$sock/healthz)"
fi

echo "== reload triggers"
touch "$CHAIN_TRIGGER" "$FULL_TRIGGER"
say "touched $CHAIN_TRIGGER and $FULL_TRIGGER"

echo "== uWSGI .ini"
has() { grep -Eq "^[[:space:]]*$1[[:space:]]*=[[:space:]]*$2[[:space:]]*$" "$INI"; }
grep -Eq '^[[:space:]]*lazy-apps[[:space:]]*=[[:space:]]*(true|1|yes)' "$INI" ||
    { say "WARNING: lazy-apps is not true — touch-chain-reload needs it"; ok=0; }
if has touch-chain-reload "$CHAIN_TRIGGER" && has touch-reload "$FULL_TRIGGER"; then
    say "trigger lines present"
else
    ok=0
    cat <<EOF
  ACTION NEEDED (sudo, once). Add these lines to the [uwsgi] section of $INI:

      touch-reload = $FULL_TRIGGER
      touch-chain-reload = $CHAIN_TRIGGER

  then:   sudo systemctl restart uwsgi-dmarc.service
EOF
fi

echo "== authorized_keys"
if [ -n "$PUBKEY" ]; then
    [[ "$PUBKEY" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || { say "not an ssh-ed25519 public key"; exit 1; }
    install -d -m 0700 "$HOME/.ssh"
    touch "$HOME/.ssh/authorized_keys"
    chmod 0600 "$HOME/.ssh/authorized_keys"
    keybody="$(awk '{print $2}' <<<"$PUBKEY")"
    if grep -qF "$keybody" "$HOME/.ssh/authorized_keys"; then
        say "key already present (not modified — make sure it carries the command= restriction)"
    else
        printf 'command="%s",restrict %s\n' "$RECEIVER" "$PUBKEY" >>"$HOME/.ssh/authorized_keys"
        say "added CI key, restricted to $RECEIVER"
    fi
else
    say "no public key given — re-run with the CI deploy public key as argument"
    ok=0
fi

echo
if [ "$ok" = 1 ]; then echo "READY: the first CI deploy can run."; else echo "NOT READY: fix the items above and re-run."; fi
