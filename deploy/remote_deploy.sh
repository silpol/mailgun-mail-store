#!/usr/bin/env bash
# deploy/remote_deploy.sh — runs ON THE SERVER as the app user (doer).
#
# Invoked by deploy/receive.sh (the SSH forced command). Never edits the uWSGI
# .ini, never needs sudo, and never touches server-only state:
#   instance/ (secrets)  archive/  failed/  logs/  — not in the bundle, not deleted.
#
# Verbs:
#   deploy <stage_dir> <sha>   install the extracted bundle in <stage_dir>
#   rollback                   restore the previous release (code + venv)
#   status                     print deployed revision and live health
#
# Model (in place, because uWSGI's .ini hardcodes chdir and virtualenv):
#   * code:  bundle files copied over $APP; files that the PREVIOUS bundle
#            shipped but this one doesn't are removed (manifest diff) — nothing
#            else is ever deleted.
#   * venv:  $APP/.venvs/<hash of requirements.txt + python version>, and
#            $APP/.venv is a symlink to it. Unchanged requirements -> the venv
#            is reused; rollback just flips the symlink back.
#   * reload: unchanged venv -> touch-chain-reload (workers one at a time, no
#            dropped webhooks); changed venv -> touch-reload (graceful full
#            reload, so the master re-execs into the new interpreter env).
#   * gate:  /healthz must report the NEW sha, else automatic rollback.
set -Eeuo pipefail

DEPLOY_ROOT="${DEPLOY_ROOT:-$HOME/dmarc-deploy}"
# shellcheck source=/dev/null
[ -f "$DEPLOY_ROOT/deploy.env" ] && . "$DEPLOY_ROOT/deploy.env"

APP="${APP:-$HOME/dmarc-handler}"
INI="${INI:-/etc/uwsgi/apps-enabled/dmarc.ini}"
PYTHON="${PYTHON:-/usr/bin/python3}"
HEALTH_URL="${HEALTH_URL:-http://10.135.55.244:9096/healthz}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"
CHAIN_TRIGGER="${CHAIN_TRIGGER:-$APP/reload-chain.trigger}"
FULL_TRIGGER="${FULL_TRIGGER:-$APP/reload.trigger}"
KEEP="${KEEP:-5}"

STATE="$DEPLOY_ROOT/state"
BACKUPS="$DEPLOY_ROOT/backups"
TOOLING="$DEPLOY_ROOT/tooling"
LOG="$DEPLOY_ROOT/deploy.log"

# Never copied, never deleted: server-owned state.
PROTECTED_RE='^(instance|archive|failed|logs|\.venv|\.venvs)(/|$)'

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG" >&2; }
die() { log "ERROR: $*"; exit 1; }

mkdir -p "$STATE" "$BACKUPS" "$TOOLING" "$DEPLOY_ROOT/incoming" "$APP/.venvs"

pyver() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])'; }

current_revision() { cat "$APP/REVISION" 2>/dev/null || echo "pre-cd"; }

preflight() {
    [ -d "$APP" ] || die "app dir $APP missing"
    [ -f "$APP/instance/config.py" ] || die "$APP/instance/config.py missing (secrets) — refusing"
    [ -r "$INI" ] || die "cannot read $INI"
    grep -Eq "^[[:space:]]*touch-chain-reload[[:space:]]*=[[:space:]]*${CHAIN_TRIGGER}[[:space:]]*$" "$INI" ||
        die "$INI lacks 'touch-chain-reload = $CHAIN_TRIGGER' (see docs/Deployment.md)"
    grep -Eq "^[[:space:]]*touch-reload[[:space:]]*=[[:space:]]*${FULL_TRIGGER}[[:space:]]*$" "$INI" ||
        die "$INI lacks 'touch-reload = $FULL_TRIGGER' (see docs/Deployment.md)"
    if [ -x "$APP/.venv/bin/python" ]; then
        local live want
        live="$(pyver "$APP/.venv/bin/python")"
        want="$(pyver "$PYTHON")"
        [ "$live" = "$want" ] || die "live venv is Python $live but $PYTHON is $want; uWSGI's python plugin \
must match — fix PYTHON in $DEPLOY_ROOT/deploy.env"
    fi
}

# Build (or reuse) the venv for this requirements.txt; prints its path.
ensure_venv() {
    local stage="$1" key venv
    key="$( (cat "$stage/requirements.txt"; pyver "$PYTHON") | sha256sum | cut -c1-12)"
    venv="$APP/.venvs/$key"
    if [ -f "$venv/.complete" ]; then
        log "reusing venv .venvs/$key"
    else
        log "building venv .venvs/$key"
        rm -rf "$venv"
        "$PYTHON" -m venv "$venv"
        if ! { "$venv/bin/pip" install -q --upgrade pip &&
            "$venv/bin/pip" install -q -r "$stage/requirements.txt"; } >>"$LOG" 2>&1; then
            rm -rf "$venv"
            die "pip install failed (see $LOG)"
        fi
        touch "$venv/.complete"
    fi
    echo "$venv"
}

# Import the NEW code with the NEW venv, outside the live dir, before touching anything live.
smoke_test() {
    local stage="$1" venv="$2" sha="$3"
    (cd "$stage" && "$venv/bin/python" - "$sha" <<'PY'
import sys
import flask, parsedmarc, requests, sentry_sdk  # noqa: F401 — server deps present
import app
r = app.app.test_client().get("/healthz")
assert r.status_code == 200, r.status_code
assert r.get_json()["revision"] == sys.argv[1], r.get_json()
PY
    ) >>"$LOG" 2>&1 || die "smoke test failed for $sha (see $LOG)"
    log "smoke test ok"
}

# Snapshot the live code (+ which venv and manifest it used) before overwriting.
backup_current() {
    local id="$1" dir="$BACKUPS/$1" list
    mkdir -p "$dir"
    list="$dir/files"
    if [ -f "$STATE/current.manifest" ]; then
        cp "$STATE/current.manifest" "$dir/manifest"
        while IFS= read -r f; do [ -e "$APP/$f" ] && printf '%s\n' "$f"; done \
            <"$STATE/current.manifest" >"$list"
    else
        # First CD deploy: no manifest yet — snapshot every non-protected file.
        (cd "$APP" && find . -path ./instance -prune -o -path ./archive -prune -o \
            -path ./failed -prune -o -path ./logs -prune -o -path ./.venv -prune -o \
            -path ./.venvs -prune -o -name '__pycache__' -prune -o -type f -print |
            sed 's|^\./||' | grep -Ev "$PROTECTED_RE" | sort) >"$list"
        : >"$dir/manifest" # empty = "unknown previous file set"
    fi
    tar -czf "$dir/code.tar.gz" -C "$APP" -T "$list"
    current_revision >"$dir/revision"
    if [ -L "$APP/.venv" ]; then readlink "$APP/.venv" >"$dir/venv"; else echo ".venvs/legacy-pre-cd" >"$dir/venv"; fi
    log "backup $id of $(cat "$dir/revision") saved"
}

# Remove files the previous release shipped that the new one no longer does.
remove_stale() {
    local old="$1" new="$2" f
    [ -s "$old" ] || return 0
    comm -23 <(sort -u "$old") <(sort -u "$new") | while IFS= read -r f; do
        case "$f" in /* | *..*) continue ;; esac
        printf '%s\n' "$f" | grep -Eq "$PROTECTED_RE" && continue
        rm -f -- "$APP/$f" && log "removed stale $f"
    done
}

point_venv() {
    local target_rel="$1"
    if [ -d "$APP/.venv" ] && [ ! -L "$APP/.venv" ]; then
        # One-time migration of the hand-built venv; kept for rollback.
        mv "$APP/.venv" "$APP/.venvs/legacy-pre-cd"
        log "moved hand-built .venv to .venvs/legacy-pre-cd"
    fi
    ln -sfn "$target_rel" "$APP/.venv.tmp"
    mv -Tf "$APP/.venv.tmp" "$APP/.venv"
}

reload_uwsgi() {
    local how="$1"
    if [ "$how" = full ]; then touch "$FULL_TRIGGER"; else touch "$CHAIN_TRIGGER"; fi
    log "triggered $how reload"
}

# Wait until the expected code is really serving.
#   <sha>  -> /healthz must report exactly that revision
#   ""     -> pre-CD code, which has no /healthz: wait for its 404. This can't be
#             satisfied by the outgoing release still answering 200 mid-reload.
wait_healthy() {
    local want="$1" deadline=$((SECONDS + HEALTH_TIMEOUT)) body code
    while [ $SECONDS -lt $deadline ]; do
        if [ -n "$want" ]; then
            body="$(curl -fsS --max-time 5 "$HEALTH_URL" 2>/dev/null || true)"
            [[ "$body" == *"\"revision\":\"$want\""* ]] && return 0
        else
            code="$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' "$HEALTH_URL" 2>/dev/null || true)"
            [ "$code" = 404 ] && return 0
        fi
        sleep 3
    done
    return 1
}

restore_backup() {
    local id="$1" dir="$BACKUPS/$1" cur_manifest="$2" venv_rel how
    log "restoring backup $id ($(cat "$dir/revision"))"
    tar -xzf "$dir/code.tar.gz" -C "$APP" --no-same-owner
    # Drop files that only the failed/rolled-back release introduced.
    if [ -s "$dir/manifest" ]; then remove_stale "$cur_manifest" "$dir/manifest"; fi
    venv_rel="$(cat "$dir/venv")"
    how=chain
    [ "$(readlink "$APP/.venv")" != "$venv_rel" ] && how=full
    point_venv "$venv_rel"
    if [ -s "$dir/manifest" ]; then cp "$dir/manifest" "$STATE/current.manifest"; else rm -f "$STATE/current.manifest"; fi
    reload_uwsgi "$how"
    local rev
    rev="$(cat "$dir/revision")"
    [ "$rev" = pre-cd ] && rev=""
    wait_healthy "$rev" || die "service still unhealthy after restoring $id — investigate NOW (journalctl -u uwsgi-dmarc)"
    log "restored $id"
}

cleanup() {
    local keep_venvs
    # old staging dirs, backups beyond KEEP, tooling beyond KEEP
    find "$DEPLOY_ROOT/incoming" -mindepth 1 -maxdepth 1 -mmin +60 -exec rm -rf {} +
    ls -1dt "$BACKUPS"/*/ 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -rf
    ls -1dt "$TOOLING"/*/ 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -rf
    # venvs still referenced by the live symlink or any kept backup survive
    keep_venvs="$( { readlink "$APP/.venv"; cat "$BACKUPS"/*/venv 2>/dev/null; } | sed 's|^\.venvs/||' | sort -u)"
    for v in "$APP/.venvs"/*/; do
        v="$(basename "$v")"
        grep -qxF "$v" <<<"$keep_venvs" || { rm -rf "${APP:?}/.venvs/$v"; log "pruned venv $v"; }
    done
}

do_deploy() {
    local stage="$1" sha="$2" id venv how prev_venv
    log "=== deploy $sha (live: $(current_revision))"
    preflight
    venv="$(ensure_venv "$stage")"
    smoke_test "$stage" "$venv" "$sha"

    id="$(date -u +%Y%m%dT%H%M%SZ)-$(current_revision | cut -c1-12)"
    backup_current "$id"

    # ---- point of no return: from here, any failure rolls back ----
    # shellcheck disable=SC2064  # expand $id/$stage now, on purpose
    trap "trap - ERR; log 'deploy failed — rolling back'; restore_backup '$id' '$stage/MANIFEST'; rm -rf '$BACKUPS/$id'; exit 1" ERR

    (cd "$stage" && tar -cf - --exclude=./MANIFEST .) | tar -xf - -C "$APP" --no-same-owner
    remove_stale "$STATE/current.manifest" "$stage/MANIFEST"

    prev_venv="$(readlink "$APP/.venv" 2>/dev/null || echo legacy)"
    how=chain
    [ "$prev_venv" != ".venvs/$(basename "$venv")" ] && how=full
    point_venv ".venvs/$(basename "$venv")"
    reload_uwsgi "$how"

    if ! wait_healthy "$sha"; then
        trap - ERR
        log "health check did not report $sha within ${HEALTH_TIMEOUT}s"
        restore_backup "$id" "$stage/MANIFEST"
        rm -rf "${BACKUPS:?}/$id" # live == this backup again; keep the rollback stack honest
        exit 1
    fi
    trap - ERR

    cp "$stage/MANIFEST" "$STATE/current.manifest"
    rm -rf "${TOOLING:?}/$sha"
    cp -r "$stage/deploy" "$TOOLING/$sha"
    ln -sfn "$TOOLING/$sha" "$DEPLOY_ROOT/current-tooling"
    rm -rf "$stage"
    cleanup
    log "=== deployed $sha OK"
}

do_rollback() {
    local id
    id="$(ls -1t "$BACKUPS" 2>/dev/null | head -1)"
    [ -n "$id" ] || die "no backup to roll back to"
    restore_backup "$id" "$STATE/current.manifest"
    rm -rf "${BACKUPS:?}/$id" # consumed; a second rollback goes one further back
}

do_status() {
    echo "deployed revision: $(current_revision)"
    echo "venv: $(readlink "$APP/.venv" 2>/dev/null || echo 'not a symlink (pre-CD)')"
    echo "health: $(curl -fsS --max-time 5 "$HEALTH_URL" 2>&1 || true)"
    echo "backups: $(ls -1t "$BACKUPS" 2>/dev/null | tr '\n' ' ')"
}

case "${1:-}" in
deploy) do_deploy "${2:?stage dir}" "${3:?sha}" ;;
rollback) do_rollback ;;
status) do_status ;;
*) die "usage: remote_deploy.sh deploy <stage> <sha> | rollback | status" ;;
esac
