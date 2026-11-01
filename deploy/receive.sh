#!/usr/bin/env bash
# deploy/receive.sh — SSH forced-command entrypoint for CI deploys.
#
# Installed ONCE on the server (by deploy/bootstrap.sh) as
#   ~/.local/bin/dmarc-deploy-receive
# and bound to the CI deploy key in ~/.ssh/authorized_keys:
#   command="/home/doer/.local/bin/dmarc-deploy-receive",restrict ssh-ed25519 AAAA... ci-deploy
#
# The key can therefore do NOTHING except the verbs below; the client's
# requested command arrives in $SSH_ORIGINAL_COMMAND and is strictly validated.
#
#   deploy <40-hex-sha>   read a .tar.gz bundle from stdin, then run the bundle's
#                         own deploy/remote_deploy.sh (so deploy logic is
#                         versioned with the app; this file stays tiny/stable)
#   rollback              restore the previous release
#   status                print the deployed revision and health
set -euo pipefail

DEPLOY_ROOT="${DEPLOY_ROOT:-$HOME/dmarc-deploy}"
MAX_BUNDLE_BYTES=$((20 * 1024 * 1024))

# shellcheck source=/dev/null
[ -f "$DEPLOY_ROOT/deploy.env" ] && . "$DEPLOY_ROOT/deploy.env"

read -r -a ARGS <<<"${SSH_ORIGINAL_COMMAND:-${*:-}}"
VERB="${ARGS[0]:-}"

exec 9>"$DEPLOY_ROOT/lock"
if ! flock -n 9; then
    echo "another deploy is running" >&2
    exit 75
fi

case "$VERB" in
deploy)
    SHA="${ARGS[1]:-}"
    if ! [[ "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
        echo "usage: deploy <40-hex-sha>" >&2
        exit 64
    fi
    STAGE="$DEPLOY_ROOT/incoming/$SHA"
    rm -rf "$STAGE"
    mkdir -p "$STAGE"
    # Bounded read: refuse oversized input instead of filling the disk.
    head -c "$((MAX_BUNDLE_BYTES + 1))" >"$STAGE.tar.gz"
    if [ "$(stat -c %s "$STAGE.tar.gz")" -gt "$MAX_BUNDLE_BYTES" ]; then
        rm -f "$STAGE.tar.gz"
        echo "bundle larger than $MAX_BUNDLE_BYTES bytes, refused" >&2
        exit 65
    fi
    # --no-same-owner/--no-overwrite-dir: plain files only, owned by us.
    tar -xzf "$STAGE.tar.gz" -C "$STAGE" --no-same-owner --no-overwrite-dir
    rm -f "$STAGE.tar.gz"
    if [ "$(cat "$STAGE/REVISION" 2>/dev/null)" != "$SHA" ]; then
        echo "bundle REVISION does not match requested sha" >&2
        exit 65
    fi
    exec bash "$STAGE/deploy/remote_deploy.sh" deploy "$STAGE" "$SHA"
    ;;
rollback | status)
    CURRENT="$(readlink -f "$DEPLOY_ROOT/current-tooling" 2>/dev/null || true)"
    if [ -z "$CURRENT" ] || [ ! -f "$CURRENT/remote_deploy.sh" ]; then
        echo "no deployed tooling yet; run a deploy first" >&2
        exit 69
    fi
    exec bash "$CURRENT/remote_deploy.sh" "$VERB"
    ;;
*)
    echo "allowed: deploy <sha> | rollback | status" >&2
    exit 64
    ;;
esac
