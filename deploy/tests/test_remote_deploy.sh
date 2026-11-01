#!/usr/bin/env bash
# deploy/tests/test_remote_deploy.sh — unit tests for remote_deploy.sh helpers.
# Run: bash deploy/tests/test_remote_deploy.sh   (CI runs it too)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fails=0
check() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails + 1)); fi; }

# Sandbox: functions only (sourcing skips the main dispatch).
export HOME="$T/home" DEPLOY_ROOT="$T/home/dmarc-deploy" APP="$T/home/dmarc-handler"
mkdir -p "$APP/instance" "$APP/archive"
# shellcheck source=../remote_deploy.sh
. "$HERE/../remote_deploy.sh"
set +e +E  # the sourced script enables errexit/ERR trap; the tests check results themselves

setup_files() { for f in "$@"; do mkdir -p "$APP/$(dirname "$f")"; echo x >"$APP/$f"; done; }

# --- remove_stale: removes exactly old-minus-new ---------------------------
setup_files a.py docs/x.md tests/test_a.py heartbeat.py
printf '%s\n' tests/test_a.py heartbeat.py a.py docs/x.md >"$T/old"   # deliberately unsorted
printf '%s\n' docs/x.md a.py tests/test_a.py >"$T/new"
remove_stale "$T/old" "$T/new"
check "stale file removed" '[ ! -e "$APP/heartbeat.py" ]'
check "kept files untouched" '[ -e "$APP/a.py" ] && [ -e "$APP/docs/x.md" ] && [ -e "$APP/tests/test_a.py" ]'

# --- regression: a coreutils whose sort order differs must not matter -------
# (the server's sort/comm disagreed on ordering and aborted a deploy + its rollback)
mkdir -p "$T/bin"
printf '#!/usr/bin/env bash\n/usr/bin/sort -r "$@"\n' >"$T/bin/sort"; chmod +x "$T/bin/sort"
setup_files gone.py
printf '%s\n' a.py gone.py docs/x.md >"$T/old"
PATH="$T/bin:$PATH" remove_stale "$T/old" "$T/new"; rc=$?
check "works with a non-standard sort order (rc=$rc)" '[ $rc -eq 0 ] && [ ! -e "$APP/gone.py" ]'

# --- protected paths and path tricks are never removed ---------------------
setup_files instance/config.py archive/r.xml
echo keep >"$T/outside"
printf '%s\n' instance/config.py archive/r.xml ../outside /etc/passwd >"$T/old"
remove_stale "$T/old" "$T/new"
check "protected and escaping paths kept" \
    '[ -e "$APP/instance/config.py" ] && [ -e "$APP/archive/r.xml" ] && [ -e "$T/outside" ]'

# --- degenerate inputs never fail the caller --------------------------------
: >"$T/empty"
remove_stale "$T/empty" "$T/new"; rc1=$?
setup_files survivor.py
printf 'survivor.py\n' >"$T/old"
remove_stale "$T/old" "$T/empty"; rc2=$?
check "empty manifests are no-ops (rc=$rc1/$rc2)" '[ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] && [ -e "$APP/survivor.py" ]'
remove_stale "$T/new" "$T/new"; rc=$?
check "nothing stale returns 0 (rc=$rc)" '[ $rc -eq 0 ]'

echo
[ "$fails" -eq 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
