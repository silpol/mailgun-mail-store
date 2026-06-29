# Plan: Continuous Deployment — GitHub → DigitalOcean droplet (uWSGI)

Status: DRAFT — to be executed later.
Owner: silpol
Target: `mailgun-mail-store` (Flask + uWSGI) on the existing Ubuntu 24.04 droplet.
Service: `uwsgi-dmarc.service` → uWSGI, 3 worker processes, gevent loop.
Config: `/etc/uwsgi/apps-enabled/dmarc.ini` (server-managed).
App dir: `/home/doer/dmarc-handler`  ·  runs as user/group `doer`.

---

## 0. Confirmed facts (from the live .ini) the plan is built on

- `base_dir = /home/doer/dmarc-handler`, `chdir = %(base_dir)`,
  `virtualenv = /home/doer/dmarc-handler/.venv`, `module = app:app`.
- `processes = 3`, `threads = 5`, `gevent = 1000`, `lazy-apps = true`,
  `master = true`, `die-on-term = true`.
- `http-socket = 10.135.55.244:9096` — a **private/VPC** address; TLS is
  terminated upstream (nginx/LB) and forwarded (logformat carries
  `HTTP_X_FORWARDED_FOR`). uWSGI is not public-facing.
- `env = TMA_CONFIG=production` → app loads secrets from `instance/config.py`.
- `logto = /home/doer/dmarc-handler/logs/dmarc.log`,
  `stats-server = /tmp/stats.socket`.
- Deploy decisions: **in-place** at the existing dir (hardcodes reviewed later);
  **touch-reload** for graceful worker cycling; secrets stay in
  `instance/config.py`.
- **No containers** — a single Flask webhook receiver under uWSGI is a native
  systemd workload; containerizing has no compelling justification here.

## 1. Goal

Push to `master` with green tests → the droplet runs that commit, workers cycle
without dropping a webhook, no manual SSH, and zero risk to data, secrets, or
the uWSGI config. One-step rollback.

## 2. CRITICAL prerequisites (do these before any CD, or the first deploy breaks)

1. **Put `gevent` in the lock.** The .ini's `gevent = 1000` runs from the app
   venv; if CD rebuilds the venv from `requirements.txt` and gevent isn't there,
   uWSGI won't start the workers on reload → outage. Add `gevent` to
   `requirements.in`, `pip-compile --no-strip-extras`, and verify:
   `.venv/bin/python -c "import gevent; print(gevent.__version__)"`.
2. **Repo↔runtime hygiene.** You unified on uWSGI but the repo still ships
   `gunicorn.conf.py` + pins `gunicorn`. Remove both from the repo and
   `requirements.in`; recompile. uWSGI stays an **apt** package + python3 plugin
   (system-level, not in the venv) — keep it that way.
3. **Add `touch-chain-reload`** to the .ini (one-time manual edit, since the
   .ini is server-managed): with `lazy-apps = true`, chain-reload cycles the 3
   workers **one at a time** (true zero-drop), unlike a plain reload that cycles
   all at once:
   `touch-chain-reload = /home/doer/dmarc-handler/reload.trigger`
   Then reload once manually so it takes effect. The deploy just `touch`es that
   file — no sudo, since `doer` owns it and uWSGI runs as `doer`.
4. **Add a `/healthz` route** to `app.py` (returns 200, no Mailgun/parse calls) —
   the deploy gate and the rollback trigger.

## 3. State that deploy must NEVER touch (server-only)

- `instance/config.py` — Mailgun keys (gitignored; selected by `TMA_CONFIG`).
- `archive/`, `failed/` — persisted DMARC reports + quarantine.
- `logs/` — uWSGI log target.
- `/etc/uwsgi/apps-enabled/dmarc.ini` — host-specific (VPC IP, paths).

Consequence for the script: use `git reset --hard <sha>` ONLY. **Never
`git clean`** — it would delete the untracked/ignored `archive/`, `failed/`,
`logs/`. Confirm `.gitignore` covers `instance/`, `archive/`, `failed/`, `logs/`,
`.venv/`, `reload.trigger`.

## 4. Deploy model — in-place, with a safe venv swap

The .ini hardcodes the dir and venv path, so we deploy in place at
`/home/doer/dmarc-handler`:

1. `git fetch` + `git reset --hard <sha>` (tracked files only).
2. Build the venv **aside** then rename it in — never mutate the live venv while
   workers are serving: build `.venv.new`, then `mv .venv .venv.old && mv .venv.new .venv`.
   Running workers hold their imports; new workers (after reload) pick up `.venv`.
3. `touch reload.trigger` → chain-reload cycles the 3 workers one by one.
4. Health-check the internal socket; on failure, roll back (reset to previous
   sha, restore `.venv.old`, touch again).
5. Keep `.venv.old` + record previous sha for rollback.

Note: in-place loses the instant atomic-flip of a releases/symlink model;
rollback is a git reset + venv restore + reload (seconds, not instant). That's
the accepted trade for keeping the unified layout. Revisit the symlink model
only if/when you review the .ini hardcodes.

## 5. Transport & auth  [the one remaining decision]

- (a) **Self-hosted runner** in your network/on the droplet → no inbound SSH;
  deploy is local. Best fit for your no-public-exposure posture. Guard: public
  repo, so run deploy only on `push` to `master` (never fork PRs) — see §10.
- (b) **GitHub-hosted runner + SSH over WireGuard** (NetBird/Headscale you run)
  → SSH never faces the internet.
- (c) **GitHub-hosted runner + public SSH** with a restricted, dedicated
  ed25519 deploy key + pinned host key + fail2ban. Simplest; weakest; OK for v1.

If SSH (b/c): secrets `DEPLOY_SSH_KEY`, `DEPLOY_HOST`, `DEPLOY_USER`,
`DEPLOY_KNOWN_HOSTS` (pin the host key; never `StrictHostKeyChecking=no`).
**No app secrets in GitHub** — `instance/config.py` is droplet-only. No sudo
rule needed: reload is a `touch`, not `systemctl`.

## 6. CI gate (add a real test workflow)

`.github/workflows/ci.yml`, on PRs and `master`:
- Python 3.12 (matches droplet / pip-compile context).
- `pip install -r requirements.txt` + dev tools (pytest, pytest-mock).
- `python -m pytest -q` (expect the full suite green).
- Lock-sync (catches the drift that started all this):
  `pip-compile --no-strip-extras --quiet --output-file=- requirements.in | diff - requirements.txt`
- Optional: a tiny "venv can actually serve" check —
  `python -c "import gevent, flask"` — so a missing server dep fails CI, not prod.
- Deploy `needs:` this job.

## 7. Deploy workflow (sketch — adapt host/paths, pin Action SHAs)

`.github/workflows/deploy.yml`:
```yaml
name: deploy
on:
  push: { branches: [master] }
  workflow_dispatch: {}
concurrency: { group: production-deploy, cancel-in-progress: false }
jobs:
  test:
    uses: ./.github/workflows/ci.yml
  deploy:
    needs: test
    runs-on: ubuntu-latest          # or [self-hosted, droplet]
    if: github.repository == 'silpol/mailgun-mail-store'
    steps:
      - name: SSH setup
        run: |
          install -m700 -d ~/.ssh
          echo "${{ secrets.DEPLOY_SSH_KEY }}"  > ~/.ssh/id_ed25519; chmod 600 ~/.ssh/id_ed25519
          echo "${{ secrets.DEPLOY_KNOWN_HOSTS }}" > ~/.ssh/known_hosts
      - name: Deploy
        run: |
          ssh -i ~/.ssh/id_ed25519 "${{ secrets.DEPLOY_USER }}@${{ secrets.DEPLOY_HOST }}" \
            "REF=${{ github.sha }} bash -s" < deploy/remote_deploy.sh
```

## 8. Remote deploy script (sketch — `deploy/remote_deploy.sh`, runs as `doer`)

```bash
#!/usr/bin/env bash
set -euo pipefail
APP=/home/doer/dmarc-handler
REF="${REF:?need REF}"
SOCK="10.135.55.244:9096"          # internal uWSGI http-socket from the .ini
cd "$APP"

PREV="$(git rev-parse HEAD)"       # for rollback

# 1. exact commit (tracked files only — NEVER git clean: would wipe archive/failed/logs)
git fetch --depth 50 origin master
git reset --hard "$REF"

# 2. build venv ASIDE from the pinned lock, then swap (don't mutate the live venv)
rm -rf .venv.new
python3 -m venv .venv.new
.venv.new/bin/pip install --upgrade pip >/dev/null
.venv.new/bin/pip install -r requirements.txt
.venv.new/bin/python -c "import gevent, flask"   # fail fast if server deps missing
rm -rf .venv.old; [ -d .venv ] && mv .venv .venv.old
mv .venv.new .venv

# 3. graceful chain-reload of the 3 workers (touch-chain-reload in the .ini)
touch "$APP/reload.trigger"
sleep 3

# 4. health check; roll back on failure
if ! curl -fsS --max-time 5 "http://$SOCK/healthz" >/dev/null; then
  echo "health check FAILED — rolling back to $PREV"
  git reset --hard "$PREV"
  rm -rf .venv; [ -d .venv.old ] && mv .venv.old .venv
  touch "$APP/reload.trigger"
  exit 1
fi
echo "deployed $REF"
```

## 9. uWSGI config handling

- Live `/etc/uwsgi/apps-enabled/dmarc.ini` stays **server-managed** (contains
  host-specific VPC IP + paths). Deploy never writes it.
- Version a **template** copy in the repo (`deploy/dmarc.ini.template`) as
  documentation-of-truth; add a CI step that diffs the committed template vs a
  sanitized live copy and *warns* (not fails) on drift — so config changes get
  noticed without the deploy stomping host values.
- One-time manual edits to the live .ini (Phase 1): add the
  `touch-chain-reload = /home/doer/dmarc-handler/reload.trigger` line, then
  `systemctl reload uwsgi-dmarc` once so it's active.

## 10. Security hardening checklist

- [ ] Deploy runs ONLY on `push` to `master` / `workflow_dispatch`; never on
      `pull_request` (public repo — fork PRs must not reach runner/secrets).
- [ ] `if: github.repository == 'silpol/mailgun-mail-store'` on the deploy job.
- [ ] Self-hosted runner (if used): ephemeral/single-job, isolated, no other
      workloads.
- [ ] Dedicated ed25519 deploy key; host key pinned; no password sudo needed.
- [ ] No app secret in GitHub; `instance/config.py` server-only.
- [ ] Pin all third-party Actions by commit SHA; branch protection on `master`
      requires CI green.

## 11. Observability / tie-in

- `/healthz` = deploy gate; also scrape it from your self-hosted
  Prometheus/Grafana/Alertmanager so a post-deploy regression pages you.
- uWSGI `stats-server = /tmp/stats.socket` → can feed `uwsgi_exporter` for
  worker/queue metrics if you want deploys correlated with load.
- `heartbeat.py` weekly digest stays independent — it verifies the DMARC
  pipeline regardless of deploys.

## 12. Phased rollout

1. **Prereqs (§2):** add gevent to the lock, remove gunicorn, recompile, test;
   add `/healthz`; add `touch-chain-reload` to the live .ini + reload once;
   create `reload.trigger` owned by `doer`; confirm `.gitignore` covers data/venv.
2. Add `ci.yml`; confirm green on a PR.
3. Add `deploy.yml` with `workflow_dispatch` only; run manually; verify chain
   reload + health check + rollback (deliberately break a release once to prove
   rollback).
4. Enable the `master` push trigger.
5. (Optional) self-hosted/WireGuard transport to drop public SSH.
6. (Later) review the .ini hardcodes → move to releases/+`current` symlink for
   instant atomic rollback, if desired.

## 13. Risks & rollback

- **Missing server dep in venv (gevent):** the #1 risk; mitigated by §2.1 + the
  `import gevent` fail-fast in the script (step 2) before any reload.
- **Mutating a live venv:** avoided by build-aside + rename swap.
- **Data/secret loss:** structural — `reset --hard` only touches tracked files;
  never `git clean`; data/config/logs are gitignored and untouched.
- **Bad release:** script auto-rolls-back (git reset to prev sha + restore
  `.venv.old` + reload).
- **Webhook loss during reload:** chain-reload cycles workers one at a time and
  Mailgun retries — effectively zero drop.
- **uWSGI won't reload:** if chain-reload misbehaves, fallback is
  `systemctl reload uwsgi-dmarc` (would need a narrow sudoers rule); prefer the
  touch path.

## 14. Acceptance criteria

- [ ] `gevent` in the lock; `gunicorn` removed from repo + lock.
- [ ] Push to `master` (green tests) → droplet runs that SHA (verify
      `git -C /home/doer/dmarc-handler rev-parse HEAD` + `/healthz`).
- [ ] `instance/config.py`, `archive/`, `failed/`, `logs/`, and the live .ini
      are byte-identical pre/post deploy.
- [ ] 3 uWSGI workers cycle on deploy with no dropped request (chain reload).
- [ ] A deliberately broken release auto-rolls-back and the service stays up.
- [ ] No app secret in GitHub; transport per chosen option in §5.