# Deployment (CI/CD to the `testing` droplet)

Push or merge to `master` → GitHub Actions runs the tests → if green, the
commit is deployed to the DigitalOcean droplet `testing` (188.166.167.154) and
uWSGI reloads. A release that fails its checks is rolled back automatically.

```
push to master
  └─ ci.yml        pytest (Python 3.14 = server), lock-sync check, shellcheck
       └─ deploy.yml  bundle = tracked files + REVISION + MANIFEST
            └─ ssh doer@testing "deploy <sha>" < bundle.tar.gz
                 └─ receive.sh (SSH forced command — the key can do nothing else)
                      └─ remote_deploy.sh (from the bundle)
                           preflight → venv (reuse/build) → smoke test outside live dir
                           → backup → install → reload → /healthz must report <sha>
                           → else restore backup automatically
```

Pull requests and other branches get CI only (`ci.yml`). Forks can never
deploy: the deploy job is limited to this repository's `master` and the
`testing` environment's secrets.

## What a deploy never touches

`instance/` (secrets) · `archive/` · `failed/` · `logs/` · the uWSGI `.ini` ·
any file of yours in `~/dmarc-handler` that the repo never shipped. Only
files a previous bundle shipped can be removed (manifest diff).

## Server layout

| Path | What |
|---|---|
| `~/dmarc-handler/` | live app (uWSGI `chdir`), code replaced in place |
| `~/dmarc-handler/.venv` | symlink → `.venvs/<hash of requirements + python>` |
| `~/dmarc-handler/.venvs/legacy-pre-cd` | your hand-built venv, kept for rollback |
| `~/dmarc-handler/REVISION` | deployed commit; served by `/healthz` |
| `~/dmarc-handler/reload*.trigger` | touched to reload uWSGI (no sudo) |
| `~/dmarc-deploy/deploy.env` | server-local settings (python, health URL, …) |
| `~/dmarc-deploy/backups/` | last 5 pre-deploy snapshots (code + venv pointer) |
| `~/dmarc-deploy/deploy.log` | every deploy/rollback, with pip output |
| `~/.local/bin/dmarc-deploy-receive` | the forced-command entrypoint |

## One-time setup

Run steps 1–4 from your laptop, in a checkout of this repo at the branch that
contains `deploy/`.

### 1. Create the CI deploy key (laptop)

```bash
ssh-keygen -t ed25519 -N '' -C ci-deploy@mailgun-mail-store -f ~/.ssh/mailgun-store-ci
```

### 2. Bootstrap the server (runs as `doer`)

Your SSH login (`testing.tlm`) is your own user, not `doer`, so the script is
run through `sudo -u doer -H`. Everything it sets up (receiver, `~/dmarc-deploy`,
the CI key in `authorized_keys`) must belong to `doer`.

```bash
scp deploy/receive.sh deploy/bootstrap.sh testing.tlm:/tmp/
```
```bash
ssh testing.tlm "sudo -u doer -H bash /tmp/bootstrap.sh '$(cat ~/.ssh/mailgun-store-ci.pub)'"
```

CI logs in directly as `doer@188.166.167.154` with that key, so sshd must
allow it. `sudo sshd -T | grep -iE '^(allowusers|allowgroups|pubkeyauthentication)'`
must not exclude `doer`.

It ends with `READY` or with the list of what's missing. It is safe to re-run.
Check the `PYTHON=` it detected in `~/dmarc-deploy/deploy.env`: it must be the
interpreter uWSGI's python plugin uses (the one your current venv was made with).

### 3. Add the reload triggers to uWSGI (sudo, once)

Add to the `[uwsgi]` section of `/etc/uwsgi/apps-enabled/dmarc.ini`:

```ini
touch-reload = /home/doer/dmarc-handler/reload.trigger
touch-chain-reload = /home/doer/dmarc-handler/reload-chain.trigger
```

`lazy-apps = true` must also be set (chain reload needs it). Then:

```bash
sudo systemctl restart uwsgi-dmarc.service
```

The trigger files must exist before the restart (bootstrap creates them; or
`sudo -u doer touch /home/doer/dmarc-handler/reload.trigger /home/doer/dmarc-handler/reload-chain.trigger`).
Re-run step 2's second command. It should print `READY`.

### 4. Get the server's host key (laptop)

```bash
ssh-keyscan -t ed25519 188.166.167.154 2>/dev/null
```

Check that it is genuine by comparing fingerprints:

```bash
ssh-keyscan -t ed25519 188.166.167.154 2>/dev/null | ssh-keygen -lf -
```
```bash
ssh testing.tlm ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

### 5. Configure GitHub (Settings → Environments → New environment `testing`)

- **Deployment branches and tags:** "Selected branches" → `master`.
- **Environment secrets:**
  - `DEPLOY_SSH_KEY`: contents of `~/.ssh/mailgun-store-ci` (the private key).
  - `DEPLOY_KNOWN_HOSTS`: the line printed by step 4's first command.
- **Environment variables:**
  - `DEPLOY_HOST` = `188.166.167.154`
  - `DEPLOY_USER` = `doer`

Then in Settings → Branches, add a protection rule for `master` that requires
the `ci / test` check, so nothing untested can reach `master`.

No app secret goes to GitHub: Mailgun keys stay in `instance/config.py` on the server.

### 6. First deploy

Merge to `master`, or run Actions → deploy → "Run workflow". Watch the job log.
The first deploy also moves your hand-built `.venv` to `.venvs/legacy-pre-cd`
(kept for rollback) and does a full graceful reload.

## Day-to-day

Deploys are automatic. To check or roll back, from your laptop:

```bash
ssh -i ~/.ssh/mailgun-store-ci doer@188.166.167.154 status
```
```bash
ssh -i ~/.ssh/mailgun-store-ci doer@188.166.167.154 rollback
```

Or on the server: `sudo -u doer -H /home/doer/.local/bin/dmarc-deploy-receive status`.
Each `rollback` goes one release further back, down to the pre-CD state.
A rollback is not permanent: the next push to `master` deploys again, so fix
or revert the commit on `master` too.

Logs: `~/dmarc-deploy/deploy.log` (deploy steps), `~/dmarc-handler/logs/dmarc.log` (app).

## Weekly heartbeat

`heartbeat.py` emails a digest to `MAILGUN_RECIPIENT` every **Tuesday 09:00
Helsinki time**, before the Tuesday 14:00 EET weekly meeting. The digest
covers the trailing 7 days:
- reports archived;
- DKIM/SPF failures (alerts that should have fired);
- files quarantined in `failed/`.

**If the digest stops arriving, something is broken**: inbound mail, the
timer, or outbound mail. That's the point: it's a dead-man's switch.

It runs from a systemd timer, versioned in `deploy/systemd/`:
- `Persistent=true` catches up a run missed while the droplet was down;
- logs go to journald;
- a non-zero exit marks the unit failed: 2 = quarantine not empty,
  3 = no reports in the window, 4 = the digest email was not delivered.

CD ships the unit files with the app and updates `heartbeat.py` itself. The
units are installed **once** with sudo, and again only if a unit file changes:

```bash
sudo install -m 0644 /home/doer/dmarc-handler/deploy/systemd/dmarc-heartbeat.service /home/doer/dmarc-handler/deploy/systemd/dmarc-heartbeat.timer /etc/systemd/system/
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now dmarc-heartbeat.timer
```

Check it:

```bash
systemctl list-timers dmarc-heartbeat.timer
```
```bash
sudo systemctl start dmarc-heartbeat.service; journalctl -u dmarc-heartbeat -n 40 --no-pager
```

The second command sends a digest right away. `start` reports an error when
the run exits 2, 3 or 4; that's the signal working, so read the journal.

## Daily outgoing-delivery check

The app only sees **incoming** DMARC reports. If a recipient's mail server
rejects an alert or the heartbeat itself (for example Outlook.com's
`550 5.7.1 ... (AS9031519)` for domains without DMARC records), that shows up
only in Mailgun's event log. `outgoing_check.py` reads that log **daily**:
- it looks back about a day, catching up after missed runs but never more
  than 3 days back;
- it records each failed event once, under `/var/lib/dmarc-outgoing/`;
- it emails an alert on **new permanent** failures.

The weekly heartbeat then shows the week in its "Outgoing delivery" section.

Why daily: Mailgun keeps events only for a few days on this plan. On 20 Nov
2026 the 10 Nov heartbeat delivery was already gone from the log, so a weekly
look-back would silently miss part of every week. The heartbeat prints how far
back Mailgun's log reaches, so a short retention is always visible.

Privacy: only recipient **domains** are stored and shown. Addresses inside bounce
messages are replaced with `<redacted>@domain`, and the API key never appears
in output or in the state files.

Exit codes: `0` ok, `2` new permanent failure(s), `4` the alert email was not
delivered, `5` the Mailgun API could not be queried. The heartbeat exits `5` when
the week has permanent failures, or when the daily check is failing or hasn't
run for 36 hours.

Install once with sudo, after the deploy that ships the units:

```bash
sudo install -m 0644 /home/doer/dmarc-handler/deploy/systemd/dmarc-outgoing.service /home/doer/dmarc-handler/deploy/systemd/dmarc-outgoing.timer /etc/systemd/system/
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now dmarc-outgoing.timer
```

Check it:

```bash
sudo systemctl start dmarc-outgoing.service; journalctl -u dmarc-outgoing -n 20 --no-pager
```
```bash
systemctl list-timers dmarc-outgoing.timer
```

systemd creates `/var/lib/dmarc-outgoing` (owned by `doer`) on the first run.

## Changing dependencies

Edit `requirements.in`, then re-lock **on Python 3.14** (same as the server):

```bash
pip-compile --no-strip-extras requirements.in -o requirements.txt
```

CI fails if the two files are out of sync. A changed `requirements.txt` makes
the deploy build a new venv and do a full (graceful) uWSGI reload instead of a
chain reload. Unchanged requirements reuse the existing venv.
