# Configuration

Runtime configuration is read from `instance/config.py` using Flask's
[instance folder](https://flask.palletsprojects.com/en/stable/config/#instance-folders)
mechanism.

How a missing file is handled depends on where the app runs:

- **Production** (`TMA_CONFIG=production`, set by `env = TMA_CONFIG=production`
  in the server's uWSGI `dmarc.ini`): the app **refuses to load** if
  `instance/config.py` is missing or lacks any of `MAILGUN_API_KEY`,
  `MAILGUN_DOMAIN`, `MAILGUN_RECIPIENT`. The error names the missing keys.
  Workers then can't serve, `/healthz` fails, and a CD deploy rolls back.
  To make uWSGI itself exit instead of running without an app, add
  `need-app = true` to `dmarc.ini`.
- **Everywhere else** (tests, the deploy smoke test, helper scripts such as
  `reprocess_failed.py`): a missing file is silent and values default to `None`,
  as before.

## Create the file

```bash
mkdir -p instance
```

```python
# instance/config.py
MAILGUN_API_KEY = "key-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
MAILGUN_DOMAIN  = "mg.yourdomain.com"
MAILGUN_RECIPIENT = "alerts@yourdomain.com"

# Optional
# MAILGUN_SENDER  = "mailgun@mg.yourdomain.com"
# GLITCHTIP_DSN   = "https://...@app.glitchtip.com/..."
```

> `instance/` is listed in `.gitignore` — never commit secrets.

## Variables reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MAILGUN_API_KEY` | ✅ | — | Mailgun API key used for **both** webhook signature verification and sending notification emails. |
| `MAILGUN_DOMAIN` | ✅ | — | Your Mailgun sending domain (e.g. `mg.example.com`). Used to build the API endpoint URL and the default sender address. |
| `MAILGUN_RECIPIENT` | ✅ | — | Email address that receives DMARC failure notifications. |
| `MAILGUN_SENDER` | ❌ | `mailgun@{MAILGUN_DOMAIN}` | Sender address for outgoing notification emails. Defaults to `mailgun@` + the value of `MAILGUN_DOMAIN`. |
| `MAILGUN_API_BASE` | ❌ | `https://api.eu.mailgun.net/v3` | Mailgun API base URL. Set `https://api.mailgun.net/v3` for a US-region account. |
| `GLITCHTIP_DSN` | ❌ | — | Sentry / GlitchTip DSN for error tracking. When set, the app initialises `sentry_sdk` with Flask integration and a 10 % trace sample rate. |

## How the API key is used

### Webhook signature verification

Mailgun signs every webhook request with HMAC-SHA256 using your API key.
The service re-computes the digest and compares it with
`hmac.compare_digest` (timing-attack resistant).  Requests older than
300 seconds are rejected regardless of signature validity.

### Sending notification emails

Outgoing emails are posted to:

```
https://api.eu.mailgun.net/v3/{MAILGUN_DOMAIN}/messages
```

using HTTP Basic Auth (`api` / `MAILGUN_API_KEY`).

> **Note:** The base URL defaults to the **EU** Mailgun region. If your account
> uses the US region, set `MAILGUN_API_BASE = "https://api.mailgun.net/v3"` in
> `instance/config.py`. The end-to-end tests also use this setting, to point the
> app at a local stand-in for Mailgun.

## Mailgun webhook setup

Point your Mailgun routing rule (or inbound route) at:

```
https://<your-host>/mailfetch
```

The endpoint accepts only `POST` requests; all other methods return `404`.

## Mailgun event log (outgoing-delivery check)

`outgoing_check.py` (daily timer) and the heartbeat's "Outgoing delivery"
section use the same `MAILGUN_API_KEY` and `MAILGUN_DOMAIN` to read Mailgun's
**events** API (`GET /v3/{MAILGUN_DOMAIN}/events?event=failed`); no extra
setting is needed. The key must be allowed to read events, which a domain's
sending key may not be: an HTTP 401 shows up as "API key rejected".

How long Mailgun keeps events depends on the account's plan (a few days on the
smaller plans). That's why the check runs daily; see docs/Deployment.md.

