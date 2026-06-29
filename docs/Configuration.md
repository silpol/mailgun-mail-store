# Configuration

Runtime configuration is read from `instance/config.py` using Flask's
[instance folder](https://flask.palletsprojects.com/en/stable/config/#instance-folders)
mechanism.  The file is loaded with `silent=True`, so a missing file only
means that all values default to `None`.

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

> **Note:** The hardcoded base URL targets the **EU** Mailgun region.
> If your account uses the US region, edit `_send_notification_email` in
> `app.py` to use `https://api.mailgun.net/v3/…`.

## Mailgun webhook setup

Point your Mailgun routing rule (or inbound route) at:

```
https://<your-host>/mailfetch
```

The endpoint accepts only `POST` requests; all other methods return `404`.
