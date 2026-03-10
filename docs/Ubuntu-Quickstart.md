# Ubuntu Quickstart

This guide walks through setting up **mailgun-mail-store** from scratch on a
fresh Ubuntu 22.04 LTS (or 24.04 LTS) system — no Python, no git assumed.

---

## 1. Update the package index

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 2. Install system packages

```bash
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl
```

Verify the Python version is 3.10 or newer:

```bash
python3 --version
# Ubuntu 22.04 typically prints: Python 3.10.12
# Ubuntu 24.04 typically prints: Python 3.12.x
# Any version ≥ 3.10 is supported.
```

---

## 3. Clone the repository

```bash
git clone https://github.com/silpol/mailgun-mail-store.git
cd mailgun-mail-store
```

---

## 4. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Your shell prompt changes to `(.venv) …` confirming the environment is active.

---

## 5. Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs Flask, parsedmarc, gunicorn, requests, sentry-sdk and all
transitive dependencies (~80 packages).

---

## 6. Configure the application

Create the instance directory and configuration file (this directory is
git-ignored):

```bash
mkdir -p instance
cat > instance/config.py << 'EOF'
# Replace with your real Mailgun credentials
MAILGUN_API_KEY   = "key-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
MAILGUN_DOMAIN    = "mg.yourdomain.com"
MAILGUN_RECIPIENT = "alerts@yourdomain.com"

# Optional: override the sender address
# MAILGUN_SENDER = "dmarc-alerts@mg.yourdomain.com"

# Optional: GlitchTip / Sentry DSN for error tracking
# GLITCHTIP_DSN = "https://...@app.glitchtip.com/..."
EOF
```

See [Configuration](Configuration.md) for a full description of every variable.

---

## 7. Verify the installation

### Run the test suite

```bash
pip install ".[test]"
pytest
```

All tests should pass.  No real Mailgun credentials are needed — the tests
use mocks and a built-in test API key.

### Start the development server

```bash
python app.py
```

Open a second terminal and confirm the service responds:

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/
# expected: 404  (the root route intentionally returns 404)
```

---

## 8. Run in production with Gunicorn

```bash
gunicorn app:app --config gunicorn.conf.py
```

To bind to a port instead of a Unix socket, edit `gunicorn.conf.py` and
uncomment:

```python
bind = "localhost:8000"
```

### Run Gunicorn as a systemd service

Create a service unit file:

```bash
sudo nano /etc/systemd/system/mailgun-mail-store.service
```

```ini
[Unit]
Description=mailgun-mail-store WSGI service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/home/ubuntu/mailgun-mail-store
ExecStart=/home/ubuntu/mailgun-mail-store/.venv/bin/gunicorn \
    app:app --config gunicorn.conf.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mailgun-mail-store
sudo systemctl status mailgun-mail-store
```

---

## 9. Expose the service (optional)

To receive real Mailgun webhooks the endpoint must be reachable over HTTPS.
A common approach on Ubuntu is to put Gunicorn behind **nginx** with a
Let's Encrypt certificate:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo certbot --nginx -d mail-store.yourdomain.com
```

Then add an nginx location block that proxies to Gunicorn:

```nginx
location /mailfetch {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

Finally, configure your Mailgun inbound route or routing rule to POST to:

```
https://mail-store.yourdomain.com/mailfetch
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `ModuleNotFoundError: No module named 'flask'` | Virtual environment not active | `source .venv/bin/activate` |
| `401 Unauthorized` from `/mailfetch` | Wrong or missing `MAILGUN_API_KEY` | Check `instance/config.py` |
| `KeyError: 'MAILGUN_API_KEY'` on startup | `instance/config.py` not found | Create the file as shown in step 6 |
| Files appear in `failed/` | parsedmarc could not parse the report | Check the logs; the file may be malformed |
| Gunicorn exits immediately | Port already in use or permission error | Check `journalctl -u mailgun-mail-store` |
