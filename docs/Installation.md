# Installation

## Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Python | 3.10 |
| pip | 21.3 (ships with Python 3.10) |

> For a complete walkthrough that starts from a bare Ubuntu machine see
> [Ubuntu Quickstart](Ubuntu-Quickstart.md).

## 1. Clone the repository

```bash
git clone https://github.com/silpol/mailgun-mail-store.git
cd mailgun-mail-store
```

## 2. Create and activate a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install runtime dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` contains pinned versions of all 80+ transitive dependencies
(Flask, parsedmarc, requests, sentry-sdk, gunicorn, …).

### Alternative: install from `pyproject.toml`

```bash
# runtime only
pip install .

# runtime + test/dev extras
pip install ".[test]"
# or
pip install ".[dev]"
```

## 4. Create the instance configuration

Flask reads runtime secrets from `instance/config.py` (this directory is
git-ignored).

```bash
mkdir -p instance
touch instance/config.py
```

Populate `instance/config.py` with the required variables described in
[Configuration](Configuration.md).

## 5. Start the service

### Development (Flask built-in server)

```bash
python app.py
```

The server starts on `http://127.0.0.1:5000` with debug mode enabled.

### Production (Gunicorn)

```bash
gunicorn app:app --config gunicorn.conf.py
```

By default Gunicorn spawns `CPU × 2 + 1` workers.  To bind to a specific
address, uncomment the `bind` line in `gunicorn.conf.py`:

```python
bind = "localhost:8000"
```
