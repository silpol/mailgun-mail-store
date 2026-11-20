# Testing

The project uses [pytest](https://docs.pytest.org/) with
[pytest-mock](https://pytest-mock.readthedocs.io/) and
[pytest-cov](https://pytest-cov.readthedocs.io/).

## Install test dependencies

```bash
pip install ".[test]"
# or
pip install pytest pytest-mock pytest-cov
```

## Run the full test suite

```bash
pytest
```

pytest discovers tests under the `tests/` directory automatically
(configured via `[tool.pytest.ini_options]` in `pyproject.toml`).

## Run with coverage

```bash
pytest --cov
```

Coverage is collected for the app and every operational module: `app.py`,
`dmarc_parser.py`, `heartbeat.py`, `outgoing_check.py`, `dmarc_fail_scan.py` and
`reprocess_failed.py` (see `[tool.coverage.run]` in `pyproject.toml`). CI prints
the same report. To also generate an HTML report:

```bash
pytest --cov --cov-report=html
# open htmlcov/index.html in a browser
```

## Run a specific file or test

```bash
# single file
pytest tests/test_validation.py

# single test class
pytest tests/test_routes.py::TestNobodyHome

# single test function
pytest tests/test_routes.py::TestNobodyHome::test_get_root_returns_404

# verbose output
pytest -v
```

## Test suite overview

| File | Lines | What it tests |
|------|-------|--------------|
| `tests/test_validation.py` | 122 | HMAC signature verification, replay-protection window, timing-attack resistance |
| `tests/test_routes.py` | 227 | Flask route handlers (`GET /`, `POST /mailfetch`) |
| `tests/test_integration.py` | 337 | Full request → parse → notify pipeline with a mocked parser |
| `tests/test_e2e.py` | 190 | **End to end:** the real app on a real HTTP server, real signed multipart POSTs with real `.zip`/`.gz`/RUF reports, a local stand-in for Mailgun; checks what is stored and what reaches Mailgun (alerts, no alert, quarantine, bad signatures, Mailgun outage) |
| `tests/test_outgoing_check.py` | 243 | Daily outgoing-delivery check against a fake Mailgun events API (empty, paging, permanent/temporary, API errors, redaction, alert) and the heartbeat's "Outgoing delivery" section |
| `tests/test_check_pass_fail.py` | 272 | `check_pass_fail_unknown` dispatcher; aggregate vs. forensic routing |
| `tests/test_unit.py` | 528 | Individual helper functions (`is_valid_request`, `_safe_get`, `_format_report_date`, `_send_notification_email`, …) |
| `tests/test_helpers.py` | 97 | `_safe_get` and `_format_report_date` edge cases |

## Shared fixtures (`tests/conftest.py`)

| Fixture | Scope | Description |
|---------|-------|-------------|
| `app_config` | function (autouse) | Injects test Mailgun config into the Flask app before every test |
| `app` | function | Returns the configured Flask app instance |
| `client` | function | Flask test client; sets CWD to `tmp_path` so `archive/`/`failed/` dirs are created there and cleaned up automatically |
| `valid_auth` | function | Pre-computed valid Mailgun webhook auth fields (`timestamp`, `token`, `signature`) |

### Test constants

```python
TEST_API_KEY   = "test-api-key-12345"
TEST_DOMAIN    = "mg.example.com"
TEST_SENDER    = "mailgun@mg.example.com"
TEST_RECIPIENT = "alerts@example.com"
```

### Signature helpers

```python
make_signature(api_key, timestamp, token)   # raw HMAC-SHA256 hex digest
make_valid_signature(timestamp, token)      # uses TEST_API_KEY by default
```

## Test levels

| Level | Where | What it proves |
|---|---|---|
| Unit | most `tests/test_*.py` | each function, including error and hostile-input cases |
| Integration | `test_integration.py`, `test_parser_contract.py` | the request → parse → notify pipeline; the real parser's output matches what `app.py` reads |
| Regression | named tests throughout | past incidents can't come back: the RUF `failure` rename, order-dependent file removal on the server, RFC 9990 namespaces, multi-member zips, a lost heartbeat digest |
| End to end, app | `tests/test_e2e.py` | the running service over real HTTP, as Mailgun calls it |
| End to end, deploy | `deploy/tests/e2e_deploy.sh` | the CD scripts against a simulated server: first deploy, auto-rollback, manual rollback to pre-CD, guard rails, data untouched |

## Deploy end-to-end rehearsal

```bash
bash deploy/tests/e2e_deploy.sh
```

It builds a simulated server in a temp directory: an app dir with secrets and
data, a hand-built venv, and a fake uWSGI that restarts the app when a reload
trigger is touched. It then drives `deploy/receive.sh` exactly as CI does over
SSH. It works on a copy of the committed tree, never on your checkout, and takes
about 1 minute, mostly pip. CI runs it as the `deploy-e2e` job.

By default it uses a reverse-ordering `sort`, to catch a return of the
order-dependent file removal that once broke a deploy on the server. Set
`E2E_REVERSE_SORT=0` to use the system `sort`, and `PYTHON=` to choose the
interpreter.

The unit tests for the deploy helpers are separate and fast:

```bash
bash deploy/tests/test_remote_deploy.sh
```

