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
pytest --cov=app
```

Coverage is collected for `app.py` only (see `[tool.coverage.run]` in
`pyproject.toml`).  To also generate an HTML report:

```bash
pytest --cov=app --cov-report=html
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
| `tests/test_integration.py` | 337 | Full request → parse → notify pipeline with mocked parsedmarc |
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
