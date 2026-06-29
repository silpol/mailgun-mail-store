"""Shared fixtures and helpers for the test suite."""
import hashlib
import hmac as _hmac
import time

import pytest

from app import app as flask_app

TEST_API_KEY = "test-api-key-12345"
TEST_DOMAIN = "mg.example.com"
TEST_SENDER = "mailgun@mg.example.com"
TEST_RECIPIENT = "alerts@example.com"


def make_signature(api_key: str, timestamp: str, token: str) -> str:
    """Return a valid Mailgun webhook HMAC-SHA256 signature."""
    msg = (timestamp + token).encode("utf-8")
    return _hmac.new(api_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def make_valid_signature(timestamp: str, token: str, api_key: str = TEST_API_KEY) -> str:
    """Return a valid Mailgun HMAC-SHA256 signature (master-compatible helper)."""
    return make_signature(api_key, timestamp, token)


@pytest.fixture(autouse=True)
def app_config():
    """Configure the Flask app for testing.

    Sets required Mailgun config keys so functions that read app.config
    work without a real config.py.  Runs automatically for every test.
    """
    flask_app.config.update(
        {
            "TESTING": True,
            "MAILGUN_API_KEY": TEST_API_KEY,
            "MAILGUN_DOMAIN": TEST_DOMAIN,
            "MAILGUN_SENDER": TEST_SENDER,
            "MAILGUN_RECIPIENT": TEST_RECIPIENT,
        }
    )


@pytest.fixture()
def app(app_config):  # noqa: F811
    """Return the Flask app configured for testing (master-compatible fixture)."""
    return flask_app


@pytest.fixture
def client(tmp_path, monkeypatch, app_config):  # noqa: F811
    """Flask test client with CWD set to *tmp_path* so archive/failed dirs
    are created there and are cleaned up automatically after each test.
    """
    monkeypatch.chdir(tmp_path)
    return flask_app.test_client()


@pytest.fixture
def valid_auth():
    """Valid Mailgun webhook authentication fields for form data."""
    ts = str(int(time.time()))
    tok = "testtoken123abc"
    return {
        "timestamp": ts,
        "token": tok,
        "signature": make_signature(TEST_API_KEY, ts, tok),
    }
