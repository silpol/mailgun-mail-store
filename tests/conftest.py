"""Shared pytest fixtures for mailgun-mail-store tests."""
import hmac
import os
from hashlib import sha256

import pytest

# ---------------------------------------------------------------------------
# Test-specific Mailgun credentials (never real values)
# ---------------------------------------------------------------------------
TEST_API_KEY = "test-mailgun-api-key"
TEST_DOMAIN = "test.mailgun.org"
TEST_RECIPIENT = "recipient@example.com"
TEST_SENDER = "sender@test.mailgun.org"


def make_valid_signature(timestamp: str, token: str, api_key: str = TEST_API_KEY) -> str:
    """Return a valid Mailgun HMAC-SHA256 signature for the given parameters."""
    return hmac.new(
        api_key.encode("utf-8"),
        (timestamp + token).encode("utf-8"),
        sha256,
    ).hexdigest()


@pytest.fixture()
def app():
    """Return the Flask app configured for testing."""
    from app import app as flask_app  # noqa: PLC0415

    flask_app.config.update(
        {
            "TESTING": True,
            "MAILGUN_API_KEY": TEST_API_KEY,
            "MAILGUN_DOMAIN": TEST_DOMAIN,
            "MAILGUN_RECIPIENT": TEST_RECIPIENT,
            "MAILGUN_SENDER": TEST_SENDER,
        }
    )
    return flask_app


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()
