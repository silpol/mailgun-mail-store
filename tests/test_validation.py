"""Unit tests for the is_valid_request() signature-validation function."""
import hmac
import time
from hashlib import sha256

import pytest

from app import app as flask_app, is_valid_request
from tests.conftest import TEST_API_KEY, make_valid_signature


# Use a fresh timestamp so the replay-protection window check passes.
TIMESTAMP = str(int(time.time()))
TOKEN = "testtoken123"


def _post_context(data: dict):
    """Return a Flask test-request context for POST /mailfetch."""
    return flask_app.test_request_context(
        "/mailfetch",
        method="POST",
        data=data,
        content_type="multipart/form-data",
    )


class TestIsValidRequest:
    """Tests for request HMAC signature validation."""

    def test_valid_signature_accepted(self, app):
        sig = make_valid_signature(TIMESTAMP, TOKEN)
        with _post_context({"timestamp": TIMESTAMP, "token": TOKEN, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is True

    def test_wrong_signature_rejected(self, app):
        with _post_context(
            {"timestamp": TIMESTAMP, "token": TOKEN, "signature": "bad" + "0" * 60}
        ):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_missing_timestamp_rejected(self, app):
        sig = make_valid_signature(TIMESTAMP, TOKEN)
        with _post_context({"token": TOKEN, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_missing_token_rejected(self, app):
        sig = make_valid_signature(TIMESTAMP, TOKEN)
        with _post_context({"timestamp": TIMESTAMP, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_missing_signature_rejected(self, app):
        with _post_context({"timestamp": TIMESTAMP, "token": TOKEN}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_all_fields_missing_rejected(self, app):
        with _post_context({}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_empty_timestamp_rejected(self, app):
        sig = make_valid_signature("", TOKEN)
        with _post_context({"timestamp": "", "token": TOKEN, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_empty_token_rejected(self, app):
        sig = make_valid_signature(TIMESTAMP, "")
        with _post_context({"timestamp": TIMESTAMP, "token": "", "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_tampered_body_rejected(self, app):
        """Replacing the timestamp field after signing invalidates the HMAC."""
        sig = make_valid_signature(TIMESTAMP, TOKEN)
        # Use a timestamp that differs by 1 second — still fresh, but HMAC won't match.
        tampered_ts = str(int(TIMESTAMP) + 1)
        with _post_context(
            {"timestamp": tampered_ts, "token": TOKEN, "signature": sig}
        ):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False


class TestReplayProtection:
    """Tests for timestamp age / replay-protection validation."""

    def test_stale_timestamp_rejected(self, app):
        """A timestamp older than 5 minutes must be rejected."""
        stale_ts = str(int(time.time()) - 301)
        sig = make_valid_signature(stale_ts, TOKEN)
        with _post_context({"timestamp": stale_ts, "token": TOKEN, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_future_timestamp_rejected(self, app):
        """A timestamp more than 5 minutes in the future must be rejected."""
        future_ts = str(int(time.time()) + 301)
        sig = make_valid_signature(future_ts, TOKEN)
        with _post_context({"timestamp": future_ts, "token": TOKEN, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False

    def test_timestamp_within_window_accepted(self, app):
        """A timestamp that is 4 minutes old and has a valid signature must pass."""
        recent_ts = str(int(time.time()) - 240)
        sig = make_valid_signature(recent_ts, TOKEN)
        with _post_context({"timestamp": recent_ts, "token": TOKEN, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is True

    def test_non_numeric_timestamp_rejected(self, app):
        """A non-numeric timestamp string must be rejected."""
        bad_ts = "not-a-number"
        sig = make_valid_signature(bad_ts, TOKEN)
        with _post_context({"timestamp": bad_ts, "token": TOKEN, "signature": sig}):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False
