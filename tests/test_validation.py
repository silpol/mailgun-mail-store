"""Unit tests for the is_valid_request() signature-validation function."""
import hmac
from hashlib import sha256

import pytest

from app import app as flask_app, is_valid_request
from tests.conftest import TEST_API_KEY, make_valid_signature


TIMESTAMP = "1609459200"
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
        """Changing the timestamp after signing should fail validation."""
        sig = make_valid_signature(TIMESTAMP, TOKEN)
        with _post_context(
            {"timestamp": "9999999999", "token": TOKEN, "signature": sig}
        ):
            from flask import request  # noqa: PLC0415
            assert is_valid_request(request) is False
