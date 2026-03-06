"""Unit tests for individual functions in app.py.

Each function is tested in isolation; external dependencies
(Mailgun API, parsedmarc, file I/O) are mocked.
"""
import datetime
import hashlib
import hmac as _hmac

import pytest

import app as app_module
from app import (
    _check_aggregate_report,
    _format_report_date,
    _notify_forensic_report,
    _safe_get,
    _send_notification_email,
    check_pass_fail_unknown,
    is_valid_request,
)
from tests.conftest import TEST_API_KEY, TEST_DOMAIN, TEST_RECIPIENT, TEST_SENDER


# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────


class _MockRequest:
    """Minimal stand-in for a Flask Request with a form dict."""

    def __init__(self, **form_fields):
        self.form = form_fields


def _make_signature(ts: str, tok: str) -> str:
    msg = (ts + tok).encode("utf-8")
    return _hmac.new(TEST_API_KEY.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _aggregate_report(
    domain="example.com",
    dkim="fail",
    spf="fail",
    source_ip="1.2.3.4",
    begin="2021-01-01T00:00:00Z",
    end="2021-01-02T00:00:00Z",
):
    """Minimal aggregate (RUA) report dict as returned by parsedmarc."""
    return {
        "policy_published": {"domain": domain},
        "report_metadata": {"begin_date": begin, "end_date": end},
        "records": [
            {
                "source": {"ip_address": source_ip},
                "policy_evaluated": {"dkim": dkim, "spf": spf},
            }
        ],
    }


def _forensic_report(
    domain="example.com",
    arrival_utc="2021-01-01 12:00:00",
    auth_failure=None,
    source_ip="1.2.3.4",
    delivery="delivered",
):
    """Minimal forensic (RUF) report dict as returned by parsedmarc."""
    return {
        "reported_domain": domain,
        "arrival_date_utc": arrival_utc,
        "auth_failure": auth_failure if auth_failure is not None else ["dkim"],
        "source": {"ip_address": source_ip},
        "delivery_result": delivery,
    }


# ────────────────────────────────────────────────────────────────
# _safe_get
# ────────────────────────────────────────────────────────────────


class TestSafeGet:
    def test_single_key_found(self):
        assert _safe_get({"a": 1}, "a") == 1

    def test_nested_keys_found(self):
        assert _safe_get({"a": {"b": 2}}, "a", "b") == 2

    def test_missing_key_returns_none(self):
        assert _safe_get({"a": 1}, "b") is None

    def test_missing_key_returns_custom_default(self):
        assert _safe_get({"a": 1}, "b", default="x") == "x"

    def test_intermediate_none_returns_default(self):
        assert _safe_get({"a": None}, "a", "b") is None

    def test_non_dict_intermediate_returns_default(self):
        assert _safe_get({"a": "string"}, "a", "b") is None

    def test_empty_dict_returns_default(self):
        assert _safe_get({}, "a") is None


# ────────────────────────────────────────────────────────────────
# _format_report_date
# ────────────────────────────────────────────────────────────────


class TestFormatReportDate:
    def test_none_returns_unknown(self):
        assert _format_report_date(None) == "unknown"

    def test_empty_string_returns_unknown(self):
        assert _format_report_date("") == "unknown"

    def test_epoch_zero_treated_as_falsy_returns_unknown(self):
        # 0 is falsy; the function treats it as "no value"
        assert _format_report_date(0) == "unknown"
        assert _format_report_date(0.0) == "unknown"

    def test_nonzero_epoch_int_returns_iso_z(self):
        result = _format_report_date(1609459200)  # 2021-01-01 00:00:00 UTC
        assert "2021" in result
        assert result.endswith("Z")

    def test_nonzero_epoch_float_returns_iso_z(self):
        result = _format_report_date(1609459200.0)
        assert "2021" in result
        assert result.endswith("Z")

    def test_aware_datetime_returns_utc_iso_z(self):
        dt = datetime.datetime(2021, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        assert _format_report_date(dt) == "2021-01-01T12:00:00Z"

    def test_naive_datetime_treated_as_utc(self):
        dt = datetime.datetime(2021, 1, 1, 12, 0, 0)
        assert _format_report_date(dt) == "2021-01-01T12:00:00Z"

    def test_string_passthrough(self):
        assert _format_report_date("2021-01-01T00:00:00Z") == "2021-01-01T00:00:00Z"

    def test_arbitrary_type_str_coercion(self):
        assert _format_report_date(42) == "1970-01-01T00:00:42Z"


# ────────────────────────────────────────────────────────────────
# is_valid_request
# ────────────────────────────────────────────────────────────────


class TestIsValidRequest:
    def test_valid_signature_returns_true(self):
        ts, tok = "1609459200", "sometoken"
        req = _MockRequest(timestamp=ts, token=tok, signature=_make_signature(ts, tok))
        assert is_valid_request(req) is True

    def test_missing_timestamp_returns_false(self):
        req = _MockRequest(token="tok", signature="sig")
        assert is_valid_request(req) is False

    def test_missing_token_returns_false(self):
        req = _MockRequest(timestamp="1234", signature="sig")
        assert is_valid_request(req) is False

    def test_missing_signature_returns_false(self):
        req = _MockRequest(timestamp="1234", token="tok")
        assert is_valid_request(req) is False

    def test_wrong_signature_returns_false(self):
        req = _MockRequest(timestamp="1234", token="tok", signature="wrong")
        assert is_valid_request(req) is False

    def test_tampered_timestamp_returns_false(self):
        ts, tok = "1609459200", "token"
        sig = _make_signature(ts, tok)
        req = _MockRequest(timestamp="9999999999", token=tok, signature=sig)
        assert is_valid_request(req) is False


# ────────────────────────────────────────────────────────────────
# check_pass_fail_unknown  (dispatcher)
# ────────────────────────────────────────────────────────────────


class TestCheckPassFailUnknown:
    def test_aggregate_dispatches_to_aggregate_handler(self, mocker):
        mock_agg = mocker.patch("app._check_aggregate_report")
        check_pass_fail_unknown({"report_type": "aggregate", "report": {}}, "f.xml", "subj")
        mock_agg.assert_called_once_with({}, "f.xml", "subj")

    def test_forensic_dispatches_to_forensic_handler(self, mocker):
        mock_forensic = mocker.patch("app._notify_forensic_report")
        check_pass_fail_unknown({"report_type": "forensic", "report": {}}, "f.eml", "subj")
        mock_forensic.assert_called_once_with({}, "f.eml", "subj")

    def test_missing_report_type_logs_warning_no_handlers_called(self, mocker):
        mock_agg = mocker.patch("app._check_aggregate_report")
        mock_forensic = mocker.patch("app._notify_forensic_report")
        mock_warn = mocker.patch("app.logger.warning")
        check_pass_fail_unknown({"report_type": None, "report": {}}, "f.xml", "subj")
        mock_warn.assert_called_once()
        mock_agg.assert_not_called()
        mock_forensic.assert_not_called()

    def test_unsupported_type_logs_debug_no_handlers_called(self, mocker):
        mock_agg = mocker.patch("app._check_aggregate_report")
        mock_forensic = mocker.patch("app._notify_forensic_report")
        mock_debug = mocker.patch("app.logger.debug")
        check_pass_fail_unknown({"report_type": "smtp_tls", "report": {}}, "f.xml", "subj")
        mock_debug.assert_called_once()
        mock_agg.assert_not_called()
        mock_forensic.assert_not_called()

    def test_none_report_value_coerced_to_empty_dict(self, mocker):
        """report=None must not cause AttributeError inside the handler."""
        mock_agg = mocker.patch("app._check_aggregate_report")
        check_pass_fail_unknown({"report_type": "aggregate", "report": None}, "f.xml", "s")
        mock_agg.assert_called_once_with({}, "f.xml", "s")


# ────────────────────────────────────────────────────────────────
# _check_aggregate_report
# ────────────────────────────────────────────────────────────────


class TestCheckAggregateReport:
    # ── no notification cases ──────────────────────────────────

    def test_all_pass_sends_no_notification(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(dkim="pass", spf="pass"), "f.xml", "s")
        mock_send.assert_not_called()

    def test_empty_records_sends_no_notification(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        report = {"policy_published": {"domain": "x.com"}, "report_metadata": {}, "records": []}
        _check_aggregate_report(report, "f.xml", "s")
        mock_send.assert_not_called()

    # ── notification cases ─────────────────────────────────────

    def test_dkim_fail_sends_notification(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(dkim="fail", spf="pass"), "f.xml", "s")
        mock_send.assert_called_once()

    def test_spf_fail_sends_notification(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(dkim="pass", spf="fail"), "f.xml", "s")
        mock_send.assert_called_once()

    def test_both_fail_sends_single_notification(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(dkim="fail", spf="fail"), "f.xml", "s")
        mock_send.assert_called_once()

    def test_mixed_records_notifies_for_failing_only(self, mocker):
        """Two records: one pass, one fail → notification includes only the failing one."""
        mock_send = mocker.patch("app._send_notification_email")
        report = {
            "policy_published": {"domain": "x.com"},
            "report_metadata": {"begin_date": "2021-01-01", "end_date": "2021-01-02"},
            "records": [
                {"source": {"ip_address": "1.1.1.1"}, "policy_evaluated": {"dkim": "pass", "spf": "pass"}},
                {"source": {"ip_address": "2.2.2.2"}, "policy_evaluated": {"dkim": "fail", "spf": "pass"}},
            ],
        }
        _check_aggregate_report(report, "f.xml", "s")
        body = mock_send.call_args[0][1]
        assert "1.1.1.1" not in body
        assert "2.2.2.2" in body

    # ── subject content ────────────────────────────────────────

    def test_subject_says_aggregate_dmarc_report(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(), "f.xml", "s")
        subject = mock_send.call_args[0][0]
        assert "aggregate DMARC report" in subject

    def test_subject_contains_domain(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(domain="mycompany.com"), "f.xml", "s")
        assert "mycompany.com" in mock_send.call_args[0][0]

    def test_subject_contains_begin_and_end(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(begin="2021-01-01T00:00:00Z", end="2021-01-02T00:00:00Z"), "f.xml", "s")
        subject = mock_send.call_args[0][0]
        assert "from" in subject
        assert "to" in subject

    # ── body content ───────────────────────────────────────────

    def test_body_contains_source_ip(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(source_ip="10.0.0.99"), "f.xml", "s")
        assert "10.0.0.99" in mock_send.call_args[0][1]

    def test_body_contains_dkim_and_spf_results(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(dkim="fail", spf="fail"), "f.xml", "s")
        body = mock_send.call_args[0][1]
        assert "DKIM: fail" in body
        assert "SPF: fail" in body

    def test_body_contains_received_subject(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(), "f.xml", "Original-Mail-Subject")
        assert "Original-Mail-Subject" in mock_send.call_args[0][1]

    def test_body_contains_file_path(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _check_aggregate_report(_aggregate_report(), "archive/report.xml", "s")
        assert "archive/report.xml" in mock_send.call_args[0][1]

    def test_source_ip_falls_back_to_row(self, mocker):
        """Records using the older row.source_ip path are handled."""
        mock_send = mocker.patch("app._send_notification_email")
        report = {
            "policy_published": {"domain": "x.com"},
            "report_metadata": {},
            "records": [
                {
                    "row": {"source_ip": "9.9.9.9"},
                    "policy_evaluated": {"dkim": "fail", "spf": "pass"},
                }
            ],
        }
        _check_aggregate_report(report, "f.xml", "s")
        assert "9.9.9.9" in mock_send.call_args[0][1]


# ────────────────────────────────────────────────────────────────
# _notify_forensic_report
# ────────────────────────────────────────────────────────────────


class TestNotifyForensicReport:
    def test_always_sends_notification(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(), "f.eml", "s")
        mock_send.assert_called_once()

    # ── subject content ────────────────────────────────────────

    def test_subject_says_forensic_dmarc_report(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(), "f.eml", "s")
        assert "forensic DMARC report" in mock_send.call_args[0][0]

    def test_subject_contains_domain(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(domain="victim.org"), "f.eml", "s")
        assert "victim.org" in mock_send.call_args[0][0]

    def test_subject_contains_arrival_date(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(arrival_utc="2021-06-15 09:30:00"), "f.eml", "s")
        assert "2021-06-15 09:30:00" in mock_send.call_args[0][0]

    def test_subject_falls_back_to_arrival_date_when_utc_missing(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        report = _forensic_report()
        report["arrival_date_utc"] = None
        report["arrival_date"] = "2021-01-01T12:00:00"
        _notify_forensic_report(report, "f.eml", "s")
        assert "2021-01-01T12:00:00" in mock_send.call_args[0][0]

    # ── body content ───────────────────────────────────────────

    def test_body_contains_auth_failures(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(auth_failure=["dkim", "spf"]), "f.eml", "s")
        body = mock_send.call_args[0][1]
        assert "dkim" in body
        assert "spf" in body

    def test_body_shows_unknown_for_empty_auth_failure(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(auth_failure=[]), "f.eml", "s")
        assert "unknown" in mock_send.call_args[0][1]

    def test_body_contains_source_ip(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(source_ip="5.6.7.8"), "f.eml", "s")
        assert "5.6.7.8" in mock_send.call_args[0][1]

    def test_body_contains_delivery_result(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(delivery="reject"), "f.eml", "s")
        assert "reject" in mock_send.call_args[0][1]

    def test_body_contains_received_subject(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(), "f.eml", "Forwarded Forensic Alert")
        assert "Forwarded Forensic Alert" in mock_send.call_args[0][1]

    def test_body_contains_file_path(self, mocker):
        mock_send = mocker.patch("app._send_notification_email")
        _notify_forensic_report(_forensic_report(), "archive/forensic.eml", "s")
        assert "archive/forensic.eml" in mock_send.call_args[0][1]


# ────────────────────────────────────────────────────────────────
# _send_notification_email
# ────────────────────────────────────────────────────────────────


class TestSendNotificationEmail:
    def test_sends_with_attachment_when_file_exists(self, mocker, tmp_path):
        f = tmp_path / "report.xml"
        f.write_bytes(b"<xml/>")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        _send_notification_email("Subject", "Body", str(f))

        assert mock_post.call_count == 1
        _, kwargs = mock_post.call_args
        assert kwargs.get("files") is not None

    def test_sends_without_attachment_when_file_missing(self, mocker):
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200
        mock_warn = mocker.patch("app.logger.warning")

        _send_notification_email("Subject", "Body", "/nonexistent/report.xml")

        assert mock_post.call_count == 1
        _, kwargs = mock_post.call_args
        assert "files" not in kwargs
        mock_warn.assert_called_once()

    def test_email_data_fields_populated_correctly(self, mocker, tmp_path):
        f = tmp_path / "report.xml"
        f.write_bytes(b"<xml/>")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        _send_notification_email("My Subject", "My Body", str(f))

        _, kwargs = mock_post.call_args
        assert kwargs["data"]["subject"] == "My Subject"
        assert kwargs["data"]["text"] == "My Body"
        assert kwargs["data"]["to"] == TEST_RECIPIENT
        assert kwargs["data"]["from"] == TEST_SENDER

    def test_mailgun_url_uses_configured_domain(self, mocker, tmp_path):
        f = tmp_path / "r.xml"
        f.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        _send_notification_email("s", "b", str(f))

        url = mock_post.call_args[0][0]
        assert TEST_DOMAIN in url

    def test_successful_send_logs_info(self, mocker, tmp_path):
        f = tmp_path / "r.xml"
        f.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200
        mock_info = mocker.patch("app.logger.info")

        _send_notification_email("s", "b", str(f))

        mock_info.assert_called()

    def test_failed_send_logs_error(self, mocker, tmp_path):
        f = tmp_path / "r.xml"
        f.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Internal Server Error"
        mock_error = mocker.patch("app.logger.error")

        _send_notification_email("s", "b", str(f))

        mock_error.assert_called_once()

    def test_uses_api_key_for_auth(self, mocker, tmp_path):
        f = tmp_path / "r.xml"
        f.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        _send_notification_email("s", "b", str(f))

        _, kwargs = mock_post.call_args
        assert kwargs["auth"] == ("api", TEST_API_KEY)

    def test_timeout_is_handled_gracefully(self, mocker, tmp_path):
        import requests as req_lib
        f = tmp_path / "r.xml"
        f.write_bytes(b"x")
        mocker.patch("app.requests.post", side_effect=req_lib.exceptions.Timeout)
        mock_error = mocker.patch("app.logger.error")

        # Must not raise; should log an error
        _send_notification_email("s", "b", str(f))

        mock_error.assert_called_once()

    def test_request_exception_is_handled_gracefully(self, mocker, tmp_path):
        import requests as req_lib
        f = tmp_path / "r.xml"
        f.write_bytes(b"x")
        mocker.patch("app.requests.post", side_effect=req_lib.exceptions.ConnectionError("refused"))
        mock_error = mocker.patch("app.logger.error")

        # Must not raise; should log an error
        _send_notification_email("s", "b", str(f))

        mock_error.assert_called_once()
