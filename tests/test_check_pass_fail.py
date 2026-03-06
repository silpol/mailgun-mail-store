"""Unit tests for the check_pass_fail_unknown() DMARC-notification function."""
import os

import pytest

from app import check_pass_fail_unknown


# ---------------------------------------------------------------------------
# Helpers – minimal DMARC report data structures
# ---------------------------------------------------------------------------

def _make_report(records, domain="example.com", begin=1609459200, end=1609545600):
    """Return a minimal parsedmarc-style aggregated report dict."""
    return {
        "report": {
            "policy_published": {"domain": domain},
            "report_metadata": {
                "begin_date": begin,
                "end_date": end,
            },
            "records": records,
        }
    }


def _pass_record(ip="1.2.3.4"):
    return {
        "policy_evaluated": {"dkim": "pass", "spf": "pass"},
        "source": {"ip_address": ip},
    }


def _fail_record(ip="5.6.7.8", dkim="fail", spf="fail"):
    return {
        "policy_evaluated": {"dkim": dkim, "spf": spf},
        "source": {"ip_address": ip},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCheckPassFailUnknown:
    """Tests for check_pass_fail_unknown()."""

    # ---- no-email cases ------------------------------------------------

    def test_all_pass_no_email_sent(self, app, mocker):
        mock_post = mocker.patch("app.requests.post")
        data = _make_report([_pass_record(), _pass_record("2.2.2.2")])
        check_pass_fail_unknown(data, "/tmp/report.xml.gz", "test subject")
        mock_post.assert_not_called()

    def test_empty_records_no_email_sent(self, app, mocker):
        mock_post = mocker.patch("app.requests.post")
        check_pass_fail_unknown(_make_report([]), "/tmp/report.xml.gz", None)
        mock_post.assert_not_called()

    def test_missing_report_key_no_email_sent(self, app, mocker):
        mock_post = mocker.patch("app.requests.post")
        check_pass_fail_unknown({}, "/tmp/report.xml.gz", None)
        mock_post.assert_not_called()

    # ---- email-is-sent cases -------------------------------------------

    def test_dkim_fail_sends_email(self, app, mocker, tmp_path):
        report_file = tmp_path / "report.xml.gz"
        report_file.write_bytes(b"fake content")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record(dkim="fail", spf="pass")])
        check_pass_fail_unknown(data, str(report_file), "original subject")
        mock_post.assert_called_once()

    def test_spf_fail_sends_email(self, app, mocker, tmp_path):
        report_file = tmp_path / "report.xml.gz"
        report_file.write_bytes(b"fake content")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record(dkim="pass", spf="fail")])
        check_pass_fail_unknown(data, str(report_file), "original subject")
        mock_post.assert_called_once()

    def test_mixed_pass_and_fail_sends_email(self, app, mocker, tmp_path):
        report_file = tmp_path / "report.xml.gz"
        report_file.write_bytes(b"fake content")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_pass_record(), _fail_record()])
        check_pass_fail_unknown(data, str(report_file), "subj")
        mock_post.assert_called_once()

    # ---- email content checks -----------------------------------------

    def test_email_subject_contains_domain(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record()], domain="acme.org")
        check_pass_fail_unknown(data, str(report_file), "subj")

        call_data = mock_post.call_args.kwargs["data"]
        assert call_data["subject"].startswith(
            "detected FAIL in aggregated report for acme.org"
        )

    def test_email_subject_contains_fail_keyword(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record()])
        check_pass_fail_unknown(data, str(report_file), "subj")

        call_data = mock_post.call_args.kwargs["data"]
        assert "FAIL" in call_data["subject"]

    def test_email_body_contains_source_ip(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record(ip="9.9.9.9")])
        check_pass_fail_unknown(data, str(report_file), "subj")

        call_data = mock_post.call_args.kwargs["data"]
        assert "9.9.9.9" in call_data["text"]

    def test_email_body_contains_received_subject(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record()])
        check_pass_fail_unknown(data, str(report_file), "my-original-subject")

        call_data = mock_post.call_args.kwargs["data"]
        assert "my-original-subject" in call_data["text"]

    def test_email_uses_correct_mailgun_url(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record()])
        check_pass_fail_unknown(data, str(report_file), None)

        called_url = mock_post.call_args.args[0]
        from tests.conftest import TEST_DOMAIN  # noqa: PLC0415
        expected_url = f"https://api.eu.mailgun.net/v3/{TEST_DOMAIN}/messages"
        assert called_url == expected_url

    def test_email_sent_to_configured_recipient(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record()])
        check_pass_fail_unknown(data, str(report_file), None)

        call_data = mock_post.call_args.kwargs["data"]
        assert call_data["to"] == "recipient@example.com"

    # ---- alternate IP field (row.source_ip) ---------------------------

    def test_fallback_source_ip_from_row(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        # Use the row.source_ip path instead of source.ip_address
        record = {
            "policy_evaluated": {"dkim": "fail", "spf": "fail"},
            "row": {"source_ip": "10.0.0.1"},
        }
        data = _make_report([record])
        check_pass_fail_unknown(data, str(report_file), None)

        call_data = mock_post.call_args.kwargs["data"]
        assert "10.0.0.1" in call_data["text"]

    # ---- error handling -----------------------------------------------

    def test_missing_attachment_sends_email_without_file(self, app, mocker):
        """Email is sent even when the report file has been deleted."""
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = _make_report([_fail_record()])
        # Use a non-existent path to trigger FileNotFoundError
        check_pass_fail_unknown(data, "/nonexistent/path/report.gz", "subj")
        mock_post.assert_called_once()

    def test_mailgun_timeout_is_handled_gracefully(self, app, mocker, tmp_path):
        import requests as req_module

        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch(
            "app.requests.post", side_effect=req_module.exceptions.Timeout
        )

        data = _make_report([_fail_record()])
        # Should not raise; just log the error
        check_pass_fail_unknown(data, str(report_file), None)

    def test_mailgun_request_exception_is_handled_gracefully(
        self, app, mocker, tmp_path
    ):
        import requests as req_module

        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch(
            "app.requests.post",
            side_effect=req_module.exceptions.RequestException("connection error"),
        )

        data = _make_report([_fail_record()])
        check_pass_fail_unknown(data, str(report_file), None)

    def test_failed_http_response_logged_not_raised(self, app, mocker, tmp_path):
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Internal Server Error"

        data = _make_report([_fail_record()])
        # Should complete without raising
        check_pass_fail_unknown(data, str(report_file), None)
        mock_post.assert_called_once()

    # ---- date_range fallback -----------------------------------------

    def test_date_range_fallback_used_when_no_top_level_dates(
        self, app, mocker, tmp_path
    ):
        """report_metadata uses date_range.begin / date_range.end paths."""
        report_file = tmp_path / "r.gz"
        report_file.write_bytes(b"x")
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = {
            "report": {
                "policy_published": {"domain": "fallback.org"},
                "report_metadata": {
                    "date_range": {"begin": 1609459200, "end": 1609545600}
                },
                "records": [_fail_record()],
            }
        }
        check_pass_fail_unknown(data, str(report_file), None)
        call_data = mock_post.call_args.kwargs["data"]
        assert "2021-01-01T00:00:00Z" in call_data["subject"]
