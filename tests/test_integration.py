"""Integration tests for the /mailfetch Flask endpoint.

These tests exercise the full request-handling pipeline — HMAC
authentication, file storage, report parsing (mocked), notification
dispatch, and error recovery — using Flask's built-in test client.
"""
import io
import time

import pytest

from tests.conftest import TEST_API_KEY, make_signature

# ── Constant auth params (reused across all tests) ────────────────────────

_TS = str(int(time.time()))
_TOK = "integrationtesttoken99"


def _auth_fields():
    """Return a fresh copy of valid Mailgun webhook auth fields."""
    return {
        "timestamp": _TS,
        "token": _TOK,
        "signature": make_signature(TEST_API_KEY, _TS, _TOK),
    }


# ── Canned report structures returned by the parsedmarc mock ─────────────


_AGGREGATE_WITH_FAILURES = {
    "report_type": "aggregate",
    "report": {
        "xml_schema": "draft",
        "policy_published": {"domain": "example.com"},
        "report_metadata": {
            "org_name": "TestOrg",
            "begin_date": "2021-01-01T00:00:00Z",
            "end_date": "2021-01-02T00:00:00Z",
        },
        "records": [
            {
                "source": {"ip_address": "192.168.1.1"},
                "policy_evaluated": {"dkim": "fail", "spf": "fail"},
            }
        ],
    },
}

_AGGREGATE_ALL_PASS = {
    "report_type": "aggregate",
    "report": {
        "policy_published": {"domain": "example.com"},
        "report_metadata": {
            "begin_date": "2021-01-01T00:00:00Z",
            "end_date": "2021-01-02T00:00:00Z",
        },
        "records": [
            {
                "source": {"ip_address": "192.168.1.1"},
                "policy_evaluated": {"dkim": "pass", "spf": "pass"},
            }
        ],
    },
}

_FORENSIC = {
    "report_type": "forensic",
    "report": {
        "reported_domain": "example.com",
        "arrival_date_utc": "2021-01-01 12:00:00",
        "auth_failure": ["dkim"],
        "source": {"ip_address": "10.0.0.1"},
        "delivery_result": "delivered",
    },
}


# ── /  endpoint ──────────────────────────────────────────────────────────


class TestNobodyHome:
    def test_root_returns_404(self, client):
        assert client.get("/").status_code == 404


# ── /mailfetch  endpoint ─────────────────────────────────────────────────


class TestReceivePostAuth:
    """Authentication and request validation."""

    def test_no_auth_fields_returns_401(self, client):
        resp = client.post("/mailfetch", data={}, content_type="multipart/form-data")
        assert resp.status_code == 401

    def test_invalid_signature_returns_401(self, client):
        data = {**_auth_fields(), "signature": "wrong", "attachment": (io.BytesIO(b"x"), "r.xml")}
        assert client.post("/mailfetch", data=data, content_type="multipart/form-data").status_code == 401

    def test_valid_auth_no_files_returns_400(self, client):
        resp = client.post("/mailfetch", data=_auth_fields(), content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_get_method_not_allowed(self, client):
        assert client.get("/mailfetch").status_code == 405


class TestReceivePostAggregateReport:
    """Aggregate (RUA) report processing."""

    def test_aggregate_with_failures_returns_200_and_notifies(self, client, mocker):
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_WITH_FAILURES)
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = {**_auth_fields(), "subject": "DMARC Report", "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        assert mock_post.call_count == 1
        subject = mock_post.call_args[1]["data"]["subject"]
        assert "aggregate DMARC report" in subject
        assert subject.endswith("example.com")

    def test_aggregate_all_pass_returns_200_no_notification(self, client, mocker):
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_ALL_PASS)
        mock_post = mocker.patch("app.requests.post")

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        mock_post.assert_not_called()

    def test_aggregate_email_body_contains_source_ip(self, client, mocker):
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_WITH_FAILURES)
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        client.post("/mailfetch", data=data, content_type="multipart/form-data")

        body = mock_post.call_args[1]["data"]["text"]
        assert "192.168.1.1" in body


class TestReceivePostForensicReport:
    """Forensic (RUF) report processing."""

    def test_forensic_report_returns_200_and_notifies(self, client, mocker):
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_FORENSIC)
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = {**_auth_fields(), "subject": "Forensic Alert", "attachment": (io.BytesIO(b"eml"), "report.eml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        assert mock_post.call_count == 1
        subject = mock_post.call_args[1]["data"]["subject"]
        assert "forensic DMARC report" in subject
        assert "example.com" in subject

    def test_forensic_email_body_contains_auth_failure(self, client, mocker):
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_FORENSIC)
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"eml"), "report.eml")}
        client.post("/mailfetch", data=data, content_type="multipart/form-data")

        body = mock_post.call_args[1]["data"]["text"]
        assert "dkim" in body


class TestReceivePostErrorHandling:
    """Error handling and file lifecycle."""

    def test_parse_error_returns_200_file_moved_to_failed(self, client, mocker, tmp_path):
        mocker.patch("app.parsedmarc.parse_report_file", side_effect=Exception("parse error"))

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"bad data"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        failed_dir = tmp_path / "failed"
        assert failed_dir.exists()
        assert len(list(failed_dir.iterdir())) == 1

    def test_successful_parse_archives_file(self, client, mocker, tmp_path):
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_ALL_PASS)

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        archive_dir = tmp_path / "archive"
        assert archive_dir.exists()
        assert len(list(archive_dir.iterdir())) == 1

    def test_multiple_files_all_processed(self, client, mocker):
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_ALL_PASS)

        data = {
            **_auth_fields(),
            "file1": (io.BytesIO(b"<xml1/>"), "report1.xml"),
            "file2": (io.BytesIO(b"<xml2/>"), "report2.xml"),
        }
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200

    def test_parse_error_does_not_prevent_other_files(self, client, mocker, tmp_path):
        """A parse failure on one file must not stop processing of subsequent files."""
        mock_parse = mocker.patch("app.parsedmarc.parse_report_file")
        mock_parse.side_effect = [Exception("bad"), _AGGREGATE_ALL_PASS]

        data = {
            **_auth_fields(),
            "bad_file": (io.BytesIO(b"garbage"), "bad.xml"),
            "good_file": (io.BytesIO(b"<xml/>"), "good.xml"),
        }
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        # The bad file should be in 'failed'
        failed_files = list((tmp_path / "failed").iterdir())
        assert len(failed_files) == 1
        # The good file should be in 'archive'
        archive_files = list((tmp_path / "archive").iterdir())
        assert len(archive_files) == 1

    def test_move_to_failed_dir_error_still_returns_200(self, client, mocker):
        """When shutil.move itself raises, the endpoint must log and still return 200."""
        mocker.patch("app.parsedmarc.parse_report_file", side_effect=Exception("parse error"))
        mocker.patch("app.shutil.move", side_effect=OSError("disk full"))
        mock_log = mocker.patch("app.logger.exception")

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"bad data"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        mock_log.assert_called_once()

    def test_mailgun_api_failure_still_returns_200(self, client, mocker):
        """A failure response from Mailgun must not crash the endpoint."""
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_WITH_FAILURES)
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Internal Server Error"

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200


class TestReceivePostMultiReport:
    """parsedmarc returning multiple reports for a single file."""

    def test_list_of_reports_all_processed(self, client, mocker):
        """parse_report_file returning a list → each report is dispatched."""
        mocker.patch(
            "app.parsedmarc.parse_report_file",
            return_value=[_AGGREGATE_WITH_FAILURES, _FORENSIC],
        )
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        # Both the aggregate failure AND the forensic report must each trigger a notification
        assert mock_post.call_count == 2

    def test_empty_parsedmarc_result_returns_200_no_notification(self, client, mocker):
        """parse_report_file returning None/empty → no notification, no crash."""
        mocker.patch("app.parsedmarc.parse_report_file", return_value=None)
        mock_post = mocker.patch("app.requests.post")

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        mock_post.assert_not_called()

    def test_list_with_empty_entry_skipped(self, client, mocker):
        """An empty dict/None inside the list is skipped without error."""
        mocker.patch(
            "app.parsedmarc.parse_report_file",
            return_value=[None, _AGGREGATE_WITH_FAILURES],
        )
        mock_post = mocker.patch("app.requests.post")
        mock_post.return_value.status_code = 200

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        # Only the valid aggregate report should trigger a notification
        assert mock_post.call_count == 1


class TestReceivePostNetworkErrors:
    """Mailgun network failures must not crash the endpoint or lose the archived file."""

    def test_mailgun_timeout_returns_200(self, client, mocker, tmp_path):
        """A requests.Timeout when contacting Mailgun must be handled gracefully."""
        import requests as req_lib
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_WITH_FAILURES)
        mocker.patch("app.requests.post", side_effect=req_lib.exceptions.Timeout)

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        # The report file must still be in the archive (timeout is not a parse error)
        archive_dir = tmp_path / "archive"
        assert archive_dir.exists(), "archive directory should have been created"
        assert len(list(archive_dir.iterdir())) == 1

    def test_mailgun_request_exception_returns_200(self, client, mocker, tmp_path):
        """A generic requests.RequestException is handled gracefully."""
        import requests as req_lib
        mocker.patch("app.parsedmarc.parse_report_file", return_value=_AGGREGATE_WITH_FAILURES)
        mocker.patch("app.requests.post", side_effect=req_lib.exceptions.ConnectionError("refused"))

        data = {**_auth_fields(), "attachment": (io.BytesIO(b"<xml/>"), "report.xml")}
        resp = client.post("/mailfetch", data=data, content_type="multipart/form-data")

        assert resp.status_code == 200
        archive_dir = tmp_path / "archive"
        assert archive_dir.exists(), "archive directory should have been created"
        assert len(list(archive_dir.iterdir())) == 1
