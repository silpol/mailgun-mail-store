"""Integration tests for the Flask routes (/ and /mailfetch)."""
import io
import os
import time

import pytest

from tests.conftest import make_valid_signature

# Use a fresh timestamp so the replay-protection window check passes.
TIMESTAMP = str(int(time.time()))
TOKEN = "routetesttoken"


def _sig():
    return make_valid_signature(TIMESTAMP, TOKEN)


def _form_data(extra=None):
    """Return base multipart form fields with a valid signature."""
    data = {"timestamp": TIMESTAMP, "token": TOKEN, "signature": _sig()}
    if extra:
        data.update(extra)
    return data


# ---------------------------------------------------------------------------
# GET /  (nobody_home)
# ---------------------------------------------------------------------------

class TestNobodyHome:
    def test_get_root_returns_404(self, client):
        response = client.get("/")
        assert response.status_code == 404

    def test_post_root_returns_405(self, client):
        response = client.post("/")
        assert response.status_code == 405


# ---------------------------------------------------------------------------
# POST /mailfetch
# ---------------------------------------------------------------------------

class TestReceivePost:

    # ---- auth failures -------------------------------------------------

    def test_missing_signature_returns_401(self, client):
        data = {"timestamp": TIMESTAMP, "token": TOKEN}
        response = client.post(
            "/mailfetch",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 401

    def test_wrong_signature_returns_401(self, client):
        data = {"timestamp": TIMESTAMP, "token": TOKEN, "signature": "bad" + "0" * 60}
        response = client.post(
            "/mailfetch",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 401

    def test_empty_body_returns_401(self, client):
        response = client.post(
            "/mailfetch",
            data={},
            content_type="multipart/form-data",
        )
        assert response.status_code == 401

    # ---- bad-request failures ------------------------------------------

    def test_no_files_returns_400(self, client):
        data = _form_data()
        response = client.post(
            "/mailfetch",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 400

    # ---- success path --------------------------------------------------

    def test_valid_request_with_passing_report_returns_200(
        self, client, mocker, tmp_path
    ):
        mocker.patch(
            "app.parsedmarc.parse_report_file",
            return_value={
                "report_type": "aggregate",
                "report": {
                    "policy_published": {"domain": "example.com"},
                    "report_metadata": {"begin_date": 1609459200, "end_date": 1609545600},
                    "records": [
                        {
                            "policy_evaluated": {"dkim": "pass", "spf": "pass"},
                            "source": {"ip_address": "1.2.3.4"},
                        }
                    ],
                },
            },
        )
        # Redirect archive/ and failed/ to tmp_path to keep test isolated
        mocker.patch("app.os.makedirs")
        mock_save = mocker.patch("werkzeug.datastructures.FileStorage.save")
        mocker.patch("app.requests.post")

        data = _form_data(
            {"attachment": (io.BytesIO(b"fake-dmarc-content"), "report.xml.gz")}
        )
        response = client.post(
            "/mailfetch",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 200

    def test_valid_request_with_failing_report_sends_notification(
        self, client, mocker
    ):
        mocker.patch(
            "app.parsedmarc.parse_report_file",
            return_value={
                "report_type": "aggregate",
                "report": {
                    "policy_published": {"domain": "example.com"},
                    "report_metadata": {"begin_date": 1609459200, "end_date": 1609545600},
                    "records": [
                        {
                            "policy_evaluated": {"dkim": "fail", "spf": "fail"},
                            "source": {"ip_address": "5.6.7.8"},
                        }
                    ],
                },
            },
        )
        mocker.patch("app.os.makedirs")
        mocker.patch("werkzeug.datastructures.FileStorage.save")
        mock_requests_post = mocker.patch("app.requests.post")
        mock_requests_post.return_value.status_code = 200

        data = _form_data(
            {"attachment": (io.BytesIO(b"fake-dmarc-content"), "report.xml.gz")}
        )
        response = client.post(
            "/mailfetch",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        mock_requests_post.assert_called_once()

    def test_parse_failure_moves_file_to_error_directory(self, client, mocker):
        mocker.patch(
            "app.parsedmarc.parse_report_file",
            side_effect=Exception("bad zip"),
        )
        mocker.patch("app.os.makedirs")
        mocker.patch("werkzeug.datastructures.FileStorage.save")
        mock_move = mocker.patch("app.shutil.move")

        data = _form_data(
            {"attachment": (io.BytesIO(b"bad-content"), "broken.xml.gz")}
        )
        response = client.post(
            "/mailfetch",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        mock_move.assert_called_once()
        # Destination should be in the 'failed' directory
        dest_path = mock_move.call_args.args[1]
        assert dest_path.startswith("failed")

    def test_multiple_files_all_processed(self, client, mocker):
        """All uploaded files should be saved and attempted to parse."""
        mock_parse = mocker.patch(
            "app.parsedmarc.parse_report_file",
            return_value={
                "report_type": "aggregate",
                "report": {
                    "policy_published": {"domain": "example.com"},
                    "report_metadata": {},
                    "records": [],
                },
            },
        )
        mocker.patch("app.os.makedirs")
        mocker.patch("werkzeug.datastructures.FileStorage.save")

        data = _form_data(
            {
                "file1": (io.BytesIO(b"a"), "a.xml.gz"),
                "file2": (io.BytesIO(b"b"), "b.xml.gz"),
            }
        )
        response = client.post(
            "/mailfetch",
            data=data,
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        assert mock_parse.call_count == 2

    def test_list_of_reports_from_parsedmarc_all_checked(self, client, mocker):
        """parse_report_file returning a list means each report is checked."""
        mock_check = mocker.patch("app.check_pass_fail_unknown")
        mocker.patch(
            "app.parsedmarc.parse_report_file",
            return_value=[
                {"report": {"policy_published": {}, "report_metadata": {}, "records": []}},
                {"report": {"policy_published": {}, "report_metadata": {}, "records": []}},
            ],
        )
        mocker.patch("app.os.makedirs")
        mocker.patch("werkzeug.datastructures.FileStorage.save")

        data = _form_data(
            {"attachment": (io.BytesIO(b"data"), "r.xml.gz")}
        )
        client.post("/mailfetch", data=data, content_type="multipart/form-data")
        assert mock_check.call_count == 2
