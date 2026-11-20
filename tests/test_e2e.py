"""End-to-end tests (#48): the real app, on a real HTTP server, over real sockets.

Nothing inside the app is mocked: the real parser, real file storage, and the
real `requests` HTTP client. The only stand-in is Mailgun itself, a local HTTP
server that records what the app sends it (via MAILGUN_API_BASE).

Each test POSTs a signed multipart request exactly as Mailgun's store()+notify
route does, then checks what was stored on disk and what reached "Mailgun".
"""
import base64
import gzip
import http.server
import io
import os
import threading
import time
import zipfile

import pytest
import requests
from werkzeug.serving import make_server

from app import app as flask_app
from tests.conftest import TEST_API_KEY, TEST_DOMAIN, make_signature
from tests.test_parser_contract import (
    _AGGREGATE_FAIL_XML, _AGGREGATE_PASS_XML, _FAILURE_REPORT_EML)


# ---------------------------------------------------------------- servers

class FakeMailgun(http.server.ThreadingHTTPServer):
    """Records every POST; answers with a configurable status."""

    def __init__(self):
        self.requests = []
        self.status = 200
        super().__init__(("127.0.0.1", 0), _MailgunHandler)


class _MailgunHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output quiet
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append(
            {"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"message": "Queued. Thank you."}')


@pytest.fixture
def mailgun():
    srv = FakeMailgun()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def live_app(tmp_path, monkeypatch, mailgun, app_config):
    """The real WSGI app on 127.0.0.1:<random port>, storing under tmp_path."""
    # Talk to local servers directly, whatever proxy the environment configures.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.chdir(tmp_path)  # archive/ and failed/ are relative to the CWD
    monkeypatch.setitem(flask_app.config, "MAILGUN_API_BASE",
                        f"http://127.0.0.1:{mailgun.server_port}/v3")
    monkeypatch.setitem(flask_app.config, "TESTING", False)  # behave like production
    server = make_server("127.0.0.1", 0, flask_app, threaded=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}", tmp_path
    server.shutdown()


# ---------------------------------------------------------------- helpers

def signed_fields(subject="Report domain: example.com"):
    ts, tok = str(int(time.time())), os.urandom(8).hex()
    return {"timestamp": ts, "token": tok,
            "signature": make_signature(TEST_API_KEY, ts, tok), "subject": subject}


def post(base, files, fields=None):
    session = requests.Session()
    session.trust_env = False
    return session.post(f"{base}/mailfetch", data=fields or signed_fields(),
                        files=files, timeout=30)


def zipped(name, data):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, data)
    return bio.getvalue()


def stored(root, sub):
    d = root / sub
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


# ---------------------------------------------------------------- tests

def test_healthz_over_http(live_app):
    base, _ = live_app
    resp = requests.get(f"{base}/healthz", timeout=10)
    assert resp.status_code == 200 and resp.json()["status"] == "ok"


def test_failing_zip_report_is_archived_and_alerts_mailgun(live_app, mailgun):
    base, root = live_app
    report = zipped("google.com!example.com!1730000000!1730086399.xml", _AGGREGATE_FAIL_XML)
    resp = post(base, {"attachment-1": ("google.com!example.com.zip", report)})

    assert resp.status_code == 200
    assert len(stored(root, "archive")) == 1 and stored(root, "failed") == []
    (req,) = mailgun.requests
    assert req["path"] == f"/v3/{TEST_DOMAIN}/messages"
    user, _, key = base64.b64decode(req["auth"].split()[1]).decode().partition(":")
    assert (user, key) == ("api", TEST_API_KEY)
    assert b"detected FAIL in aggregate DMARC report for example.com" in req["body"]
    assert b"203.0.113.5" in req["body"]
    assert b'filename="' in req["body"] and report in req["body"]  # report attached


def test_passing_gzip_report_is_archived_without_alert(live_app, mailgun):
    base, root = live_app
    resp = post(base, {"attachment-1": ("report.xml.gz", gzip.compress(_AGGREGATE_PASS_XML))})
    assert resp.status_code == 200
    assert len(stored(root, "archive")) == 1
    assert mailgun.requests == []


def test_failure_report_email_alerts(live_app, mailgun):
    base, root = live_app
    resp = post(base, {"attachment-1": ("ruf.eml", _FAILURE_REPORT_EML)})
    assert resp.status_code == 200 and len(stored(root, "archive")) == 1
    (req,) = mailgun.requests
    assert b"forensic DMARC report for example.com" in req["body"]


def test_malformed_report_is_quarantined_without_alert(live_app, mailgun):
    base, root = live_app
    resp = post(base, {"attachment-1": ("junk.xml", b"<feedback><report_metadata>")})
    assert resp.status_code == 200
    assert stored(root, "archive") == [] and len(stored(root, "failed")) == 1
    assert mailgun.requests == []


def test_several_attachments_in_one_request(live_app, mailgun):
    base, root = live_app
    resp = post(base, {
        "attachment-1": ("fail.zip", zipped("f.xml", _AGGREGATE_FAIL_XML)),
        "attachment-2": ("pass.xml.gz", gzip.compress(_AGGREGATE_PASS_XML)),
        "attachment-3": ("junk.xml", b"not xml"),
    })
    assert resp.status_code == 200
    assert len(stored(root, "archive")) == 2 and len(stored(root, "failed")) == 1
    assert len(mailgun.requests) == 1  # only the failing report alerts


@pytest.mark.parametrize("fields", [
    {"subject": "no signature at all"},
    {**signed_fields(), "signature": "0" * 64},                  # forged
    {**signed_fields(), "timestamp": str(int(time.time()) - 3600)},  # replayed/stale
])
def test_bad_signature_is_rejected_and_nothing_is_stored(live_app, mailgun, fields):
    base, root = live_app
    resp = post(base, {"attachment-1": ("r.zip", zipped("r.xml", _AGGREGATE_FAIL_XML))}, fields)
    assert resp.status_code == 401
    assert stored(root, "archive") == [] and stored(root, "failed") == []
    assert mailgun.requests == []


def test_mailgun_outage_keeps_the_report(live_app, mailgun):
    """Mailgun answering 500: the report stays archived (not quarantined) and the
    webhook still gets 200, so Mailgun doesn't redeliver the same report forever."""
    base, root = live_app
    mailgun.status = 500
    resp = post(base, {"attachment-1": ("fail.zip", zipped("f.xml", _AGGREGATE_FAIL_XML))})
    assert resp.status_code == 200
    assert len(stored(root, "archive")) == 1 and stored(root, "failed") == []
    assert len(mailgun.requests) == 1  # the alert was attempted
