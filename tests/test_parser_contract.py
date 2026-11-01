"""Contract tests: run the REAL parser (no mock) through /mailfetch.

The rest of the suite mocks ``dmarc_parser.parse_report_file`` with
hand-written dicts, so it cannot notice when the parser's output stops matching
what app.py reads. That is how parsedmarc's forensic -> failure rename once
silently disabled RUF notifications. These tests pin the contract end to end.
"""
import io
import os
import time

from tests.conftest import TEST_API_KEY, make_signature

_AGGREGATE_FAIL_XML = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>reporter.example</org_name><email>dmarc@reporter.example</email>
    <report_id>contract-1</report_id>
    <date_range><begin>1730000000</begin><end>1730086399</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>
    <p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.5</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>
"""

_AGGREGATE_PASS_XML = _AGGREGATE_FAIL_XML.replace(b"<dkim>fail</dkim><spf>fail</spf>",
                                                  b"<dkim>pass</dkim><spf>pass</spf>")

_FAILURE_REPORT_EML = b"""From: dmarc@reporter.example
To: ruf@example.com
Subject: Report Domain: example.com Submitter: reporter.example
Date: Sun, 01 Nov 2026 10:00:00 +0000
Message-ID: <r1@reporter.example>
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="B"

--B
Content-Type: text/plain

This is an authentication failure report.

--B
Content-Type: message/feedback-report

Feedback-Type: auth-failure
User-Agent: test/1.0
Version: 1
Original-Mail-From: <bad@example.com>
Arrival-Date: Sun, 01 Nov 2026 09:00:00 +0000
Source-IP: 203.0.113.9
Reported-Domain: example.com
Auth-Failure: dmarc
Delivery-Result: reject

--B
Content-Type: text/rfc822-headers

From: bad@example.com
To: victim@example.org
Subject: spoof
Date: Sun, 01 Nov 2026 09:00:00 +0000
Message-ID: <spoof@x>

--B--
""".replace(b"\n", b"\r\n")


def _post(client, payload, filename):
    ts, tok = str(int(time.time())), "contracttoken"
    data = {
        "timestamp": ts,
        "token": tok,
        "signature": make_signature(TEST_API_KEY, ts, tok),
        "subject": "contract",
        "attachment-1": (io.BytesIO(payload), filename),
    }
    return client.post("/mailfetch", data=data, content_type="multipart/form-data")


def _mock_send(mocker):
    mock_post = mocker.patch("app.requests.post")
    mock_post.return_value.status_code = 200
    return mock_post


def test_real_aggregate_failure_sends_notification(client, mocker):
    mock_post = _mock_send(mocker)
    assert _post(client, _AGGREGATE_FAIL_XML, "agg.xml").status_code == 200
    assert mock_post.call_count == 1
    sent = mock_post.call_args.kwargs["data"]
    assert "aggregate DMARC report for example.com" in sent["subject"]
    assert "203.0.113.5" in sent["text"]
    assert os.listdir("failed") == []


def test_real_aggregate_all_pass_sends_nothing(client, mocker):
    mock_post = _mock_send(mocker)
    assert _post(client, _AGGREGATE_PASS_XML, "agg.xml").status_code == 200
    assert mock_post.call_count == 0
    assert os.listdir("failed") == []


def test_real_failure_report_sends_notification(client, mocker):
    mock_post = _mock_send(mocker)
    assert _post(client, _FAILURE_REPORT_EML, "ruf.eml").status_code == 200
    assert mock_post.call_count == 1
    sent = mock_post.call_args.kwargs["data"]
    assert "forensic DMARC report for example.com" in sent["subject"]
    assert "203.0.113.9" in sent["text"]
    assert os.listdir("failed") == []
