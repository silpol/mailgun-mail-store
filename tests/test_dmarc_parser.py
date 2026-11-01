"""Tests for dmarc_parser (issue #115: stdlib replacement for parsedmarc).

Covers the output contract the app relies on, containers, the RFC 9990
namespace, failure (RUF) emails, rejection of non-reports, and the safety caps.
"""
import gzip
import io
import zipfile

import pytest

import app as app_module
import compare_parsers
import dmarc_parser
from dmarc_parser import ParserError, parse_report_file


def rec(ip="203.0.113.5", count=3, dkim="fail", spf="fail", header_from="example.com"):
    pe = "<policy_evaluated><disposition>none</disposition>"
    pe += f"<dkim>{dkim}</dkim>" if dkim is not None else ""
    pe += f"<spf>{spf}</spf>" if spf is not None else ""
    pe += "</policy_evaluated>"
    return (f"<record><row><source_ip>{ip}</source_ip><count>{count}</count>{pe}</row>"
            f"<identifiers><header_from>{header_from}</header_from></identifiers>"
            f"<auth_results><spf><domain>{header_from}</domain><result>{spf}</result></spf>"
            f"<dkim><domain>{header_from}</domain><selector>s1</selector>"
            f"<result>{dkim}</result></dkim></auth_results></record>")


def agg(records=None, domain="example.com", ns="", begin=1730000000, end=1730086399):
    records = [rec()] if records is None else records
    return (f'<?xml version="1.0"?><feedback{ns}><report_metadata><org_name>google.com</org_name>'
            f"<email>noreply@google.com</email><report_id>r1</report_id><date_range>"
            f"<begin>{begin}</begin><end>{end}</end></date_range></report_metadata>"
            f"<policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf>"
            f"<p>none</p><sp>none</sp><pct>100</pct></policy_published>"
            f"{''.join(records)}</feedback>").encode()


def zip_of(*members):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members:
            z.writestr(name, data)
    return bio.getvalue()


RUF = b"""From: dmarc@reporter.example
To: ruf@example.com
Subject: Report Domain: example.com
Date: Sun, 01 Nov 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="B"

--B
Content-Type: text/plain

This is an authentication failure report.

--B
Content-Type: message/feedback-report

Feedback-Type: auth-failure
Version: 1
Arrival-Date: Sun, 01 Nov 2026 11:00:00 +0200
Source-IP: 203.0.113.9
Reported-Domain: Example.com
Auth-Failure: dkim, spf
Delivery-Result: reject

--B
Content-Type: text/rfc822-headers

From: bad@example.com
Subject: spoof

--B--
""".replace(b"\n", b"\r\n")


@pytest.fixture
def write(tmp_path):
    def _write(data, name="report.xml"):
        p = tmp_path / name
        p.write_bytes(data)
        return str(p)
    return _write


# ------------------------------------------------------------ aggregate contract

class TestAggregateContract:
    def test_fields_the_app_reads(self, write):
        out = parse_report_file(write(agg()))
        assert out["report_type"] == "aggregate"
        r = out["report"]
        assert r["policy_published"]["domain"] == "example.com"
        # parsedmarc's date format, in UTC
        assert r["report_metadata"]["begin_date"] == "2024-10-27 03:33:20"
        assert r["report_metadata"]["end_date"] == "2024-10-28 03:33:19"
        record = r["records"][0]
        assert record["source"]["ip_address"] == "203.0.113.5"
        assert record["count"] == 3
        assert record["policy_evaluated"]["dkim"] == "fail"
        assert record["policy_evaluated"]["spf"] == "fail"
        assert record["identifiers"]["header_from"] == "example.com"
        assert record["auth_results"]["dkim"][0]["selector"] == "s1"

    def test_results_are_lowercased(self, write):
        r = parse_report_file(write(agg([rec(dkim="PASS", spf="Fail")])))["report"]
        assert r["records"][0]["policy_evaluated"] == {
            "disposition": "none", "dkim": "pass", "spf": "fail", "policy_override_reasons": []}

    def test_missing_result_counts_as_fail(self, write):
        r = parse_report_file(write(agg([rec(dkim=None, spf="pass")])))["report"]
        assert r["records"][0]["policy_evaluated"]["dkim"] == "fail"

    def test_domain_case_is_kept(self, write):
        r = parse_report_file(write(agg(domain="Example.COM")))["report"]
        assert r["policy_published"]["domain"] == "Example.COM"

    def test_report_without_records_parses(self, write):
        assert parse_report_file(write(agg(records=[])))["report"]["records"] == []

    def test_rfc9990_namespace(self, write):
        out = parse_report_file(write(agg(ns=' xmlns="urn:ietf:params:xml:ns:dmarc-2.0"')))
        assert out["report"]["records"][0]["source"]["ip_address"] == "203.0.113.5"

    def test_record_without_source_ip_raises(self, write):
        bad = agg([rec()]).replace(b"<source_ip>203.0.113.5</source_ip>", b"")
        with pytest.raises(ParserError, match="source_ip"):
            parse_report_file(write(bad))

    def test_bad_count_raises(self, write):
        with pytest.raises(ParserError, match="count"):
            parse_report_file(write(agg([rec(count="lots")])))

    def test_offline_argument_is_accepted(self, write):
        assert parse_report_file(write(agg()), offline=False)["report_type"] == "aggregate"


# ------------------------------------------------------------ containers

class TestContainers:
    def test_gzip(self, write):
        out = parse_report_file(write(gzip.compress(agg()), "r.xml.gz"))
        assert out["report_type"] == "aggregate"

    def test_zip(self, write):
        out = parse_report_file(write(zip_of(("r.xml", agg())), "r.zip"))
        assert out["report_type"] == "aggregate"

    def test_multi_member_zip_returns_every_report(self, write):
        # parsedmarc only reads the first member; a failure in the second was lost
        data = zip_of(("a.xml", agg([rec(dkim="pass", spf="pass")], domain="a.example")),
                      ("b.xml", agg([rec(ip="192.0.2.1")], domain="b.example")))
        out = parse_report_file(write(data, "r.zip"))
        domains = [o["report"]["policy_published"]["domain"] for o in out]
        assert domains == ["a.example", "b.example"]

    def test_aggregate_attached_to_an_email(self, write):
        import email.message
        msg = email.message.EmailMessage()
        msg["From"] = "noreply@google.com"
        msg["Subject"] = "Report domain: example.com"
        msg.set_content("report attached")
        msg.add_attachment(zip_of(("r.xml", agg())), maintype="application",
                           subtype="zip", filename="r.zip")
        out = parse_report_file(write(msg.as_bytes(), "r.eml"))
        assert out["report"]["records"][0]["source"]["ip_address"] == "203.0.113.5"


# ------------------------------------------------------------ failure (RUF) reports

class TestFailureReports:
    def test_feedback_report_fields(self, write):
        out = parse_report_file(write(RUF, "ruf.eml"))
        assert out["report_type"] == "failure"
        r = out["report"]
        assert r["reported_domain"] == "example.com"
        assert r["auth_failure"] == ["dkim", "spf"]
        assert r["source"]["ip_address"] == "203.0.113.9"
        assert r["delivery_result"] == "reject"
        assert r["arrival_date_utc"] == "2026-11-01 09:00:00"  # converted to UTC

    def test_app_notifies_on_it(self, write, mocker):
        post = mocker.patch("app.requests.post")
        post.return_value.status_code = 200
        path = write(RUF, "ruf.eml")
        app_module.check_pass_fail_unknown(parse_report_file(path), path, "s")
        subject = post.call_args.kwargs["data"]["subject"]
        assert "forensic DMARC report for example.com" in subject


# ------------------------------------------------------------ rejection and safety

class TestRejection:
    @pytest.mark.parametrize("data", [
        b"",
        b"\x00\x01 not a report",
        b"<feedback><report_metadata>",              # truncated XML
        b"<html><body>hi</body></html>",             # wrong root
        b"<feedback><record/></feedback>",           # no metadata
        gzip.compress(b""),
    ])
    def test_non_reports_raise(self, write, data):
        with pytest.raises(ParserError):
            parse_report_file(write(data))

    def test_doctype_rejected_before_parsing(self, write):
        # default-attribute amplification (parsedmarc GHSA-m47j-wp78-fqjg)
        bomb = (b'<?xml version="1.0"?><!DOCTYPE feedback [<!ATTLIST z a0 CDATA "v">]>'
                b"<feedback>" + b"<z/>" * 1000 + b"</feedback>")
        with pytest.raises(ParserError, match="DOCTYPE"):
            parse_report_file(write(bomb))

    def test_entity_declaration_rejected(self, write):
        lol = b'<?xml version="1.0"?><!ENTITY lol "lol"><feedback/>'
        with pytest.raises(ParserError, match="DOCTYPE/ENTITY"):
            parse_report_file(write(lol))

    def test_gzip_bomb_capped(self, write, monkeypatch):
        monkeypatch.setattr(dmarc_parser, "MAX_DECOMPRESSED_BYTES", 1000)
        with pytest.raises(ParserError, match="exceeds"):
            parse_report_file(write(gzip.compress(b" " * 5000 + agg()), "r.xml.gz"))

    def test_zip_bomb_capped(self, write, monkeypatch):
        monkeypatch.setattr(dmarc_parser, "MAX_DECOMPRESSED_BYTES", 1000)
        data = zip_of(("a.xml", b" " * 600 + agg()), ("b.xml", b" " * 600 + agg()))
        with pytest.raises(ParserError):
            parse_report_file(write(data, "r.zip"))

    def test_empty_zip_rejected(self, write):
        with pytest.raises(ParserError, match="empty"):
            parse_report_file(write(zip_of(), "r.zip"))


# ------------------------------------------------------------ app integration

class TestAppContract:
    def test_failing_aggregate_produces_the_usual_email(self, write, mocker):
        post = mocker.patch("app.requests.post")
        post.return_value.status_code = 200
        path = write(agg())
        app_module.check_pass_fail_unknown(parse_report_file(path), path, "s")
        data = post.call_args.kwargs["data"]
        assert data["subject"] == ("detected FAIL in aggregate DMARC report for example.com "
                                   "from 2024-10-27 03:33:20 to 2024-10-28 03:33:19")
        assert "- Source IP: 203.0.113.5, DKIM: fail, SPF: fail" in data["text"]

    def test_passing_aggregate_sends_nothing(self, write, mocker):
        post = mocker.patch("app.requests.post")
        path = write(agg([rec(dkim="pass", spf="pass")]))
        app_module.check_pass_fail_unknown(parse_report_file(path), path, "s")
        post.assert_not_called()


# ------------------------------------------------------------ compare_parsers

class TestCompareVerdict:
    def test_verdict_reduces_to_alert_relevant_fields(self, write):
        v = compare_parsers.verdict(parse_report_file(write(agg([
            rec(ip="1.1.1.1", dkim="pass", spf="pass"),
            rec(ip="2.2.2.2", dkim="fail", spf="pass"),
            rec(ip="2.2.2.2", dkim="fail", spf="pass"),  # duplicates collapse
        ]))))
        assert v == [("aggregate", "example.com", "2024-10-27 03:33:20",
                      "2024-10-28 03:33:19", (("2.2.2.2", "fail", "pass"),))]

    def test_verdict_for_failure_report(self, write):
        v = compare_parsers.verdict(parse_report_file(write(RUF, "ruf.eml")))
        assert v == [("failure", "example.com", ("dkim", "spf"), "203.0.113.9")]
