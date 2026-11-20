"""Unit tests for dmarc_fail_scan.py (the read-only archive scanner)."""
import gzip
import io
import zipfile

import pytest

import dmarc_fail_scan as scan
from dmarc_parser import ParserError


# ---------------------------------------------------------------------------
# fixtures / builders
# ---------------------------------------------------------------------------

def agg_xml(domain="example.com", begin="1758240000", end="1758326400", records=()):
    """Build a minimal DMARC aggregate report. records: (ip, count, dkim, spf)."""
    recs = "".join(
        f"<record><row><source_ip>{ip}</source_ip><count>{c}</count>"
        f"<policy_evaluated><dkim>{d}</dkim><spf>{s}</spf></policy_evaluated>"
        f"</row></record>"
        for ip, c, d, s in records
    )
    return (
        f"<feedback><report_metadata><date_range>"
        f"<begin>{begin}</begin><end>{end}</end></date_range></report_metadata>"
        f"<policy_published><domain>{domain}</domain></policy_published>"
        f"{recs}</feedback>"
    ).encode("utf-8")


def write_zip(path, xml_bytes, inner="report.xml"):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(inner, xml_bytes)


def write_gz(path, xml_bytes):
    with gzip.open(path, "wb") as f:
        f.write(xml_bytes)


# ---------------------------------------------------------------------------
# analyse()
# ---------------------------------------------------------------------------

class TestAnalyse:
    def test_all_pass_has_no_failing_records(self):
        xml = agg_xml(records=[("1.2.3.4", "5", "pass", "pass")])
        domain, begin, end, failing = scan.analyse(xml)
        assert domain == "example.com"
        assert begin == "1758240000"
        assert end == "1758326400"
        assert failing == []

    def test_dkim_fail_is_flagged(self):
        xml = agg_xml(records=[("1.2.3.4", "3", "fail", "pass")])
        _, _, _, failing = scan.analyse(xml)
        assert failing == [("1.2.3.4", "3", "fail", "pass")]

    def test_spf_fail_is_flagged(self):
        xml = agg_xml(records=[("1.2.3.4", "1", "pass", "fail")])
        _, _, _, failing = scan.analyse(xml)
        assert failing and failing[0][3] == "fail"

    def test_both_fail_is_flagged_once(self):
        xml = agg_xml(records=[("9.9.9.9", "2", "fail", "fail")])
        _, _, _, failing = scan.analyse(xml)
        assert len(failing) == 1

    def test_mixed_records_returns_only_failing(self):
        xml = agg_xml(records=[
            ("1.1.1.1", "5", "pass", "pass"),
            ("2.2.2.2", "1", "fail", "pass"),
            ("3.3.3.3", "7", "pass", "pass"),
        ])
        _, _, _, failing = scan.analyse(xml)
        assert [f[0] for f in failing] == ["2.2.2.2"]

    def test_uppercase_pass_is_still_pass(self):
        # The app lowercases before comparing; "PASS" must not count as a fail.
        xml = agg_xml(records=[("1.2.3.4", "1", "PASS", "Pass")])
        _, _, _, failing = scan.analyse(xml)
        assert failing == []

    def test_missing_domain_defaults_unknown(self):
        xml = b"<feedback><record><row><source_ip>1.2.3.4</source_ip>" \
              b"<policy_evaluated><dkim>fail</dkim><spf>fail</spf>" \
              b"</policy_evaluated></row></record></feedback>"
        domain, _, _, failing = scan.analyse(xml)
        assert domain == "unknown"
        assert failing  # still detects the failure

    def test_malformed_xml_raises_parseerror(self):
        import xml.etree.ElementTree as ET
        with pytest.raises(ET.ParseError):
            scan.analyse(b"")


# ---------------------------------------------------------------------------
# iter_xml_blobs()
# ---------------------------------------------------------------------------

class TestIterXmlBlobs:
    def test_reads_zip(self, tmp_path):
        p = tmp_path / "r.zip"
        write_zip(p, agg_xml())
        blobs = list(scan.iter_xml_blobs(str(p)))
        assert len(blobs) == 1 and b"<feedback>" in blobs[0]

    def test_reads_gz(self, tmp_path):
        p = tmp_path / "r.xml.gz"
        write_gz(p, agg_xml())
        blobs = list(scan.iter_xml_blobs(str(p)))
        assert len(blobs) == 1 and b"<feedback>" in blobs[0]

    def test_reads_plain_xml(self, tmp_path):
        p = tmp_path / "r.xml"
        p.write_bytes(agg_xml())
        blobs = list(scan.iter_xml_blobs(str(p)))
        assert len(blobs) == 1

    def test_zip_ignores_non_xml_members(self, tmp_path):
        p = tmp_path / "r.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("notes.txt", b"ignore me")
            z.writestr("report.xml", agg_xml())
        blobs = list(scan.iter_xml_blobs(str(p)))
        assert len(blobs) == 1

    def test_unknown_extension_yields_nothing(self, tmp_path):
        p = tmp_path / "r.csv"
        p.write_bytes(b"a,b,c")
        assert list(scan.iter_xml_blobs(str(p))) == []

    def test_corrupt_container_does_not_raise(self, tmp_path):
        p = tmp_path / "r.zip"
        p.write_bytes(b"not really a zip")
        # Must swallow the error and yield nothing rather than crash the run.
        assert list(scan.iter_xml_blobs(str(p))) == []


# ---------------------------------------------------------------------------
# issue #119: RFC 9990 (dmarc-2.0 namespace) and DOCTYPE rejection
# ---------------------------------------------------------------------------

def ns_xml(**kw):
    return agg_xml(**kw).replace(
        b"<feedback>", b'<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">', 1)


class TestRfc9990:
    def test_namespaced_failure_is_found(self):
        domain, begin, end, failing = scan.analyse(
            ns_xml(records=[("203.0.113.9", "4", "fail", "fail")]))
        assert (domain, begin, end) == ("example.com", "1758240000", "1758326400")
        assert failing == [("203.0.113.9", "4", "fail", "fail")]

    def test_namespaced_pass_has_no_failures(self):
        domain, _, _, failing = scan.analyse(ns_xml(records=[("1.1.1.1", "2", "pass", "pass")]))
        assert domain == "example.com" and failing == []

    def test_doctype_rejected(self):
        bomb = (b'<?xml version="1.0"?><!DOCTYPE feedback [<!ATTLIST z a0 CDATA "v">]>'
                b"<feedback><z/></feedback>")
        with pytest.raises(ParserError, match="DOCTYPE"):
            scan.analyse(bomb)

    def test_main_reports_rejected_file_and_continues(self, tmp_path, capsys, monkeypatch):
        write_gz(tmp_path / "2026-06-27T08-00-00_bomb.xml.gz",
                 b'<!DOCTYPE x [<!ENTITY a "b">]><feedback/>')
        write_gz(tmp_path / "2026-06-27T09-00-00_ns.xml.gz",
                 ns_xml(records=[("203.0.113.9", "1", "fail", "pass")]))
        monkeypatch.setattr("sys.argv", ["dmarc_fail_scan.py", str(tmp_path)])
        scan.main()
        out = capsys.readouterr()
        assert "XML parse error" in out.err
        assert "1 contained at least one DKIM/SPF FAIL" in out.out
