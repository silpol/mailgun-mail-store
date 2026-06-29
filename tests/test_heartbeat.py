"""Unit tests for heartbeat.py — window filtering, counting, and exit codes."""
import gzip
import zipfile

import pytest

import heartbeat as hb


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------

def agg_xml(domain="example.com", records=()):
    recs = "".join(
        f"<record><row><source_ip>{ip}</source_ip><count>{c}</count>"
        f"<policy_evaluated><dkim>{d}</dkim><spf>{s}</spf></policy_evaluated>"
        f"</row></record>"
        for ip, c, d, s in records
    )
    return (
        f"<feedback><policy_published><domain>{domain}</domain></policy_published>"
        f"{recs}</feedback>"
    ).encode("utf-8")


def write_gz(path, xml_bytes):
    with gzip.open(path, "wb") as f:
        f.write(xml_bytes)


PASS = [("1.1.1.1", "5", "pass", "pass")]
FAIL = [("2.2.2.2", "3", "fail", "fail")]


# ---------------------------------------------------------------------------
# in_window()
# ---------------------------------------------------------------------------

class TestInWindow:
    def test_no_since_always_true(self):
        assert hb.in_window("2020-01-01T00-00-00_x.xml.gz", None) is True

    def test_on_or_after_boundary_included(self):
        assert hb.in_window("2025-09-20T17-00-00_x.xml.gz", "2025-09-20") is True

    def test_before_boundary_excluded(self):
        assert hb.in_window("2025-09-19T23-59-59_x.xml.gz", "2025-09-20") is False


# ---------------------------------------------------------------------------
# report_has_failure()
# ---------------------------------------------------------------------------

class TestReportHasFailure:
    def test_pass(self):
        assert hb.report_has_failure(agg_xml(records=PASS)) == ("example.com", False)

    def test_fail(self):
        assert hb.report_has_failure(agg_xml(records=FAIL)) == ("example.com", True)

    def test_malformed_raises(self):
        import xml.etree.ElementTree as ET
        with pytest.raises(ET.ParseError):
            hb.report_has_failure(b"")


# ---------------------------------------------------------------------------
# scan_dir()
# ---------------------------------------------------------------------------

class TestScanDir:
    def test_counts_files_reports_and_fails(self, tmp_path):
        write_gz(tmp_path / "2026-06-25T08-00-00_a.xml.gz", agg_xml(records=PASS))
        write_gz(tmp_path / "2026-06-26T08-00-00_b.xml.gz", agg_xml(records=PASS))
        write_gz(tmp_path / "2026-06-27T08-00-00_c.xml.gz",
                 agg_xml(domain="bad.com", records=FAIL))
        out = hb.scan_dir(str(tmp_path), since="2026-06-01")
        assert out["files"] == 3
        assert out["reports"] == 3
        assert out["with_fail"] == 1
        assert out["fail_domains"] == {"bad.com": 1}
        assert out["latest"] == "2026-06-27T08-00-00"

    def test_window_excludes_old_files(self, tmp_path):
        write_gz(tmp_path / "2025-01-01T08-00-00_old.xml.gz", agg_xml(records=FAIL))
        write_gz(tmp_path / "2026-06-27T08-00-00_new.xml.gz", agg_xml(records=PASS))
        out = hb.scan_dir(str(tmp_path), since="2026-06-01")
        assert out["files"] == 1
        assert out["with_fail"] == 0

    def test_empty_gz_counts_as_unparseable(self, tmp_path):
        write_gz(tmp_path / "2026-06-27T08-00-00_junk.xml.gz", b"")
        out = hb.scan_dir(str(tmp_path), since="2026-06-01")
        assert out["reports"] == 1
        assert out["unparseable"] == 1

    def test_missing_dir_returns_zeros(self, tmp_path):
        out = hb.scan_dir(str(tmp_path / "nope"), since=None)
        assert out["files"] == 0 and out["latest"] is None


# ---------------------------------------------------------------------------
# build_digest()
# ---------------------------------------------------------------------------

class TestBuildDigest:
    def _empty(self):
        return {"files": 0, "reports": 0, "with_fail": 0, "unparseable": 0,
                "fail_domains": {}, "latest": None}

    def test_clean_when_quarantine_empty(self):
        arch = self._empty(); arch["files"] = 2; arch["reports"] = 2
        arch["latest"] = "2026-06-27T08-00-00"
        text = hb.build_digest("2026-06-20", "2026-06-27", arch, self._empty())
        assert "(clean)" in text
        assert "INVESTIGATE" not in text

    def test_investigate_when_quarantine_nonempty(self):
        failed = self._empty(); failed["files"] = 1; failed["with_fail"] = 1
        arch = self._empty(); arch["files"] = 1; arch["latest"] = "x"
        text = hb.build_digest("2026-06-20", "2026-06-27", arch, failed)
        assert "INVESTIGATE" in text
        assert "MISSED ALERTS" in text

    def test_warns_when_nothing_archived(self):
        text = hb.build_digest("2026-06-20", "2026-06-27", self._empty(), self._empty())
        assert "inbound may be down" in text


# ---------------------------------------------------------------------------
# main() exit codes  (the cron-facing contract)
# ---------------------------------------------------------------------------

class TestMainExitCodes:
    def _run(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit) as exc:
            hb.main()
        return exc.value.code

    def test_clean_window_exits_0(self, tmp_path, monkeypatch):
        (tmp_path / "archive").mkdir()
        (tmp_path / "failed").mkdir()
        write_gz(tmp_path / "archive" / "2026-06-27T08-00-00_a.xml.gz",
                 agg_xml(records=PASS))
        monkeypatch.setattr("sys.argv", ["heartbeat.py", "--days", "3650"])
        assert self._run(tmp_path, monkeypatch) == 0

    def test_quarantine_nonempty_exits_2(self, tmp_path, monkeypatch):
        (tmp_path / "archive").mkdir()
        (tmp_path / "failed").mkdir()
        write_gz(tmp_path / "archive" / "2026-06-27T08-00-00_a.xml.gz",
                 agg_xml(records=PASS))
        write_gz(tmp_path / "failed" / "2026-06-27T09-00-00_q.xml.gz",
                 agg_xml(records=FAIL))
        monkeypatch.setattr("sys.argv", ["heartbeat.py", "--days", "3650"])
        assert self._run(tmp_path, monkeypatch) == 2

    def test_empty_window_exits_3(self, tmp_path, monkeypatch):
        (tmp_path / "archive").mkdir()
        (tmp_path / "failed").mkdir()
        monkeypatch.setattr("sys.argv", ["heartbeat.py", "--days", "7"])
        assert self._run(tmp_path, monkeypatch) == 3
