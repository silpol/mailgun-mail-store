"""Unit tests for reprocess_failed.py.

The core reprocess() loop takes parsedmarc and the app module as injected
dependencies, so every test here runs fully offline with fakes — no real
parsing, no real Mailgun, no app import. The invariants under test are the
ones that matter for a one-shot production drain: dry runs are inert, files
move to archive/ only on a clean send, and a failure never loses a file.
"""
import gzip
import os
import types

import pytest

import reprocess_failed as rp


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_failed_file(failed_dir, name="2025-06-12T06-33-36_x.xml.gz"):
    os.makedirs(failed_dir, exist_ok=True)
    path = os.path.join(failed_dir, name)
    with gzip.open(path, "wb") as f:
        f.write(b"<feedback/>")  # content irrelevant; parsedmarc is faked
    return name


def aggregate_report(dkim="fail", spf="fail"):
    return {"report_type": "aggregate",
            "report": {"records": [{"policy_evaluated": {"dkim": dkim, "spf": spf}}]}}


def fake_parsedmarc(return_value=None, raises=None):
    def parse_report_file(path, offline=True):
        if raises is not None:
            raise raises
        return return_value
    return types.SimpleNamespace(parse_report_file=parse_report_file)


def fake_app(mocker):
    return types.SimpleNamespace(check_pass_fail_unknown=mocker.Mock())


def _silent(*args, **kwargs):
    """Drop-in for the log callback so tests stay quiet."""


# ---------------------------------------------------------------------------
# _aggregate_has_failure  (dry-run "would alert" predicate)
# ---------------------------------------------------------------------------

class TestWouldAlert:
    def test_aggregate_fail_true(self):
        assert rp._aggregate_has_failure(aggregate_report("fail", "pass")) is True

    def test_aggregate_pass_false(self):
        assert rp._aggregate_has_failure(aggregate_report("pass", "pass")) is False

    def test_forensic_always_true(self):
        assert rp._aggregate_has_failure({"report_type": "forensic", "report": {}}) is True

    def test_unknown_type_false(self):
        assert rp._aggregate_has_failure({"report_type": None, "report": {}}) is False


# ---------------------------------------------------------------------------
# reprocess()  — dry run
# ---------------------------------------------------------------------------

class TestDryRun:
    def test_dry_run_sends_nothing_and_moves_nothing(self, tmp_path, mocker):
        failed = str(tmp_path / "failed")
        archive = str(tmp_path / "archive")
        name = make_failed_file(failed)
        app = fake_app(mocker)

        counts = rp.reprocess(
            failed, archive, send=False,
            parsedmarc=fake_parsedmarc(aggregate_report("fail", "pass")),
            mailapp=app, log=_silent,
        )

        app.check_pass_fail_unknown.assert_not_called()
        assert os.path.exists(os.path.join(failed, name))          # stayed put
        assert os.listdir(archive) == []                           # nothing moved
        assert counts["parseable"] == 1 and counts["would_alert"] == 1

    def test_dry_run_counts_pass_as_no_alert(self, tmp_path, mocker):
        failed = str(tmp_path / "failed")
        make_failed_file(failed)
        counts = rp.reprocess(
            failed, str(tmp_path / "archive"), send=False,
            parsedmarc=fake_parsedmarc(aggregate_report("pass", "pass")),
            mailapp=fake_app(mocker), log=_silent,
        )
        assert counts["would_alert"] == 0 and counts["parseable"] == 1


# ---------------------------------------------------------------------------
# reprocess()  — send
# ---------------------------------------------------------------------------

class TestSend:
    def test_send_success_moves_to_archive(self, tmp_path, mocker):
        failed = str(tmp_path / "failed")
        archive = str(tmp_path / "archive")
        name = make_failed_file(failed)
        app = fake_app(mocker)

        counts = rp.reprocess(
            failed, archive, send=True,
            parsedmarc=fake_parsedmarc(aggregate_report("fail", "fail")),
            mailapp=app, throttle=0, log=_silent,
        )

        app.check_pass_fail_unknown.assert_called_once()
        assert not os.path.exists(os.path.join(failed, name))      # left failed/
        assert os.path.exists(os.path.join(archive, name))         # landed archive/
        assert counts["sent"] == 1 and counts["moved"] == 1

    def test_send_failure_leaves_file_in_failed(self, tmp_path, mocker):
        failed = str(tmp_path / "failed")
        archive = str(tmp_path / "archive")
        name = make_failed_file(failed)
        app = fake_app(mocker)
        app.check_pass_fail_unknown.side_effect = RuntimeError("mailgun down")

        counts = rp.reprocess(
            failed, archive, send=True,
            parsedmarc=fake_parsedmarc(aggregate_report("fail", "fail")),
            mailapp=app, throttle=0, log=_silent,
        )

        assert os.path.exists(os.path.join(failed, name))          # NOT lost
        assert not os.path.exists(os.path.join(archive, name))     # NOT moved
        assert counts["errored"] == 1 and counts["sent"] == 0

    def test_unparseable_file_stays_and_is_counted(self, tmp_path, mocker):
        failed = str(tmp_path / "failed")
        archive = str(tmp_path / "archive")
        name = make_failed_file(failed)
        app = fake_app(mocker)

        counts = rp.reprocess(
            failed, archive, send=True,
            parsedmarc=fake_parsedmarc(raises=ValueError("bad xml")),
            mailapp=app, throttle=0, log=_silent,
        )

        app.check_pass_fail_unknown.assert_not_called()
        assert os.path.exists(os.path.join(failed, name))
        assert counts["errored"] == 1 and counts["parseable"] == 0

    def test_list_of_reports_is_handled(self, tmp_path, mocker):
        failed = str(tmp_path / "failed")
        make_failed_file(failed)
        app = fake_app(mocker)
        reports = [aggregate_report("fail", "fail"), aggregate_report("pass", "pass")]
        rp.reprocess(
            failed, str(tmp_path / "archive"), send=True,
            parsedmarc=fake_parsedmarc(reports),
            mailapp=app, throttle=0, log=_silent,
        )
        assert app.check_pass_fail_unknown.call_count == 2

    def test_no_file_is_ever_lost(self, tmp_path, mocker):
        """Union of failed/ + archive/ filenames is invariant across a mixed run."""
        failed = str(tmp_path / "failed")
        archive = str(tmp_path / "archive")
        good = make_failed_file(failed, "2025-06-12T06-33-36_good.xml.gz")
        bad = make_failed_file(failed, "2025-06-13T06-33-36_bad.xml.gz")
        before = {good, bad}

        app = fake_app(mocker)
        # good sends fine; bad raises on send
        app.check_pass_fail_unknown.side_effect = [None, RuntimeError("boom")]
        rp.reprocess(
            failed, archive, send=True,
            parsedmarc=fake_parsedmarc(aggregate_report("fail", "fail")),
            mailapp=app, throttle=0, log=_silent,
        )
        after = set(os.listdir(failed)) | set(os.listdir(archive))
        assert after == before

    def test_missing_failed_dir_raises(self, tmp_path, mocker):
        with pytest.raises(FileNotFoundError):
            rp.reprocess(str(tmp_path / "nope"), str(tmp_path / "archive"),
                         send=False, parsedmarc=fake_parsedmarc(),
                         mailapp=fake_app(mocker))


# ---------------------------------------------------------------------------
# real_send_blocked()  — the CI / stray-flag guard
# ---------------------------------------------------------------------------

class TestRealSendGuard:
    def test_dry_run_never_blocked(self, monkeypatch):
        monkeypatch.delenv("ALLOW_REAL_SEND", raising=False)
        assert rp.real_send_blocked(send=False) is False

    def test_send_blocked_without_env(self, monkeypatch):
        monkeypatch.delenv("ALLOW_REAL_SEND", raising=False)
        assert rp.real_send_blocked(send=True) is True

    def test_send_allowed_with_env(self, monkeypatch):
        monkeypatch.setenv("ALLOW_REAL_SEND", "1")
        assert rp.real_send_blocked(send=True) is False

    def test_main_refuses_send_without_env(self, monkeypatch):
        monkeypatch.delenv("ALLOW_REAL_SEND", raising=False)
        # main() returns 1 before importing app / touching the network
        assert rp.main(["--send"]) == 1
