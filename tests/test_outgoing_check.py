"""Tests for outgoing_check.py and the heartbeat's "Outgoing delivery" section (#120).

Mailgun is faked: no network, no real key.
"""
import json
import types

import pytest

import heartbeat as hb
import outgoing_check as oc

KEY = "key-SECRET-0123456789"
NOW = 1_763_600_000.0  # 2025-11-20 (arbitrary fixed clock)
BASE = "https://api.example/v3"


def ev(i, severity="permanent", recipient="alice@outlook.com", code=550,
       msg="Message rejected: lacks SPF/DKIM/DMARC Auth Records (AS9031519)", ts=None):
    return {"id": f"ev{i}", "timestamp": ts or NOW - 3600, "recipient": recipient,
            "severity": severity, "reason": "generic",
            "delivery-status": {"code": code, "message": msg}}


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


class FakeSession:
    """Serves the events API from a list of pages; records every call."""

    def __init__(self, pages=(), status=200, raise_exc=None, coverage_ts=NOW - 4 * 86400,
                 post_status=200):
        self.pages = list(pages)
        self.status = status
        self.raise_exc = raise_exc
        self.coverage_ts = coverage_ts
        self.post_status = post_status
        self.gets, self.posts = [], []

    def get(self, url, auth=None, params=None, timeout=None):
        self.gets.append((url, auth, params))
        if self.raise_exc:
            raise self.raise_exc
        if self.status != 200:
            return Resp(self.status, {"message": f"Forbidden for {auth}"})
        if params and params.get("limit") == 1:  # coverage probe
            return Resp(200, {"items": [{"timestamp": self.coverage_ts}]})
        if url.startswith(BASE):  # first page (paging.next URLs use another host)
            idx = 0
        else:
            idx = int(url.rsplit("=", 1)[1])
        items = self.pages[idx] if idx < len(self.pages) else []
        nxt = f"https://next.example/p?page={idx + 1}"
        return Resp(200, {"items": items, "paging": {"next": nxt}})

    def post(self, url, auth=None, data=None, timeout=None):
        self.posts.append((url, data))
        return Resp(self.post_status)


@pytest.fixture
def env(tmp_path):
    cfg = tmp_path / "config.py"
    cfg.write_text(f'MAILGUN_API_KEY = "{KEY}"\nMAILGUN_DOMAIN = "mg.example"\n'
                   'MAILGUN_RECIPIENT = "ops@talentmiles.pro"\n')
    state = tmp_path / "state"
    args = types.SimpleNamespace(config=str(cfg), base_url=BASE, state_dir=str(state),
                                 email=False, to=None)
    return args, state


def run(args, session, now=NOW):
    return oc.run(args, session, now=now)


# ------------------------------------------------------------------ fetching

class TestFetch:
    def test_empty_log(self, env, capsys):
        args, state = env
        assert run(args, FakeSession(pages=[])) == 0
        assert "failed events in window: 0" in capsys.readouterr().out
        assert oc.load_records(str(state)) == []

    def test_one_page(self, env):
        args, state = env
        s = FakeSession(pages=[[ev(1), ev(2, "temporary", code=421, msg="try later")]])
        assert run(args, s) == 2  # a permanent failure
        assert [r["id"] for r in oc.load_records(str(state))] == ["ev1", "ev2"]
        _, auth, params = s.gets[0]
        assert auth == ("api", KEY) and params["event"] == "failed"

    def test_two_pages_follow_paging_next(self, env):
        args, state = env
        s = FakeSession(pages=[[ev(1)], [ev(2)]])
        run(args, s)
        assert len(oc.load_records(str(state))) == 2
        assert s.gets[1][2] is None  # the 'next' URL carries the query, no params

    def test_only_temporary_is_not_an_alert(self, env):
        args, _ = env
        assert run(args, FakeSession(pages=[[ev(1, "temporary", code=421)]])) == 0

    def test_duplicates_across_runs_are_recorded_once(self, env):
        args, state = env
        run(args, FakeSession(pages=[[ev(1)]]))
        assert run(args, FakeSession(pages=[[ev(1)]]), now=NOW + 86400) == 0  # nothing new
        assert len(oc.load_records(str(state))) == 1

    def test_window_and_catch_up(self):
        assert oc.window_begin({}, NOW) == NOW - oc.LOOKBACK
        assert oc.window_begin({"last_ok": NOW - 2 * 86400}, NOW) == NOW - 2 * 86400 - 3600
        # never ask beyond what Mailgun keeps
        assert oc.window_begin({"last_ok": NOW - 30 * 86400}, NOW) == NOW - oc.MAX_CATCHUP


# ------------------------------------------------------------------ errors & privacy

class TestErrors:
    @pytest.mark.parametrize("status,hint", [(401, "API key rejected"), (404, "MAILGUN_DOMAIN"),
                                             (500, "HTTP 500")])
    def test_http_error_is_reported_not_raised(self, env, capsys, status, hint):
        args, state = env
        assert run(args, FakeSession(status=status)) == 5
        out = capsys.readouterr().out
        assert hint in out and KEY not in out
        st = oc.load_status(str(state))
        assert st["ok"] is False and KEY not in st["error"]

    def test_network_error(self, env, capsys):
        args, state = env
        exc = ConnectionError(f"failed for https://api:{KEY}@host/")  # key in the text
        assert run(args, FakeSession(raise_exc=exc)) == 5
        out = capsys.readouterr().out
        assert "ConnectionError" in out and KEY not in out
        assert KEY not in json.dumps(oc.load_status(str(state)))

    def test_missing_config(self, env):
        args, state = env
        args.config = "/nonexistent/config.py"
        assert run(args, FakeSession()) == 5
        assert "config not found" in oc.load_status(str(state))["error"]

    def test_addresses_are_redacted(self, env):
        args, state = env
        run(args, FakeSession(pages=[[ev(1, msg="550 5.1.1 <bob.smith@outlook.com>: unknown")]]))
        r = oc.load_records(str(state))[0]
        assert "bob.smith" not in json.dumps(r)
        assert r["message"] == "550 5.1.1 <<redacted>@outlook.com>: unknown"
        assert r["domain"] == "outlook.com" and "recipient" not in r


# ------------------------------------------------------------------ alert email

class TestAlert:
    def test_permanent_failure_sends_alert(self, env):
        args, _ = env
        args.email = True
        s = FakeSession(pages=[[ev(1), ev(2, "temporary", code=421)]])
        assert run(args, s) == 2
        (url, data), = s.posts
        assert url == f"{BASE}/mg.example/messages"
        assert "OUTGOING" in data["subject"]
        assert "1 × outlook.com  permanent  550" in data["text"]  # the grouped failure line
        assert "AS9031519" in data["text"] and "alice" not in data["text"]
        assert "421" not in data["text"]  # temporary ones are not in the alert

    def test_no_alert_without_new_permanent(self, env):
        args, _ = env
        args.email = True
        s = FakeSession(pages=[[ev(1, "temporary", code=421)]])
        assert run(args, s) == 0 and s.posts == []

    def test_alert_send_failure_exits_4(self, env):
        args, _ = env
        args.email = True
        assert run(args, FakeSession(pages=[[ev(1)]], post_status=401)) == 4


# ------------------------------------------------------------------ heartbeat section

class TestHeartbeatSection:
    SINCE = "2025-11-13"

    def test_not_set_up(self, tmp_path):
        lines, problem = hb.outgoing_section(str(tmp_path / "none"), self.SINCE, now=NOW)
        assert "not set up" in "\n".join(lines) and problem is False

    def test_clean_week(self, env):
        args, state = env
        run(args, FakeSession(pages=[]))
        lines, problem = hb.outgoing_section(str(state), self.SINCE, now=NOW + 3600)
        text = "\n".join(lines)
        assert "failed: 0" in text and "reaches back to" in text and problem is False

    def test_permanent_failures_in_window_are_a_problem(self, env):
        args, state = env
        run(args, FakeSession(pages=[[ev(1), ev(2), ev(3, "temporary", code=421)]]))
        lines, problem = hb.outgoing_section(str(state), self.SINCE, now=NOW + 3600)
        text = "\n".join(lines)
        assert problem is True
        assert "permanent: 2, temporary: 1" in text and "did NOT get mail" in text
        assert "2 × outlook.com  permanent  550" in text

    def test_old_failures_outside_window_ignored(self, env):
        args, state = env
        run(args, FakeSession(pages=[[ev(1, ts=NOW - 20 * 86400)]]))
        lines, problem = hb.outgoing_section(str(state), self.SINCE, now=NOW + 3600)
        assert "failed: 0" in "\n".join(lines) and problem is False

    def test_stale_daily_check_is_a_problem(self, env):
        args, state = env
        run(args, FakeSession(pages=[]))
        lines, problem = hb.outgoing_section(str(state), self.SINCE, now=NOW + 3 * 86400)
        assert "NOT RUNNING" in "\n".join(lines) and problem is True

    def test_failing_daily_check_is_a_problem(self, env):
        args, state = env
        run(args, FakeSession(status=401))
        lines, problem = hb.outgoing_section(str(state), self.SINCE, now=NOW + 3600)
        assert "FAILED" in "\n".join(lines) and problem is True

    def test_heartbeat_exit_code_5(self, env, tmp_path, monkeypatch):
        import datetime
        import time
        args, state = env
        now = time.time()
        run(args, FakeSession(pages=[[ev(1, ts=now - 3600)]]), now=now)
        (tmp_path / "archive").mkdir()
        (tmp_path / "failed").mkdir()
        (tmp_path / "archive" / f"{datetime.date.today()}T08-00-00_a.xml").write_bytes(
            b"<feedback><policy_published><domain>example.com</domain></policy_published>"
            b"</feedback>")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("sys.argv", ["heartbeat.py", "--outgoing-state", str(state)])
        with pytest.raises(SystemExit) as exc:
            hb.main()
        assert exc.value.code == 5
