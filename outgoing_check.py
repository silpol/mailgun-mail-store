#!/usr/bin/env python3
"""
outgoing_check.py — daily check of OUTGOING mail failures in Mailgun's event log (#120).

The app only watches incoming DMARC reports. A notification or heartbeat mail
that the recipient's server rejects at SMTP time (e.g. Outlook.com's
"550 5.7.1 ... (AS9031519)") is visible nowhere except Mailgun's event log,
and a bounced heartbeat looks exactly like "no heartbeat".

Why daily: Mailgun keeps events only for a few days on this plan (the 10 Nov
2026 heartbeat delivery was already gone on 20 Nov). A weekly look-back would
silently miss part of every week, so a daily timer looks back ~1 day, records
each failure once, and the weekly heartbeat summarises those records.

State (default /var/lib/dmarc-outgoing, systemd StateDirectory):
  failures.jsonl   one line per failed event, de-duplicated by Mailgun event id
  status.json      last run, last success, error, how far back Mailgun's log reaches

Privacy: only recipient DOMAINS are stored or printed; e-mail addresses inside
bounce messages are redacted. The API key never appears in output or errors.

Exit codes: 0 ok · 2 new PERMANENT failure(s) · 4 alert email not delivered ·
5 Mailgun API unreachable / error (nothing could be checked).

Usage:
    python3 outgoing_check.py                 # check and print
    python3 outgoing_check.py --email         # also email an alert on new permanent failures
"""
import argparse
import datetime
import json
import os
import re
import runpy
import sys
import time

DEFAULT_STATE_DIR = "/var/lib/dmarc-outgoing"
DEFAULT_BASE_URL = "https://api.eu.mailgun.net/v3"
DAY = 86400
LOOKBACK = 26 * 3600          # daily run + 2 h overlap; duplicates are dropped by event id
MAX_CATCHUP = 3 * DAY         # after missed runs, never ask beyond what retention keeps
COVERAGE_PROBE = 60 * DAY     # "how far back does the log reach": ask for much older
MAX_PAGES = 50                # safety net against a paging loop
KEEP_RECORDS = 90 * DAY

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


class OutgoingCheckError(RuntimeError):
    """Mailgun could not be queried. The message never contains the API key."""


# ---------------------------------------------------------------- Mailgun API

def _get_pages(session, url, key, params):
    """Yield the items of every page, following paging.next until a page is empty."""
    for _ in range(MAX_PAGES):
        try:
            resp = session.get(url, auth=("api", key), params=params, timeout=30)
        except Exception as exc:  # noqa: BLE001 - network errors of any library
            # Class name only: some exception texts echo request details.
            raise OutgoingCheckError(f"Mailgun not reachable ({type(exc).__name__})") from None
        if resp.status_code != 200:
            hint = {401: " (API key rejected)", 404: " (unknown MAILGUN_DOMAIN?)"}.get(
                resp.status_code, "")
            raise OutgoingCheckError(
                f"Mailgun events API returned HTTP {resp.status_code}{hint}")
        body = resp.json()
        items = body.get("items") or []
        if not items:
            return
        yield from items
        url = (body.get("paging") or {}).get("next")
        params = None  # the 'next' URL already carries the query
        if not url:
            return
    raise OutgoingCheckError(f"Mailgun paging did not end after {MAX_PAGES} pages")


def fetch_failed(session, base_url, domain, key, begin_ts):
    url = f"{base_url}/{domain}/events"
    params = {"event": "failed", "begin": f"{begin_ts:.0f}", "ascending": "yes", "limit": 300}
    return list(_get_pages(session, url, key, params))


def log_covers_from(session, base_url, domain, key, now):
    """Timestamp of the oldest event Mailgun still keeps (None if the log is empty)."""
    url = f"{base_url}/{domain}/events"
    params = {"begin": f"{now - COVERAGE_PROBE:.0f}", "ascending": "yes", "limit": 1}
    try:
        resp = session.get(url, auth=("api", key), params=params, timeout=30)
    except Exception:  # noqa: BLE001
        return None
    if resp.status_code != 200:
        return None
    items = resp.json().get("items") or []
    return items[0].get("timestamp") if items else None


# ---------------------------------------------------------------- records

def redact(text):
    """Replace e-mail addresses with <redacted>@domain."""
    return _EMAIL_RE.sub(lambda m: f"<redacted>@{m.group(1)}", text or "")


def to_record(event):
    ds = event.get("delivery-status") or {}
    recipient = event.get("recipient") or ""
    return {
        "id": event.get("id"),
        "ts": event.get("timestamp"),
        "domain": recipient.rsplit("@", 1)[-1].lower() if "@" in recipient else "?",
        "severity": (event.get("severity") or "?").lower(),
        "code": ds.get("code"),
        "reason": event.get("reason"),
        "message": redact(ds.get("message") or ds.get("description") or "")[:300],
    }


def load_records(state_dir):
    path = os.path.join(state_dir, "failures.jsonl")
    out = []
    if os.path.isfile(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
    return out


def save_records(state_dir, records, now):
    keep = [r for r in records if (r.get("ts") or now) >= now - KEEP_RECORDS]
    path = os.path.join(state_dir, "failures.jsonl")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for r in keep:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    os.replace(tmp, path)


def load_status(state_dir):
    try:
        with open(os.path.join(state_dir, "status.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_status(state_dir, status):
    path = os.path.join(state_dir, "status.json")
    with open(path + ".tmp", "w") as f:
        json.dump(status, f, sort_keys=True, indent=1)
    os.replace(path + ".tmp", path)


def window_begin(status, now):
    """Look back ~1 day; after missed runs catch up from the last success, max 3 days."""
    begin = now - LOOKBACK
    last_ok = status.get("last_ok")
    if last_ok:
        begin = min(begin, last_ok - 3600)
    return max(begin, now - MAX_CATCHUP)


# ---------------------------------------------------------------- reporting

def summarize(records):
    """Totals and groups by (recipient domain, severity, code), first message per group."""
    groups = {}
    for r in sorted(records, key=lambda r: r.get("ts") or 0):
        k = (r.get("domain"), r.get("severity"), r.get("code"))
        g = groups.setdefault(k, {"count": 0, "message": r.get("message")})
        g["count"] += 1
    return {
        "total": len(records),
        "permanent": sum(1 for r in records if r.get("severity") == "permanent"),
        "temporary": sum(1 for r in records if r.get("severity") == "temporary"),
        "groups": groups,
    }


def format_groups(summary, indent="  "):
    lines = []
    for (dom, sev, code), g in sorted(summary["groups"].items(),
                                      key=lambda kv: (kv[0][1] != "permanent",
                                                      -kv[1]["count"])):
        lines.append(f"{indent}{g['count']:>3} × {dom}  {sev}  {code}  {g['message']}")
    return lines


def _fmt(ts):
    if not ts:
        return "?"
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _load_cfg(path):
    if not os.path.isfile(path):
        raise OutgoingCheckError(f"config not found: {path}")
    ns = runpy.run_path(path)
    cfg = {k: v for k, v in ns.items() if k.isupper()}
    for k in ("MAILGUN_API_KEY", "MAILGUN_DOMAIN"):
        if not cfg.get(k):
            raise OutgoingCheckError(f"{path} lacks {k}")
    return cfg


def send_alert(session, base_url, cfg, text, to=None):
    domain = cfg["MAILGUN_DOMAIN"]
    try:
        resp = session.post(
            f"{base_url}/{domain}/messages", auth=("api", cfg["MAILGUN_API_KEY"]),
            data={"from": cfg.get("MAILGUN_SENDER", f"mailgun@{domain}"),
                  "to": to or cfg["MAILGUN_RECIPIENT"],
                  "subject": "[mailgun-mail-store] OUTGOING mail failures detected",
                  "text": text},
            timeout=20)
    except Exception as exc:  # noqa: BLE001
        print(f"[email] alert send FAILED ({type(exc).__name__})")
        return False
    print(f"[email] HTTP {resp.status_code}")
    return resp.status_code == 200


# ---------------------------------------------------------------- main

def run(args, session, now=None):
    now = time.time() if now is None else now
    os.makedirs(args.state_dir, exist_ok=True)
    status = load_status(args.state_dir)
    status["last_run"] = now
    try:
        cfg = _load_cfg(args.config)
        begin = window_begin(status, now)
        events = fetch_failed(session, args.base_url, cfg["MAILGUN_DOMAIN"],
                              cfg["MAILGUN_API_KEY"], begin)
    except OutgoingCheckError as exc:
        status.update(ok=False, error=str(exc))
        save_status(args.state_dir, status)
        print(f"Outgoing check FAILED: {exc}")
        return 5

    records = load_records(args.state_dir)
    seen = {r.get("id") for r in records}
    new = [to_record(e) for e in events if e.get("id") not in seen]
    records.extend(new)
    save_records(args.state_dir, records, now)
    covers = log_covers_from(session, args.base_url, cfg["MAILGUN_DOMAIN"],
                             cfg["MAILGUN_API_KEY"], now)
    status.update(ok=True, error=None, last_ok=now, window_begin=begin, log_covers_from=covers)
    save_status(args.state_dir, status)

    new_summary = summarize(new)
    print(f"Outgoing delivery check  {_fmt(begin)} .. {_fmt(now)}")
    print(f"  failed events in window: {len(events)}  (new: {len(new)}, "
          f"permanent: {new_summary['permanent']}, temporary: {new_summary['temporary']})")
    print(f"  Mailgun log currently reaches back to: {_fmt(covers)}")
    for line in format_groups(new_summary):
        print(line)

    if not new_summary["permanent"]:
        return 0
    if args.email:
        text = "\n".join([
            "Mailgun reports PERMANENT delivery failures for mail sent from "
            f"{cfg['MAILGUN_DOMAIN']} (new since the last daily check):", "",
            *format_groups(summarize([r for r in new if r["severity"] == "permanent"])), "",
            "These recipients did NOT get those notifications/heartbeats.",
            "Check the bounce message (e.g. Outlook.com 550 5.7.1 AS9031519 = missing "
            "SPF/DKIM/DMARC records for the sending domain).",
        ])
        if not send_alert(session, args.base_url, cfg, text, args.to):
            return 4
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(description="Daily check of outgoing Mailgun delivery failures.")
    ap.add_argument("--email", action="store_true",
                    help="email an alert on new permanent failures")
    ap.add_argument("--to", help="override MAILGUN_RECIPIENT for the alert")
    ap.add_argument("--config", default=os.path.join("instance", "config.py"))
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--state-dir", default=os.environ.get("STATE_DIRECTORY", DEFAULT_STATE_DIR))
    args = ap.parse_args(argv)
    import requests
    return run(args, requests.Session())


if __name__ == "__main__":
    sys.exit(main())
