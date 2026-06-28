#!/usr/bin/env python3
"""
heartbeat.py — weekly liveness + activity digest for mailgun-mail-store.

Why this exists: the app has three distinct ways to silently produce "no
notification", all indistinguishable from your inbox —
  1. nothing was failing DMARC (correct silence),
  2. a report was quarantined into failed/ (a bug / a malformed payload),
  3. the outbound send failed (credential/plan).
A heartbeat collapses all three into ONE observable signal that arrives on a
schedule whether or not anything happened. Silence from the heartbeat itself
then means something is wrong (inbound stopped, or the cron died) — which is
exactly the signal you currently lack.

It is intentionally dependency-light: stdlib only for the scan (no parsedmarc),
so it can run as a pure monitor even outside the app's virtualenv. `requests`
is imported only if you ask it to email the digest.

Counts, over a trailing window (default 7 days):
  * reports archived (parsed OK and kept)            -> pipeline did its job
  * of those, how many carried a DKIM/SPF failure    -> alerts that should fire
  * reports quarantined in failed/                   -> should be ZERO now
  * of those, parseable-with-failure vs unparseable  -> missed alerts vs junk

Exit codes (cron-friendly):
  0  normal (quarantine empty in window)
  2  quarantine NON-EMPTY in window  -> investigate
  3  NO files at all in window        -> possible inbound outage / dead cron

Usage:
    python3 heartbeat.py                          # print digest for last 7 days
    python3 heartbeat.py --days 30
    python3 heartbeat.py --email                  # also send via Mailgun (uses instance/config.py)
    python3 heartbeat.py --email --to ops@example.com
    # cron (every Monday 08:00):
    # 0 8 * * 1 cd /srv/app && /srv/app/venv/bin/python heartbeat.py --email >> /var/log/dmarc-heartbeat.log 2>&1
"""
import argparse
import datetime
import gzip
import os
import sys
import zipfile
import xml.etree.ElementTree as ET


# ---------- lightweight, dependency-free DMARC aggregate parsing ----------

def iter_xml_blobs(path):
    low = path.lower()
    try:
        if low.endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if name.lower().endswith(".xml"):
                        yield z.read(name)
        elif low.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                yield f.read()
        elif low.endswith(".xml"):
            with open(path, "rb") as f:
                yield f.read()
    except Exception:
        return  # corrupt container -> treated as unparseable by caller


def _text(el):
    return (el.text or "").strip() if el is not None else ""


def report_has_failure(xml_bytes):
    """Return (domain, has_fail) for one aggregate report; raises on bad XML."""
    root = ET.fromstring(xml_bytes)
    domain = _text(root.find("./policy_published/domain")) or "unknown"
    for rec in root.findall("./record"):
        pe = rec.find("./row/policy_evaluated")
        dkim = _text(pe.find("dkim") if pe is not None else None).lower()
        spf = _text(pe.find("spf") if pe is not None else None).lower()
        if dkim != "pass" or spf != "pass":
            return domain, True
    return domain, False


# ---------- scanning ----------

def in_window(fn, since):
    # filenames are ISO-prefixed: 2025-09-20T...  -> string compare on YYYY-MM-DD
    return (not since) or fn[:10] >= since


def scan_dir(path, since):
    """Return dict of counts + collected detail for one directory."""
    out = {
        "files": 0, "reports": 0, "with_fail": 0,
        "unparseable": 0, "fail_domains": {}, "latest": None,
    }
    if not os.path.isdir(path):
        return out
    for fn in sorted(os.listdir(path)):
        full = os.path.join(path, fn)
        if not os.path.isfile(full) or not in_window(fn, since):
            continue
        out["files"] += 1
        out["latest"] = fn[:19]
        any_blob = False
        for blob in iter_xml_blobs(full):
            any_blob = True
            out["reports"] += 1
            try:
                domain, has_fail = report_has_failure(blob)
            except ET.ParseError:
                out["unparseable"] += 1
                continue
            if has_fail:
                out["with_fail"] += 1
                out["fail_domains"][domain] = out["fail_domains"].get(domain, 0) + 1
        if not any_blob:  # unknown extension or empty container
            out["unparseable"] += 1
    return out


# ---------- reporting ----------

def build_digest(since, until, arch, failed):
    lines = []
    lines.append(f"DMARC store heartbeat  {since} .. {until}")
    lines.append("=" * 52)
    lines.append(f"Archived (processed OK): {arch['files']} files, "
                 f"{arch['reports']} reports")
    lines.append(f"  with DKIM/SPF failure: {arch['with_fail']}  "
                 f"(notifications that should have fired)")
    if arch["fail_domains"]:
        for dom, n in sorted(arch["fail_domains"].items(), key=lambda x: -x[1]):
            lines.append(f"      {dom}: {n}")
    lines.append("")
    q = failed["files"]
    lines.append(f"Quarantined (failed/): {q} files"
                 + ("  <-- INVESTIGATE" if q else "  (clean)"))
    if q:
        lines.append(f"  parseable w/ failure (MISSED ALERTS): {failed['with_fail']}")
        lines.append(f"  unparseable / junk:                   {failed['unparseable']}")
        if failed["fail_domains"]:
            for dom, n in sorted(failed["fail_domains"].items(), key=lambda x: -x[1]):
                lines.append(f"      {dom}: {n}")
    lines.append("")
    if arch["latest"]:
        lines.append(f"Most recent archived report: {arch['latest']}")
    else:
        lines.append("No reports archived in this window — inbound may be down.")
    return "\n".join(lines)


def maybe_email(text, args):
    import requests  # only needed when emailing
    import runpy
    cfg_path = args.config
    if not os.path.isfile(cfg_path):
        sys.exit(f"--email given but config not found: {cfg_path}")
    ns = runpy.run_path(cfg_path)
    cfg = {k: v for k, v in ns.items() if k.isupper()}
    try:
        key, domain = cfg["MAILGUN_API_KEY"], cfg["MAILGUN_DOMAIN"]
        recipient = args.to or cfg["MAILGUN_RECIPIENT"]
    except KeyError as e:
        sys.exit(f"missing config key for --email: {e}")
    sender = cfg.get("MAILGUN_SENDER", f"mailgun@{domain}")
    resp = requests.post(
        f"{args.base_url}/{domain}/messages",
        auth=("api", key),
        data={"from": sender, "to": recipient,
              "subject": "[mailgun-mail-store] weekly DMARC heartbeat",
              "text": text},
        timeout=20,
    )
    print(f"\n[email] HTTP {resp.status_code} {resp.text.strip()[:120]}")
    if resp.status_code != 200:
        print("[email] heartbeat send FAILED — the digest didn't reach you.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", default="archive")
    ap.add_argument("--failed", default="failed")
    ap.add_argument("--days", type=int, default=7, help="trailing window in days (default 7)")
    ap.add_argument("--since", help="override window start as YYYY-MM-DD")
    ap.add_argument("--email", action="store_true", help="also send the digest via Mailgun")
    ap.add_argument("--config", default=os.path.join("instance", "config.py"))
    ap.add_argument("--to", help="override recipient for the heartbeat email")
    ap.add_argument("--base-url", default="https://api.eu.mailgun.net/v3")
    args = ap.parse_args()

    today = datetime.date.today()
    since = args.since or (today - datetime.timedelta(days=args.days)).isoformat()
    until = today.isoformat()

    arch = scan_dir(args.archive, since)
    failed = scan_dir(args.failed, since)

    digest = build_digest(since, until, arch, failed)
    print(digest)

    if args.email:
        maybe_email(digest, args)

    if failed["files"]:
        sys.exit(2)
    if arch["files"] == 0:
        sys.exit(3)
    sys.exit(0)


if __name__ == "__main__":
    main()
