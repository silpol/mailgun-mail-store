#!/usr/bin/env python3
"""
reprocess_failed.py — drain the failed/ quarantine through the notification path.

Background: an earlier version of the app called parsedmarc with offline=False,
whose live IP-enrichment occasionally raised on valid (Outlook) reports. The
app's except clause moved those reports to failed/ with no alert, so each one
is a MISSED notification. This script re-parses every file in failed/ with
offline=True (the fix) and sends the notification email the app would have sent,
then moves successfully-processed files into archive/ so the quarantine ends up
empty and the audit trail stays intact.

It uses the app's OWN functions (check_pass_fail_unknown) so the emails are
byte-for-byte what the live app produces — no reimplementation to drift.

SAFETY:
  * Run mailgun_send_test.py first and confirm HTTP 200. If outbound is dead,
    this will "succeed" while sending nothing.
  * Default is a DRY RUN: parses and reports what it WOULD send; sends nothing,
    moves nothing. Add --send to actually email + move.
  * A real --send additionally requires ALLOW_REAL_SEND=1 in the environment,
    so a stray --send in a CI shell or test run can never reach Mailgun.

Usage:
    python3 reprocess_failed.py                              # dry run, from app dir
    ALLOW_REAL_SEND=1 python3 reprocess_failed.py --send     # really send + move
    ALLOW_REAL_SEND=1 python3 reprocess_failed.py --send --throttle 2
"""
import argparse
import os
import shutil
import sys
import time


DEFAULT_SUBJECT = "[reprocessed from failed/]"


def _aggregate_has_failure(report):
    """True if a parsed report would trigger a notification (mirrors the app)."""
    rtype = report.get("report_type")
    rep = report.get("report") or {}
    if rtype == "forensic":
        return True
    if rtype == "aggregate":
        for rec in rep.get("records", []):
            pol = rec.get("policy_evaluated", {})
            if (pol.get("dkim") or "").lower() != "pass" or \
               (pol.get("spf") or "").lower() != "pass":
                return True
    return False


def reprocess(failed_dir, archive_dir, *, send, parsedmarc, mailapp,
              throttle=0.0, received_subject=DEFAULT_SUBJECT, log=print):
    """Core loop. Dependencies (parsedmarc, mailapp) are injected so this is
    fully unit-testable with fakes and never imports the app at module load.

    Returns a counts dict: {sent, would_alert, parseable, errored, moved}.
    Invariant: a file is moved to archive/ ONLY after its notification call
    returns without raising; on any error it is left in failed/ (never lost).
    """
    counts = {"sent": 0, "would_alert": 0, "parseable": 0, "errored": 0, "moved": 0}
    if not os.path.isdir(failed_dir):
        raise FileNotFoundError(failed_dir)
    os.makedirs(archive_dir, exist_ok=True)

    files = sorted(f for f in os.listdir(failed_dir)
                   if os.path.isfile(os.path.join(failed_dir, f)))
    for fn in files:
        src = os.path.join(failed_dir, fn)
        try:
            result = parsedmarc.parse_report_file(src, offline=True)
        except Exception as exc:  # noqa: BLE001 — quarantine stays put
            counts["errored"] += 1
            log(f"STILL-UNPARSEABLE  {fn}\n    {type(exc).__name__}: {exc}")
            continue

        counts["parseable"] += 1
        reports = result if isinstance(result, (list, tuple)) else [result]

        if not send:
            if any(r and _aggregate_has_failure(r) for r in reports):
                counts["would_alert"] += 1
                log(f"     WOULD ALERT  {fn}")
            else:
                log(f"  parses, no fail  {fn}")
            continue

        try:
            for report in reports:
                if report:
                    mailapp.check_pass_fail_unknown(report, src, received_subject)
        except Exception as exc:  # noqa: BLE001 — leave file in failed/, never lose it
            counts["errored"] += 1
            log(f"SEND-ERROR  {fn}\n    {type(exc).__name__}: {exc}")
            continue

        counts["sent"] += 1
        dst = os.path.join(archive_dir, fn)
        try:
            shutil.move(src, dst)
            counts["moved"] += 1
            log(f"PROCESSED  {fn}  -> {archive_dir}/")
        except (OSError, shutil.Error) as exc:
            log(f"  ! sent but could not move {fn} to {archive_dir}/: {exc}")
        if throttle:
            time.sleep(throttle)

    return counts


def real_send_blocked(send):
    """Belt-and-suspenders: a real send requires explicit env opt-in."""
    return bool(send) and os.environ.get("ALLOW_REAL_SEND") != "1"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-dir", default=".")
    ap.add_argument("--failed", default="failed")
    ap.add_argument("--archive", default="archive")
    ap.add_argument("--send", action="store_true",
                    help="actually send emails and move files (default: dry run)")
    ap.add_argument("--throttle", type=float, default=1.0,
                    help="seconds between sends (default: 1.0)")
    args = ap.parse_args(argv)

    if real_send_blocked(args.send):
        print("REFUSING to send: set ALLOW_REAL_SEND=1 to confirm a real run.\n"
              "(This guard exists so a stray --send in CI can't reach Mailgun.)")
        return 1

    app_dir = os.path.abspath(args.app_dir)
    sys.path.insert(0, app_dir)
    os.chdir(app_dir)  # app builds 'archive'/'failed' relative to CWD

    try:
        import parsedmarc
        import app as mailapp
    except Exception as exc:  # noqa: BLE001
        print(f"could not import app from {app_dir}: {exc}\n"
              f"Run this from the app's virtualenv (the one with parsedmarc).")
        return 1

    mode = "SEND" if args.send else "DRY RUN"
    print(f"[{mode}] scanning {args.failed}/\n" + "-" * 60)
    try:
        counts = reprocess(args.failed, args.archive, send=args.send,
                           parsedmarc=parsedmarc, mailapp=mailapp,
                           throttle=args.throttle)
    except FileNotFoundError as exc:
        print(f"no such directory: {exc}")
        return 1

    print("-" * 60)
    if args.send:
        remaining = len([f for f in os.listdir(args.failed)
                         if os.path.isfile(os.path.join(args.failed, f))])
        print(f"sent {counts['sent']}, moved {counts['moved']}, "
              f"errored {counts['errored']}. {args.failed}/ now: {remaining} file(s).")
    else:
        print(f"dry run: {counts['parseable']} parseable "
              f"({counts['would_alert']} would alert), "
              f"{counts['errored']} still-unparseable. "
              f"Re-run with ALLOW_REAL_SEND=1 --send to email + move.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
