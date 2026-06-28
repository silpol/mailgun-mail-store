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

It imports the app's OWN functions (check_pass_fail_unknown / _send_notification_email)
so the emails are byte-for-byte what the live app produces — no reimplementation
to drift out of sync.

SAFETY:
  * Run mailgun_send_test.py first and confirm HTTP 200. If outbound is dead,
    this will "succeed" while sending nothing.
  * Default is a DRY RUN: it parses and reports what it WOULD send, sends
    nothing, moves nothing. Add --send to actually email + move.
  * --throttle adds a delay between sends to stay polite to Mailgun.

Usage:
    python3 reprocess_failed.py                      # dry run, from app dir
    python3 reprocess_failed.py --send               # really send + move
    python3 reprocess_failed.py --send --throttle 2  # 2s between reports
    python3 reprocess_failed.py --app-dir /srv/app --failed failed --archive archive
"""
import argparse
import os
import shutil
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-dir", default=".",
                    help="directory containing app.py + instance/config.py (default: .)")
    ap.add_argument("--failed", default="failed", help="quarantine dir (default: failed)")
    ap.add_argument("--archive", default="archive", help="archive dir (default: archive)")
    ap.add_argument("--send", action="store_true",
                    help="actually send emails and move files (default: dry run)")
    ap.add_argument("--throttle", type=float, default=1.0,
                    help="seconds to sleep between reports when sending (default: 1.0)")
    args = ap.parse_args()

    app_dir = os.path.abspath(args.app_dir)
    sys.path.insert(0, app_dir)
    # The app builds paths relative to CWD ('archive', 'failed'), so run from app_dir.
    os.chdir(app_dir)

    try:
        import parsedmarc  # noqa: F401  (import surfaced early for a clean error)
        import app as mailapp
    except Exception as exc:
        sys.exit(f"could not import app from {app_dir}: {exc}\n"
                 f"Run this from the app's virtualenv (the one with parsedmarc et al).")

    failed_dir = args.failed
    archive_dir = args.archive
    if not os.path.isdir(failed_dir):
        sys.exit(f"no such directory: {failed_dir}")
    os.makedirs(archive_dir, exist_ok=True)

    files = sorted(f for f in os.listdir(failed_dir)
                   if os.path.isfile(os.path.join(failed_dir, f)))
    if not files:
        print("failed/ is empty — nothing to do.")
        return

    mode = "SEND" if args.send else "DRY RUN"
    print(f"[{mode}] {len(files)} file(s) in {failed_dir}/\n" + "-" * 60)

    sent = skipped = errored = 0
    for fn in files:
        src = os.path.join(failed_dir, fn)
        try:
            result = parsedmarc.parse_report_file(src, offline=True)
        except Exception as exc:
            errored += 1
            print(f"STILL-UNPARSEABLE  {fn}\n    {type(exc).__name__}: {exc}")
            continue

        reports = result if isinstance(result, (list, tuple)) else [result]
        # The subject the original webhook carried is long gone; pass a marker.
        received_subject = "[reprocessed from failed/]"

        if args.send:
            try:
                for report in reports:
                    if report:
                        mailapp.check_pass_fail_unknown(report, src, received_subject)
            except Exception as exc:
                errored += 1
                print(f"SEND-ERROR  {fn}\n    {type(exc).__name__}: {exc}")
                continue
            dst = os.path.join(archive_dir, fn)
            try:
                shutil.move(src, dst)
            except (OSError, shutil.Error) as exc:
                print(f"  ! sent but could not move {fn} to archive/: {exc}")
            sent += 1
            print(f"PROCESSED  {fn}  -> archive/")
            if args.throttle:
                time.sleep(args.throttle)
        else:
            # Dry run: just say whether it parses and whether it'd alert.
            would_alert = False
            for report in reports:
                if not report:
                    continue
                rtype = report.get("report_type")
                rep = report.get("report") or {}
                if rtype == "forensic":
                    would_alert = True
                elif rtype == "aggregate":
                    for rec in rep.get("records", []):
                        pol = rec.get("policy_evaluated", {})
                        if (pol.get("dkim") or "").lower() != "pass" or \
                           (pol.get("spf") or "").lower() != "pass":
                            would_alert = True
                            break
            tag = "WOULD ALERT" if would_alert else "parses, no fail"
            skipped += 1
            print(f"{tag:>16}  {fn}")

    print("-" * 60)
    if args.send:
        print(f"sent {sent}, errored {errored}. failed/ now: "
              f"{len(os.listdir(failed_dir))} file(s).")
    else:
        print(f"dry run: {skipped} parseable, {errored} still-unparseable. "
              f"Re-run with --send to email and move them.")


if __name__ == "__main__":
    main()
