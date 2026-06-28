#!/usr/bin/env python3
"""
dmarc_fail_scan.py — scan archived DMARC aggregate reports for DKIM/SPF failures.

Mirrors the notification logic of mailgun-mail-store: a record "fails" if
policy_evaluated/dkim != pass OR policy_evaluated/spf != pass. For each report
that contains at least one failing record, it prints the file, the report
window, and the failing source IPs — i.e. exactly the reports that *should*
have produced a notification email.

No third-party deps (stdlib only), so it runs anywhere Python 3.8+ is present.

Usage:
    python3 dmarc_fail_scan.py /path/to/archive
    python3 dmarc_fail_scan.py /path/to/archive --since 2025-09-20
    python3 dmarc_fail_scan.py /path/to/archive --since 2025-09-20 --quiet-pass
"""
import argparse
import datetime
import gzip
import os
import sys
import zipfile
import xml.etree.ElementTree as ET


def iter_xml_blobs(path):
    """Yield raw XML bytes from a .zip, .xml.gz, or .xml file."""
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
    except Exception as e:  # corrupt/truncated file shouldn't abort the whole run
        print(f"  ! could not open {os.path.basename(path)}: {e}", file=sys.stderr)


def _text(el):
    return (el.text or "").strip() if el is not None else ""


def analyse(xml_bytes):
    """Return (domain, begin_epoch, end_epoch, [failing_records]) for one report."""
    root = ET.fromstring(xml_bytes)
    domain = _text(root.find("./policy_published/domain")) or "unknown"
    begin = _text(root.find("./report_metadata/date_range/begin"))
    end = _text(root.find("./report_metadata/date_range/end"))
    failing = []
    for rec in root.findall("./record"):
        pe = rec.find("./row/policy_evaluated")
        dkim = _text(pe.find("dkim") if pe is not None else None).lower()
        spf = _text(pe.find("spf") if pe is not None else None).lower()
        # Same rule the app uses: fail if either is not exactly "pass".
        if dkim != "pass" or spf != "pass":
            src = _text(rec.find("./row/source_ip")) or "unknown"
            count = _text(rec.find("./row/count")) or "?"
            failing.append((src, count, dkim or "?", spf or "?"))
    return domain, begin, end, failing


def hum_epoch(s):
    try:
        return datetime.datetime.fromtimestamp(
            int(s), datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return s or "?"


def main():
    ap = argparse.ArgumentParser(description="Scan archived DMARC reports for failures.")
    ap.add_argument("archive", help="path to the archive/ directory")
    ap.add_argument("--since", help="only files whose name starts on/after YYYY-MM-DD")
    ap.add_argument("--quiet-pass", action="store_true",
                    help="don't print the all-pass files (default already only prints FAILs)")
    args = ap.parse_args()

    total = scanned = with_fail = 0
    for fn in sorted(os.listdir(args.archive)):
        full = os.path.join(args.archive, fn)
        if not os.path.isfile(full):
            continue
        # filenames are timestamp-prefixed: 2025-09-20T... so a string compare works
        if args.since and fn[:10] < args.since:
            continue
        total += 1
        for blob in iter_xml_blobs(full):
            scanned += 1
            try:
                domain, b, e, failing = analyse(blob)
            except ET.ParseError as ex:
                print(f"  ! XML parse error in {fn}: {ex}", file=sys.stderr)
                continue
            if failing:
                with_fail += 1
                print(f"FAIL  {fn}")
                print(f"      {domain}  {hum_epoch(b)} -> {hum_epoch(e)}")
                for src, count, dkim, spf in failing:
                    print(f"        src={src}  count={count}  dkim={dkim}  spf={spf}")

    print(f"\n{total} files considered, {scanned} reports parsed, "
          f"{with_fail} contained at least one DKIM/SPF FAIL.")
    if with_fail == 0:
        print("=> No failing records in this window. Getting zero notifications is "
              "CORRECT behaviour: nothing was failing DMARC, so there was nothing to "
              "alert on. The pipeline is fine; your mail auth simply got clean.")
    else:
        print("=> These reports SHOULD have triggered notification emails. If you "
              "received none, the break is the OUTBOUND Mailgun send (credential, "
              "plan/quota, or sender), not the report content or the inbound path.")


if __name__ == "__main__":
    main()
