#!/usr/bin/env python3
"""
compare_parsers.py — differential test: dmarc_parser vs parsedmarc on real files.

Run on the server, in the app venv (which still has parsedmarc), before the
app switches parsers (issue #115):

    cd ~/dmarc-handler && .venv/bin/python compare_parsers.py archive/ failed/

For every file it compares what the app's alerting depends on:
  aggregate: report type, policy domain, report window, and the SET of failing
             (source ip, dkim, spf) records  -> decides "alert or not" + body
  failure:   report type, reported domain, auth failures, source ip
Exit 0 = no differences (safe to switch); 1 = differences listed above.
"""
import argparse
import os
import sys

import dmarc_parser


def _reports(result):
    if not result:
        return []
    return list(result) if isinstance(result, (list, tuple)) else [result]


def verdict(result):
    """Reduce a parse result to what the notification logic actually uses."""
    out = []
    for item in _reports(result):
        rtype = item.get("report_type")
        rep = item.get("report") or {}
        if rtype == "aggregate":
            meta = rep.get("report_metadata") or {}
            failing = set()
            for rec in rep.get("records", []):
                pe = rec.get("policy_evaluated") or {}
                dkim = (pe.get("dkim") or "").lower()
                spf = (pe.get("spf") or "").lower()
                if dkim != "pass" or spf != "pass":
                    ip = (rec.get("source") or {}).get("ip_address")
                    failing.add((ip, dkim, spf))
            out.append(("aggregate",
                        ((rep.get("policy_published") or {}).get("domain") or "").lower(),
                        str(meta.get("begin_date")), str(meta.get("end_date")),
                        tuple(sorted(failing))))
        elif rtype in ("failure", "forensic"):
            out.append(("failure", (rep.get("reported_domain") or "").lower(),
                        tuple(sorted(a.lower() for a in rep.get("auth_failure") or [])),
                        (rep.get("source") or {}).get("ip_address")))
        else:
            out.append((rtype,))
    return sorted(out, key=repr)


def run(path, parse):
    try:
        return "ok", verdict(parse(path))
    except Exception as exc:  # noqa: BLE001 - any failure is a data point here
        return "error", f"{type(exc).__name__}: {exc}"[:160]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("dirs", nargs="+", help="directories with report files (archive/, failed/)")
    ap.add_argument("-v", "--verbose", action="store_true", help="also list matching files")
    args = ap.parse_args(argv)

    try:
        import parsedmarc
    except ImportError:
        sys.exit("parsedmarc is not installed in this environment; run inside the app venv")

    def old(p):
        return parsedmarc.parse_report_file(p, offline=True)

    def new(p):
        return dmarc_parser.parse_report_file(p, offline=True)

    counts = {"files": 0, "same": 0, "both_rejected": 0, "different": 0}
    for d in args.dirs:
        for fn in sorted(os.listdir(d)):
            path = os.path.join(d, fn)
            if not os.path.isfile(path):
                continue
            counts["files"] += 1
            o, n = run(path, old), run(path, new)
            if o[0] == n[0] == "error":
                counts["both_rejected"] += 1
                if args.verbose:
                    print(f"both-rejected  {path}\n    {o[1]}\n    {n[1]}")
            elif o == n:
                counts["same"] += 1
                if args.verbose:
                    print(f"same           {path}")
            else:
                counts["different"] += 1
                print(f"DIFFERENT      {path}")
                print(f"    parsedmarc:   {o[0]}: {o[1]}")
                print(f"    dmarc_parser: {n[0]}: {n[1]}")

    print(f"\n{counts['files']} files: {counts['same']} same, "
          f"{counts['both_rejected']} rejected by both, {counts['different']} different.")
    return 1 if counts["different"] else 0


if __name__ == "__main__":
    sys.exit(main())
