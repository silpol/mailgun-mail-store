#!/usr/bin/env python3
"""
mailgun_send_test.py — prove the outbound notification path still works.

Fires ONE clearly-labelled test email through the exact same Mailgun EU
endpoint and auth that mailgun-mail-store uses for notifications, then prints
the HTTP status and response body so a silent failure (401/402/403) is
impossible to miss.

It reads the SAME instance/config.py the app uses, so it tests the real
credential — not a copy you might keep in sync by hand.

Usage:
    # from the app's working directory (where instance/config.py lives):
    python3 mailgun_send_test.py
    # or point it explicitly:
    python3 mailgun_send_test.py --config /path/to/instance/config.py
    # override the recipient just for the test:
    python3 mailgun_send_test.py --to you@example.com

Exit code 0 only on HTTP 200; non-zero otherwise, so it's CI/cron friendly.
"""
import argparse
import datetime
import os
import runpy
import sys

import requests


def load_config(path):
    """Execute instance/config.py and return its UPPERCASE module-level names."""
    if not os.path.isfile(path):
        sys.exit(f"config not found: {path}")
    ns = runpy.run_path(path)
    return {k: v for k, v in ns.items() if k.isupper()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join("instance", "config.py"),
                    help="path to instance/config.py (default: ./instance/config.py)")
    ap.add_argument("--to", help="override MAILGUN_RECIPIENT for this test only")
    ap.add_argument("--base-url", default="https://api.eu.mailgun.net/v3",
                    help="Mailgun API base (use https://api.mailgun.net/v3 for US region)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    try:
        api_key = cfg["MAILGUN_API_KEY"]
        domain = cfg["MAILGUN_DOMAIN"]
        recipient = args.to or cfg["MAILGUN_RECIPIENT"]
    except KeyError as e:
        sys.exit(f"missing required config key: {e}")
    sender = cfg.get("MAILGUN_SENDER", f"mailgun@{domain}")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    url = f"{args.base_url}/{domain}/messages"

    print(f"POST {url}")
    print(f"  from: {sender}")
    print(f"  to:   {recipient}")
    print(f"  key:  ...{api_key[-4:]} (len {len(api_key)})")
    print("-" * 60)

    try:
        resp = requests.post(
            url,
            auth=("api", api_key),
            data={
                "from": sender,
                "to": recipient,
                "subject": "[mailgun-mail-store] send-path test — please ignore",
                "text": (
                    "This is a one-off test of the outbound notification path.\n"
                    f"Sent at {now}.\n"
                    "If you are reading this in your inbox, sending works.\n"
                ),
            },
            timeout=20,
        )
    except requests.exceptions.RequestException as exc:
        sys.exit(f"NETWORK ERROR contacting Mailgun: {exc}")

    print(f"HTTP {resp.status_code}")
    print(resp.text.strip())
    print("-" * 60)

    if resp.status_code == 200:
        print("OK — outbound send works. Safe to reprocess failed/.")
        sys.exit(0)
    # Decode the usual silent killers.
    hints = {
        401: "Invalid/expired API key, OR you're passing the webhook SIGNING key, "
             "which is not a valid sending credential. Check Settings > API keys.",
        402: "Payment/plan required — trial expired or quota exhausted.",
        403: "Forbidden — sandbox domain with an unauthorised recipient, or the "
             "key lacks sending rights for this domain.",
        404: "Domain not found at this region/base URL — wrong region "
             "(EU vs US) or wrong MAILGUN_DOMAIN.",
    }
    print("FAILED — this is exactly the silent miss the app would have hidden.")
    if resp.status_code in hints:
        print("Likely cause: " + hints[resp.status_code])
    sys.exit(1)


if __name__ == "__main__":
    main()
