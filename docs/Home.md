# mailgun-mail-store

A small Python/Flask WSGI service that accepts Mailgun webhook calls, stores
the received DMARC reports and — when authentication failures are detected —
sends notification emails back through Mailgun.

## Wiki pages

| Page | What it covers |
|------|---------------|
| [Installation](Installation.md) | Cloning the repo and installing Python dependencies |
| [Configuration](Configuration.md) | All runtime configuration variables |
| [Testing](Testing.md) | Running the test suite and checking coverage |
| [Linting](Linting.md) | Code-style checks with flake8 |
| [Ubuntu Quickstart](Ubuntu-Quickstart.md) | End-to-end setup on a fresh Ubuntu system |

## How it works

1. Mailgun delivers a DMARC report to the `/mailfetch` endpoint via HTTP POST.
2. The service verifies the Mailgun webhook signature (HMAC-SHA256, replay
   protection within a 300-second window).
3. Each uploaded file is saved to an `archive/` directory.
4. The file is parsed with [parsedmarc](https://domainaware.github.io/parsedmarc/).
   - **Aggregate (RUA)** reports: a notification is sent only when one or more
     records show a DKIM or SPF failure.
   - **Forensic (RUF)** reports: a notification is always sent, because every
     forensic report represents a confirmed authentication failure.
5. Files that cannot be parsed are moved to a `failed/` directory.

## Project links

- Repository: <https://github.com/silpol/mailgun-mail-store>
- Issue tracker: <https://github.com/silpol/mailgun-mail-store/issues>
- License: MIT
