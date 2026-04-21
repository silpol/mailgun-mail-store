from flask import Flask, request, Request, abort
from werkzeug.utils import secure_filename
from hashlib import sha256
import hmac
import time
import datetime
import logging
import parsedmarc
import os
import shutil
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import requests  # Used by check_pass_fail_unknown()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile("config.py", silent=True)

if dsn := app.config.get("GLITCHTIP_DSN"):  # pragma: no cover
    sentry_sdk.init(
        dsn=dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
    )


@app.route("/")
def nobody_home():
    abort(404)


@app.route('/mailfetch', methods=['POST'])
def receive_post():
    # Directories for storing files
    archive_directory = 'archive'
    error_directory = 'failed'

    # Create directories with precise permissions
    os.makedirs(archive_directory, mode=0o770, exist_ok=True)
    os.makedirs(error_directory, mode=0o770, exist_ok=True)

    if not is_valid_request(request):
        return 'Unauthorized', 401

    if not request.files:
        return 'Bad request: No files provided', 400

    received_subject = request.form.get('subject')

    for file_key, file_obj in request.files.items():
        # Generate a safe filename with a timestamp for uniqueness
        file_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%S-%f%z")
        safe_filename = secure_filename(file_obj.filename)
        file_path = os.path.join(archive_directory, f"{file_timestamp}_{safe_filename}")
        file_obj.save(file_path)

        try:
            # Process the report using parsedmarc
            result = parsedmarc.parse_report_file(file_path, offline=True)
            if not result:
                logger.warning("parse_report_file returned empty result for %s; skipping.", file_path)
                continue
            # Normalize to a list: parse_report_file may return a single dict
            # or a list/tuple when the file contains multiple reports.
            reports = result if isinstance(result, (list, tuple)) else [result]
            # Process each report and send email if there are any FAIL results
            for report in reports:
                if not report:
                    logger.warning("Skipping empty report entry in %s.", file_path)
                    continue
                check_pass_fail_unknown(report, file_path, received_subject)
        except Exception:
            # If parsing fails, move the file to the error (or failed) directory
            error_file_path = os.path.join(error_directory, os.path.basename(file_path))
            try:
                shutil.move(file_path, error_file_path)
                logger.error(
                    "Error parsing file %s. Moved to: %s", file_path, error_file_path,
                    exc_info=True,
                )
            except (OSError, shutil.Error):
                logger.exception(
                    "Error parsing file %s. Failed to move to error directory %s",
                    file_path, error_file_path,
                )

    return 'Ok', 200


def is_valid_request(request: Request, max_age: int = 300) -> bool:
    # Build key string from form parameters; return False if any key is missing
    timestamp = request.form.get("timestamp")
    token = request.form.get("token")
    signature = request.form.get("signature")
    if not timestamp or not token or not signature:
        return False
    # Replay protection: reject requests whose timestamp is outside the allowed window
    try:
        request_time = int(timestamp)
    except ValueError:
        return False
    if abs(int(time.time()) - request_time) > max_age:
        return False
    timestamp_plus_token = (timestamp + token).encode("utf-8")
    hmac_calculated = hmac.new(
        app.config["MAILGUN_API_KEY"].encode("utf-8"),
        timestamp_plus_token,
        sha256
    ).hexdigest()
    # Secure comparison using a timing-attack resistant method
    return hmac.compare_digest(hmac_calculated, signature)


def _safe_get(d, *keys, default=None):
    """Safely traverse nested dicts.

    Returns *default* if any intermediate value is missing or not a dict.
    """
    for key in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
        if d is None:
            return default
    return d if d is not None else default


def _format_report_date(date_value):
    """
    Formats a report date into a human-readable UTC string.
    Handles epoch ints/floats, datetime instances, and arbitrary string-like values.
    """
    if date_value is None or date_value == "":
        return "unknown"

    if isinstance(date_value, (int, float)):
        # timezone-aware UTC and Z-suffix
        return datetime.datetime.fromtimestamp(date_value, tz=datetime.timezone.utc) \
                                .isoformat().replace("+00:00", "Z")

    if isinstance(date_value, datetime.datetime):
        # ensure timezone-aware UTC, keep Z-suffix
        dt_utc = date_value.astimezone(datetime.timezone.utc) if date_value.tzinfo \
                 else date_value.replace(tzinfo=datetime.timezone.utc)
        return dt_utc.isoformat().replace("+00:00", "Z")

    # Fallback for strings or other types
    return str(date_value)


def _send_notification_email(subject, body, file_path):
    """Sends a notification email via the Mailgun API with the report file attached."""
    mailgun_api_key = app.config["MAILGUN_API_KEY"]
    mailgun_domain = app.config["MAILGUN_DOMAIN"]
    mailgun_sender = app.config.get("MAILGUN_SENDER", f"mailgun@{mailgun_domain}")
    mailgun_recipient = app.config["MAILGUN_RECIPIENT"]
    url = f"https://api.eu.mailgun.net/v3/{mailgun_domain}/messages"
    email_data = {
        "from": mailgun_sender,
        "to": mailgun_recipient,
        "subject": subject,
        "text": body,
    }
    try:
        try:
            with open(file_path, "rb") as f:
                response = requests.post(
                    url,
                    auth=("api", mailgun_api_key),
                    data=email_data,
                    files=[("attachment", (os.path.basename(file_path), f, "application/octet-stream"))],  # noqa: E501
                    timeout=20,
                )
        except FileNotFoundError:
            logger.warning("Attachment file not found at %s. Sending email without attachment.", file_path)
            response = requests.post(
                url,
                auth=("api", mailgun_api_key),
                data=email_data,
                timeout=20,
            )
    except requests.exceptions.Timeout:
        logger.error("Mailgun request timed out for notification email: %s.", file_path)
        return
    except requests.exceptions.RequestException as exc:
        logger.error("Failed to contact Mailgun for notification email %s: %s", file_path, exc)
        return
    if response.status_code == 200:
        logger.info("Notification email sent successfully (with attachment if available).")
    else:
        logger.error("Failed to send notification email: %s - %s", response.status_code, response.text)


def _check_aggregate_report(report, file_path, received_subject):
    """Checks an aggregate DMARC report (RUA) for DKIM/SPF failures and notifies if found."""
    failing_records = []
    for record in report.get('records', []):
        policy = record.get('policy_evaluated', {})
        dkim_result = (policy.get('dkim') or '').lower()
        spf_result = (policy.get('spf') or '').lower()
        # Record is failing if either DKIM or SPF is not "pass"
        if dkim_result != 'pass' or spf_result != 'pass':
            failing_records.append(record)

    if not failing_records:
        # All records passed; nothing to notify.
        return

    domain_name = report.get('policy_published', {}).get('domain', 'unknown')

    report_metadata = _safe_get(report, 'report_metadata', default={})
    _begin = _safe_get(report_metadata, 'begin_date')
    begin_human = _format_report_date(
        _begin if _begin is not None else _safe_get(report_metadata, 'date_range', 'begin')
    )
    _end = _safe_get(report_metadata, 'end_date')
    end_human = _format_report_date(
        _end if _end is not None else _safe_get(report_metadata, 'date_range', 'end')
    )

    subject = (
        f"detected FAIL in aggregate DMARC report for {domain_name}"
        f" from {begin_human} to {end_human}"
    )
    body_lines = [
        f"DMARC FAIL detected for domain: {domain_name}",
        f"Report window: {begin_human} \u2192 {end_human}",
        "",
        "Failing records:",
    ]
    for record in failing_records:
        _ip = _safe_get(record, 'source', 'ip_address')
        source_ip = (
            _ip if _ip is not None
            else _safe_get(record, 'row', 'source_ip', default='unknown')
        )
        policy = record.get('policy_evaluated', {})
        dkim = policy.get('dkim', 'unknown')
        spf = policy.get('spf', 'unknown')
        body_lines.append(f"- Source IP: {source_ip}, DKIM: {dkim}, SPF: {spf}")
    body_lines += [
        "",
        f"Received subject: {received_subject or 'unknown'}",
        f"Archived report file: {file_path}",
    ]
    _send_notification_email(subject, "\n".join(body_lines), file_path)


def _notify_forensic_report(report, file_path, received_subject):
    """Sends a notification for a forensic DMARC failure report (RUF).

    Every forensic report represents a confirmed authentication failure,
    so a notification is always sent.
    """
    domain_name = report.get('reported_domain', 'unknown')
    arrival_date = report.get('arrival_date_utc') or report.get('arrival_date', 'unknown')
    auth_failure = report.get('auth_failure', [])
    source_ip = _safe_get(report, 'source', 'ip_address', default='unknown')
    delivery_result = report.get('delivery_result', 'unknown')

    subject = f"detected FAIL in forensic DMARC report for {domain_name} on {arrival_date}"
    failure_str = ', '.join(auth_failure) if auth_failure else 'unknown'
    body_lines = [
        f"DMARC forensic failure report for domain: {domain_name}",
        f"Arrival date (UTC): {arrival_date}",
        f"Auth failures: {failure_str}",
        f"Source IP: {source_ip}",
        f"Delivery result: {delivery_result}",
        "",
        f"Received subject: {received_subject or 'unknown'}",
        f"Archived report file: {file_path}",
    ]
    _send_notification_email(subject, "\n".join(body_lines), file_path)


def check_pass_fail_unknown(data, file_path, received_subject):
    """
    Dispatches a parsed DMARC report to the appropriate notification handler.

    Handles two DMARC report types:
    - ``aggregate`` (RUA): Checks each record's policy_evaluated results; sends
      a notification only if any record shows a DKIM or SPF failure.
    - ``forensic`` (RUF): Sends a notification for every forensic report received,
      as each one already represents a confirmed authentication failure.

    Args:
        data: Parsed report dict from ``parsedmarc.parse_report_file``, containing
              ``report_type`` (``"aggregate"`` or ``"forensic"``) and ``report`` keys.
        file_path: Path to the archived report file, attached to the notification email.
        received_subject: The email subject from the original Mailgun webhook.
    """
    report_type = data.get('report_type')
    report = data.get('report') or {}
    if report_type is None:
        logger.warning("Received report with missing report_type; skipping notification.")
    elif report_type == 'aggregate':
        _check_aggregate_report(report, file_path, received_subject)
    elif report_type == 'forensic':
        _notify_forensic_report(report, file_path, received_subject)
    else:
        logger.debug("Skipping notification for unsupported report type: %s", report_type)


if __name__ == '__main__':  # pragma: no cover
    # Enable debug only when explicitly requested via environment.
    debug_mode = os.getenv("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
    app.run(debug=debug_mode)