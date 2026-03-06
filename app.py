from flask import Flask, request, Request, abort
from werkzeug.utils import secure_filename
from hashlib import sha256
import hmac
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
app.config.from_pyfile("config.py")

if dsn := app.config.get("GLITCHTIP_DSN"):
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
            report = parsedmarc.parse_report_file(file_path, offline=True)
            # Process the report results and send email if there are any FAIL results
            check_pass_fail_unknown(report, file_path, received_subject)
        except Exception:
            # If parsing fails, move the file to the error (or failed) directory
            error_file_path = os.path.join(error_directory, os.path.basename(file_path))
            shutil.move(file_path, error_file_path)
            logger.exception("Error parsing file %s. Moved to: %s", file_path, error_file_path)

    return 'Ok', 200


def is_valid_request(request: Request) -> bool:
    # Build key string from form parameters; return False if any key is missing
    timestamp = request.form.get("timestamp")
    token = request.form.get("token")
    signature = request.form.get("signature")
    if not timestamp or not token or not signature:
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
    if not date_value:
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


def check_pass_fail_unknown(data, file_path, received_subject):
    """
    Processes an aggregated DMARC report dictionary and sends
    a notification email via the Mailgun API if any record shows a FAIL
    in either DKIM or SPF. The original report file is attached.

    Steps:
      1. Iterate over records in data['report']['records'].
      2. Skip records where both DKIM and SPF are "pass".
      3. Collect details for any record where either DKIM or SPF != "pass".
      4. If at least one failing record is found, build an email:
           - Subject: "detected FAIL in aggregated report for {domain_name}
             from {start_time} to {end_time}"
           - Body: Includes report metadata (file name, received subject),
             then a list of failing records (source IP, DKIM, SPF).
      5. Send the email using the Mailgun API, with the original file attached.
    """
    failing_records = []
    records = data.get('report', {}).get('records', [])

    for record in records:
        policy = record.get('policy_evaluated', {})
        dkim_result = (policy.get('dkim') or '').lower()
        spf_result = (policy.get('spf') or '').lower()
        # Record is failing if either DKIM or SPF is not "pass"
        if dkim_result != 'pass' or spf_result != 'pass':
            failing_records.append(record)

    if not failing_records:
        # All records passed; nothing to notify.
        return

    # Retrieve the domain name from the published policy.
    domain_name = data.get('report', {}).get('policy_published', {}).get('domain', 'unknown')

    # Extract and format time range from the report metadata.
    report_metadata = _safe_get(data, 'report', 'report_metadata', default={})
    _begin = _safe_get(report_metadata, 'begin_date')
    begin_human = _format_report_date(
        _begin if _begin is not None else _safe_get(report_metadata, 'date_range', 'begin')
    )
    _end = _safe_get(report_metadata, 'end_date')
    end_human = _format_report_date(
        _end if _end is not None else _safe_get(report_metadata, 'date_range', 'end')
    )

    # Build the email subject.
    subject = f"detected FAIL in aggregated report for {domain_name} from {begin_human} to {end_human}"

    # Build the email body.
    body_lines = [f"DMARC FAIL detected for domain: {domain_name}", f"Report window: {begin_human} → {end_human}",
                  "", "Failing records:"]
    for record in failing_records:
        _ip = _safe_get(record, 'source', 'ip_address')
        source_ip = _ip if _ip is not None \
            else _safe_get(record, 'row', 'source_ip', default='unknown')
        policy = record.get('policy_evaluated', {})
        dkim = policy.get('dkim', 'unknown')
        spf = policy.get('spf', 'unknown')
        body_lines.append(f"- Source IP: {source_ip}, DKIM: {dkim}, SPF: {spf}")
    body_lines += ["", f"Received subject: {received_subject or 'unknown'}", f"Archived report file: {file_path}"]
    body = "\n".join(body_lines)

    # Retrieve Mailgun configuration from app config.
    mailgun_api_key = app.config["MAILGUN_API_KEY"]
    mailgun_domain = app.config["MAILGUN_DOMAIN"]
    mailgun_sender = app.config.get("MAILGUN_SENDER", f"mailgun@{mailgun_domain}")
    mailgun_recipient = app.config["MAILGUN_RECIPIENT"]

    # Send the email via Mailgun with the file attached.
    # Using 'files' for multipart/form-data ensures the attachment is sent correctly.
    url = f"https://api.eu.mailgun.net/v3/{mailgun_domain}/messages"
    try:
        with open(file_path, "rb") as f:
            files = [
                ("attachment", (os.path.basename(file_path), f, "application/octet-stream"))
            ]
            response = requests.post(
                url,
                auth=("api", mailgun_api_key),
                data={
                    "from": mailgun_sender,
                    "to": mailgun_recipient,
                    "subject": subject,
                    "text": body,
                },
                files=files,
                timeout=20,  # sensible timeout to avoid hanging
            )
    except FileNotFoundError:
        logger.warning("Attachment file not found at %s. Sending email without attachment.", file_path)
        response = requests.post(
            url,
            auth=("api", mailgun_api_key),
            data={
                "from": mailgun_sender,
                "to": mailgun_recipient,
                "subject": subject,
                "text": body,
            },
            timeout=20,
        )

    # Logging the outcome of the email send.
    if response.status_code == 200:
        logger.info("Notification email sent successfully (with attachment if available).")
    else:
        logger.error("Failed to send notification email: %s - %s", response.status_code, response.text)


if __name__ == '__main__':
    # Running in debug mode is useful during development.
    app.run(debug=True)