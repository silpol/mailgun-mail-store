from flask import Flask, request, Request, abort
from werkzeug.utils import secure_filename
from hashlib import sha256
import hmac
import datetime
import parsedmarc
import os
import shutil
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import requests  # Used later in check_pass_fail_unknown()

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile("config.py")

sentry_sdk.init(
    dsn=app.config["GLITCHTIP_DSN"],
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
    # (if needed, add mode/chmod calls)
    os.makedirs(archive_directory, mode=0o770, exist_ok=True)
    # os.chmod(archive_directory, 0o770)
    os.makedirs(error_directory, mode=0o770, exist_ok=True)
    # os.chmod(error_directory, 0o770)

    if not is_valid_request(request):
        return 'Unauthorized', 401

    for file_key, file_obj in request.files.items():
        # Generate a safe filename with a timestamp
        # for uniqueness and traceability
        file_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        safe_filename = secure_filename(file_obj.filename)
        file_path = os.path.join(archive_directory, f"{file_timestamp}_{safe_filename}")
        file_obj.save(file_path)

        try:
            # Process the report using parsedmarc
            report = parsedmarc.parse_report_file(file_path, offline=False)
            # Process the report results and send email if there are any FAIL results
            check_pass_fail_unknown(report)
        except Exception as e:
            # If parsing fails, move the file to the error (or failed) directory
            error_file_path = os.path.join(error_directory, os.path.basename(file_path))
            shutil.move(file_path, error_file_path)
            print(f"Error parsing file {file_path}. Exception: {e}. Moved to: {error_file_path}")

    return 'Ok', 200


def is_valid_request(request: Request) -> bool:
    # Build key string from form parameters
    timestamp_plus_token = (request.form["timestamp"] + request.form["token"]).encode("utf-8")
    hmac_calculated = hmac.new(
        app.config["MAILGUN_API_KEY"].encode("utf-8"),
        timestamp_plus_token,
        sha256
    ).hexdigest()
    signature = request.form["signature"]
    # Secure comparison using a timing-attack resistant method
    return hmac.compare_digest(hmac_calculated, signature)


def check_pass_fail_unknown(data):
    """
    Processes an aggregated DMARC report dictionary and sends
    a notification email via the Mailgun API
    if any record shows a FAIL in either DKIM or SPF.

    It does the following:
      1. Iterates over each record in data['report']['records'].
      2. Skips records where both DKIM and SPF are evaluated as "pass".
      3. Collects details for any record where either DKIM or SPF is not "pass".
      4. If at least one failing record is found, it builds an email:
           - Subject: "detected FAIL in aggregated report {domain_name} {start_time - end_time}"
             where the times are converted to human-readable form.
           - Body: Contains a line for each failing record with details
             like source IP, DKIM, and SPF results.
      5. Sends the email using the Mailgun API.

    The function expects the following structure in the data:
      - data['policy_published'] with key 'domain'
      - data['report_metadata'] with key 'date_range' containing 'begin' and 'end' timestamps
      - data['report']['records']: list of records, each having a 'policy_evaluated' dict
    """
    failing_records = []
    records = data.get('report', {}).get('records', [])

    for record in records:
        policy = record.get('policy_evaluated', {})
        dkim_result = policy.get('dkim', '').lower()
        spf_result = policy.get('spf', '').lower()
        # Skip record if both DKIM and SPF are "pass"; otherwise, mark it as failing.
        if dkim_result != 'pass' or spf_result != 'pass':
            failing_records.append(record)

    if not failing_records:
        # All records are passing the policies; nothing to notify.
        return

    # Retrieve the domain name from the published policy.
    domain_name = data.get('policy_published', {}).get('domain', 'unknown')

    # Extract and format time range from the report metadata.
    date_range = data.get('report_metadata', {}).get('date_range', {})
    begin_timestamp = date_range.get('begin')
    end_timestamp = date_range.get('end')
    if begin_timestamp and end_timestamp:
        begin_human = datetime.datetime.fromtimestamp(begin_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        end_human = datetime.datetime.fromtimestamp(end_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    else:
        begin_human = "unknown"
        end_human = "unknown"

    # Build the email subject.
    subject = f"detected FAIL in aggregated report {domain_name} {begin_human} - {end_human}"

    # Build the email body with details for each failing record.
    body_lines = []
    for record in failing_records:
        source_ip = record.get('source', {}).get('ip_address', 'unknown')
        policy = record.get('policy_evaluated', {})
        dkim = policy.get('dkim', 'unknown')
        spf = policy.get('spf', 'unknown')
        body_lines.append(f"Source IP: {source_ip}, DKIM: {dkim}, SPF: {spf}")
    body = "\n".join(body_lines)

    # Retrieve Mailgun configuration from app config.
    MAILGUN_API_KEY = app.config["MAILGUN_API_KEY"]
    MAILGUN_DOMAIN = app.config["MAILGUN_DOMAIN"]
    MAILGUN_SENDER = app.config.get("MAILGUN_SENDER", f"mailgun@{MAILGUN_DOMAIN}")
    MAILGUN_RECIPIENT = app.config["MAILGUN_RECIPIENT"]

    # Send the email via Mailgun
    response = requests.post(
        f"https://api.eu.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
        auth=("api", MAILGUN_API_KEY),
        data={
            "from": MAILGUN_SENDER,
            "to": MAILGUN_RECIPIENT,
            "subject": subject,
            "text": body
        }
    )

    # Logging the outcome of the email send.
    if response.status_code == 200:
        print("Notification email sent successfully.")
    else:
        print(f"Failed to send notification email: {response.status_code} - {response.text}")


if __name__ == '__main__':
    # Running in debug mode is useful during development.
    app.run(debug=True)
