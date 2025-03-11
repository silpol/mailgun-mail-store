from flask import Flask, request, Request
from werkzeug.utils import secure_filename
from hashlib import sha256
import hmac
import datetime
import parsedmarc
import os
import shutil

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile("config.py")


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route('/mailfetch', methods=['POST'])
def receive_post():
    # Directories for storing files
    archive_directory = 'archive'
    error_directory = 'failed'

    # Ensure that required directories exist
    if not os.path.exists(archive_directory):
        os.makedirs(archive_directory)
    if not os.path.exists(error_directory):
        os.makedirs(error_directory)

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
            # Process the report results
            check_pass_fail(report)
            # If processing succeeded, exit the loop (we assume only one file is needed)
            break
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
    return hmac_calculated == signature


def check_pass_fail(data):
    # Iterate over each record in the DMARC report and print evaluation results
    for record in data['report']['records']:
        # Check policy evaluation results for DKIM and SPF
        policy_evaluated = record.get('policy_evaluated', {})
        for key, value in policy_evaluated.items():
            if key in ['dkim', 'spf']:
                print(f"{key.upper()} Policy: {value}")

        # Check authentication results
        auth_results = record.get('auth_results', {})
        for auth_type, results in auth_results.items():
            for result in results:
                print(f"{auth_type.upper()} Result for {result['domain']}: {result['result']}")


if __name__ == '__main__':
    # Running in debug mode is useful for development.
    app.run(debug=True)
