from flask import Flask, request, Request
from werkzeug.utils import secure_filename
from hashlib import sha256
import hmac
import datetime
import parsedmarc

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile("config.py")


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route('/mailfetch', methods=['POST'])
def receive_post():

    directory = 'archive'

    if not is_valid_request(request):
        return 'Unauthorized', 401

    for k, v in request.files.items():
        file_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
# assumes directory archive/ exists in current app directory
        filename_for_store = 'archive/' + file_timestamp + '_' + secure_filename(v.filename)
        v.save(filename_for_store)
        report = parsedmarc.parse_report_file(filename_for_store,offline=False)
        check_pass_fail(report)

    return 'Ok', 200

def is_valid_request(request: Request) -> bool:

    timestamp_plus_token = (request.form["timestamp"]+request.form["token"]).encode(encoding="utf-8")
    hmac_calculated =  hmac.new(app.config["MAILGUN_API_KEY"].encode(encoding="utf-8"), timestamp_plus_token, sha256).hexdigest()
    signature = request.form["signature"]
    return (hmac_calculated == signature)

def check_pass_fail(data):
    for record in data['report']['records']:
#        print("Source IP:", record['source']['ip_address'])
        
        # Check policy_evaluated
        policy_evaluated = record['policy_evaluated']
        for key, value in policy_evaluated.items():
            if key in ['dkim', 'spf']:
                print(f"{key.upper()} Policy: {value}")

        # Check auth_results
        auth_results = record['auth_results']
        for auth_type, results in auth_results.items():
            for result in results:
                print(f"{auth_type.upper()} Result for {result['domain']}: {result['result']}")

 #       print("-" * 40)
