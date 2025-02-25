from flask import Flask, request, Request
from werkzeug.utils import secure_filename
from hashlib import sha256
import hmac

app = Flask(__name__, instance_relative_config=True)
app.config.from_pyfile("config.py")


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route('/mailfetch', methods=['POST'])
def receive_post():

    if not is_valid_request(request):
        return 'Unauthorized', 401

    for k, v in request.files.items():
        print(k, v)
        v.save(secure_filename(v.filename))

    return 'Ok', 200

def is_valid_request(request: Request) -> bool:

    timestamp_plus_token = (request.form["timestamp"]+request.form["token"]).encode(encoding="utf-8")
    hmac_calculated =  hmac.new(app.config["MAILGUN_API_KEY"].encode(encoding="utf-8"), timestamp_plus_token, sha256).hexdigest()
    signature = request.form["signature"]
    return (hmac_calculated == signature)

