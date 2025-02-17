from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.from_pyfile("config.py")


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route('/mailfetch', methods=['POST'])
def receive_post()

    for k, v in request.files.items():
        print(k, v)
        v.save(secure_filename(v.filename))

    return 'Ok', 200

