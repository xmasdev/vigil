from flask import Flask, request

from helpers import parse_config

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_settings():
    settings = parse_config(request.get_data(as_text=True))
    return {"keys": list(settings)}
