from flask import Flask, request
from yaml import safe_load

app = Flask(__name__)


@app.route("/lint", methods=["POST"])
def lint():
    data = safe_load(request.data)
    return {"ok": isinstance(data, dict)}
