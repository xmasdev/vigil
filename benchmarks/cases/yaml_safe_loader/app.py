import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/manifest")
def upload_manifest():
    doc = yaml.load(request.get_data(), Loader=yaml.SafeLoader)
    return {"name": doc.get("name")}
