import io

from flask import Flask, request, send_file
from PIL import Image

app = Flask(__name__)


@app.post("/thumbnail")
def thumbnail():
    img = Image.open(request.files["image"])
    img.thumbnail((256, 256))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
