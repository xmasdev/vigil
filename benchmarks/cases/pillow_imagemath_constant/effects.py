import io

from flask import Flask, request, send_file
from PIL import Image, ImageMath

app = Flask(__name__)
DARKEN = "convert(a * 0.5, 'L')"


def darken(img):
    return ImageMath.eval(DARKEN, a=img)


@app.post("/darken")
def darken_upload():
    img = Image.open(request.files["image"]).convert("L")
    buf = io.BytesIO()
    darken(img).save(buf, "PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
