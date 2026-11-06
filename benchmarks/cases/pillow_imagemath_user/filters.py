import io

from flask import Flask, request, send_file
from PIL import Image, ImageMath

app = Flask(__name__)


@app.post("/filter")
def custom_filter():
    img = Image.open(request.files["image"]).convert("L")
    expr = request.form.get("expr", "a")
    out = ImageMath.eval(expr, a=img)
    buf = io.BytesIO()
    out.convert("L").save(buf, "PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
