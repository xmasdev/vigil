import io

from PIL import Image


def make_thumbnail(upload):
    img = Image.open(upload)
    img.thumbnail((320, 320))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()
