"""A small shop backend: product imports, image thumbnails, webhook delivery."""
import io

from flask import Flask, request, send_file

from imports import import_catalog
from images import make_thumbnail
from webhooks import notify

app = Flask(__name__)


@app.post("/admin/catalog")
def upload_catalog():
    products = import_catalog(request.get_data(as_text=True))
    notify("catalog.updated", {"count": len(products)})
    return {"imported": len(products)}


@app.post("/products/<int:pid>/image")
def upload_image(pid):
    thumb = make_thumbnail(request.files["image"])
    return send_file(io.BytesIO(thumb), mimetype="image/png")
