from flask import Flask, request
from lxml.html.clean import Cleaner

app = Flask(__name__)
cleaner = Cleaner(scripts=True, javascript=True, style=True)
POSTS = []


def sanitize(html):
    return cleaner.clean_html(html)


@app.post("/posts")
def create_post():
    POSTS.append(sanitize(request.form["body"]))
    return {"count": len(POSTS)}
