from flask import Flask, request
from jinja2 import Environment, PackageLoader

app = Flask(__name__)
templates = Environment(loader=PackageLoader("blog", "templates"), autoescape=True)
COMMENTS = []


@app.post("/comments")
def add_comment():
    COMMENTS.append(request.form["body"])
    return templates.get_template("comments.html").render(comments=COMMENTS)
