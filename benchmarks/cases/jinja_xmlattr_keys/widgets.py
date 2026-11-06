from flask import Flask, request
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
env = Environment(loader=FileSystemLoader("templates"), autoescape=True)


@app.get("/widget")
def widget():
    # embed options are passed straight through as HTML attributes
    attrs = {k: v for k, v in request.args.items()}
    return env.get_template("widget.html").render(attrs=attrs)
