from flask import Flask, request
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = Flask(__name__)
env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape())


@app.get("/hello")
def hello():
    page = env.get_template("hello.html")
    return page.render(name=request.args.get("name", "world"))
