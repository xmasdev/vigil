from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "change-me"


@app.post("/login")
def login():
    session.permanent = True
    session["user"] = request.form["user"]
    return {"ok": True}


@app.get("/public/news")
def news():
    return {"items": []}
