import urllib3
from flask import Flask, request

app = Flask(__name__)
http = urllib3.PoolManager()


@app.get("/fetch")
def fetch_for_user():
    resp = http.request("GET", request.args["url"], headers={"Cookie": request.headers.get("Cookie", "")},
                        redirect=False)
    return resp.data
