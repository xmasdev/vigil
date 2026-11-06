import requests

WEBHOOK_URL = "https://hooks.internal.example/shop"


def notify(event, payload):
    requests.post(WEBHOOK_URL, json={"event": event, **payload}, timeout=5)
