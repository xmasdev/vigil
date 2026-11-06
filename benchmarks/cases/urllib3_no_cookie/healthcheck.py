import sys

import urllib3

SERVICES = ["https://status.internal.example/health", "https://db.internal.example/health"]


def check_all():
    http = urllib3.PoolManager()
    return {url: http.request("GET", url, timeout=2.0).status for url in SERVICES}


if __name__ == "__main__":
    results = check_all()
    sys.exit(0 if all(s == 200 for s in results.values()) else 1)
