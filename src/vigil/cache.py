"""Tiny on-disk JSON/text cache so scans and evals are reproducible offline."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

CACHE_DIR = Path(os.environ.get("VIGIL_CACHE", Path.home() / ".cache" / "vigil"))
OFFLINE = os.environ.get("VIGIL_OFFLINE") == "1"


class OfflineMiss(RuntimeError):
    pass


def _path(namespace: str, key: str, suffix: str) -> Path:
    digest = hashlib.sha256(key.encode()).hexdigest()[:24]
    p = CACHE_DIR / namespace / f"{digest}{suffix}"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def cached_json(namespace: str, key: str, fetch: Callable[[], Any]) -> Any:
    p = _path(namespace, key, ".json")
    if p.exists():
        return json.loads(p.read_text())
    if OFFLINE:
        raise OfflineMiss(f"{namespace}:{key} not in cache and VIGIL_OFFLINE=1")
    value = fetch()
    p.write_text(json.dumps(value))
    return value


def cached_text(namespace: str, key: str, fetch: Callable[[], str]) -> str:
    p = _path(namespace, key, ".txt")
    if p.exists():
        return p.read_text()
    if OFFLINE:
        raise OfflineMiss(f"{namespace}:{key} not in cache and VIGIL_OFFLINE=1")
    value = fetch()
    p.write_text(value)
    return value
