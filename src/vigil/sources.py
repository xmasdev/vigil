"""Fetch the exact source of a dependency version from PyPI (never installed/executed)."""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from .cache import CACHE_DIR, OFFLINE, OfflineMiss, cached_json

SKIP_DIRS = {"tests", "test", "testing", "docs", "doc", "examples", "benchmarks", "build", ".git"}


@dataclass
class SourceTree:
    package: str
    version: str
    root: Path  # directory that contains the top-level import packages/modules
    top_level: list[str]


def _pick_artifact(files: list[dict]) -> dict | None:
    def score(f: dict) -> tuple:
        fn = f["filename"]
        if f["packagetype"] == "bdist_wheel":
            if "py3-none-any" in fn or "py2.py3-none-any" in fn:
                return (0,)
            if "-cp3" in fn or "-py3" in fn:
                return (1,)
            return (3,)  # py2-only wheels may not parse under py3
        if f["packagetype"] == "sdist":
            return (2,)
        return (9,)
    usable = [f for f in files if f["packagetype"] in ("bdist_wheel", "sdist")]
    return min(usable, key=score) if usable else None


def _top_level_in(root: Path) -> list[str]:
    tops = []
    for child in sorted(root.iterdir()):
        if child.name in SKIP_DIRS or child.name.startswith((".", "_")) and child.name != "_yaml":
            continue
        if child.is_dir() and (child / "__init__.py").exists():
            tops.append(child.name)
        elif child.suffix == ".py" and child.name not in ("setup.py", "conftest.py"):
            tops.append(child.stem)
    return tops


def _sdist_root(extracted: Path) -> Path:
    base = next((p for p in extracted.iterdir() if p.is_dir()), extracted)
    for cand in ("lib3", "src", "lib", "."):
        p = (base / cand).resolve()
        if p.is_dir() and any((c / "__init__.py").exists() for c in p.iterdir() if c.is_dir() and c.name not in SKIP_DIRS):
            return p
    return base


def fetch(package: str, version: str) -> SourceTree:
    dest = CACHE_DIR / "src" / f"{package}-{version}"
    marker = dest / ".root"
    if not marker.exists():
        if OFFLINE:
            raise OfflineMiss(f"source for {package}=={version} not cached")
        meta = cached_json("pypi", f"{package}=={version}",
                           lambda: httpx.get(f"https://pypi.org/pypi/{package}/{version}/json", timeout=30).raise_for_status().json())
        art = _pick_artifact(meta["urls"])
        if art is None:
            raise RuntimeError(f"no downloadable artifact for {package}=={version}")
        blob = httpx.get(art["url"], timeout=120, follow_redirects=True).raise_for_status().content
        dest.mkdir(parents=True, exist_ok=True)
        if art["filename"].endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                z.extractall(dest)
            root = dest if art["packagetype"] == "bdist_wheel" else _sdist_root(dest)
        else:
            with tarfile.open(fileobj=io.BytesIO(blob)) as t:
                t.extractall(dest, filter="data")
            root = _sdist_root(dest)
        marker.write_text(str(root))
    root = Path(marker.read_text())
    return SourceTree(package, version, root, _top_level_in(root))
