"""Hybrid retrieval: BM25 (lexical) + dense embeddings (llama-server) fused with RRF.

Used to ground the LLM: given an advisory's prose, retrieve the library functions it
most plausibly talks about (names, signatures, docstrings)."""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import dataclass

import httpx
import numpy as np

from .cache import CACHE_DIR

EMBED_URL = os.environ.get("VIGIL_EMBED_URL", "http://localhost:8081/v1/embeddings")
_TOKEN = re.compile(r"[A-Za-z][a-z]+|[A-Z]+(?![a-z])|\d+")


def tokenize(text: str) -> list[str]:
    # split snake_case and CamelCase so "full_load" matches "FullLoader" partially
    return [t.lower() for t in _TOKEN.findall(text.replace("_", " "))]


@dataclass
class Doc:
    id: str
    text: str


class BM25:
    def __init__(self, docs: list[Doc], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.tfs = [Counter(tokenize(d.text)) for d in docs]
        self.lens = [sum(tf.values()) for tf in self.tfs]
        self.avg = sum(self.lens) / max(1, len(self.lens))
        df = Counter(t for tf in self.tfs for t in tf)
        n = len(docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self.k1, self.b = k1, b

    def scores(self, query: str) -> np.ndarray:
        q = tokenize(query)
        out = np.zeros(len(self.docs))
        for i, tf in enumerate(self.tfs):
            s = 0.0
            for t in q:
                if t in tf:
                    f = tf[t]
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.lens[i] / self.avg))
            out[i] = s
        return out


class Embedder:
    """nomic-embed-text via llama-server, with an on-disk vector cache keyed by text hash."""

    def __init__(self, url: str = EMBED_URL):
        self.url = url
        self.dir = CACHE_DIR / "emb"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _key(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:32]

    def embed(self, texts: list[str], prefix: str) -> np.ndarray:
        out: list[np.ndarray | None] = []
        missing: list[int] = []
        for i, t in enumerate(texts):
            p = self.dir / f"{self._key(prefix + t)}.npy"
            if p.exists():
                out.append(np.load(p))
            else:
                out.append(None)
                missing.append(i)
        for start in range(0, len(missing), 32):
            batch = missing[start:start + 32]
            r = httpx.post(self.url, json={"input": [prefix + texts[i][:6000] for i in batch]}, timeout=300)
            r.raise_for_status()
            for i, item in zip(batch, sorted(r.json()["data"], key=lambda d: d["index"])):
                v = np.asarray(item["embedding"], dtype=np.float32)
                v /= np.linalg.norm(v) + 1e-9
                np.save(self.dir / f"{self._key(prefix + texts[i])}.npy", v)
                out[i] = v
        return np.stack(out) if out else np.zeros((0, 768), dtype=np.float32)


class HybridIndex:
    def __init__(self, docs: list[Doc], embedder: Embedder | None = None):
        self.docs = docs
        self.bm25 = BM25(docs)
        self.embedder = embedder
        self.vecs = embedder.embed([d.text for d in docs], "search_document: ") if embedder and docs else None

    def search(self, query: str, k: int = 10, rrf_k: int = 60, mode: str = "hybrid") -> list[tuple[Doc, float]]:
        if not self.docs:
            return []
        rankings = []
        if mode in ("hybrid", "bm25"):
            rankings.append(np.argsort(-self.bm25.scores(query)))
        if mode in ("hybrid", "dense") and self.vecs is not None:
            q = self.embedder.embed([query], "search_query: ")[0]
            rankings.append(np.argsort(-(self.vecs @ q)))
        fused: dict[int, float] = {}
        for ranking in rankings:
            for rank, idx in enumerate(ranking[:200]):
                fused[int(idx)] = fused.get(int(idx), 0.0) + 1.0 / (rrf_k + rank + 1)
        best = sorted(fused.items(), key=lambda kv: -kv[1])[:k]
        return [(self.docs[i], s) for i, s in best]
