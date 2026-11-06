"""Deterministic reachability: entry points -> vulnerable symbols over the call graph."""

from __future__ import annotations

import heapq
from dataclasses import dataclass

from .codegraph import CONF_RANK, CallSite, CodeGraph

ENTRY_PRIORITY = {"http": 0, "task": 1, "cli": 2, "main": 3, "import": 4}


@dataclass
class Path:
    entry: str
    entry_kind: str
    target: str
    nodes: list[str]
    sites: list[CallSite]  # one representative call site per hop
    confidence: str        # weakest edge

    def render(self) -> str:
        lines = [f"[{self.entry_kind}] {self.entry}"]
        for site in self.sites:
            lines.append(f"  → {site.callee}   ({site.file.rsplit('/', 1)[-1]}:{site.lineno}, {site.confidence})")
        return "\n".join(lines)


def find_paths(cg: CodeGraph, targets: list[str], max_paths: int = 3) -> list[Path]:
    """Best paths (strongest confidence, then shortest) from any entry point to any target.

    Dijkstra on cost = (confidence rank of weakest edge, hops), run backwards from the
    targets so one search covers all entry points."""
    targets = [t for t in targets if t in cg.g]
    if not targets:
        return []
    entries = {q: cg.nodes[q].entry for q in cg.entry_points()}
    rg = cg.g.reverse(copy=False)

    best: dict[str, tuple[int, int]] = {}
    nxt: dict[str, str] = {}          # node -> next node towards target
    heap = [((0, 0), t, None) for t in targets]
    while heap:
        (conf, hops), node, succ = heapq.heappop(heap)
        if node in best:
            continue
        best[node] = (conf, hops)
        if succ is not None:
            nxt[node] = succ
        for pred in rg.successors(node):
            if pred in best:
                continue
            ec = CONF_RANK[cg.g.edges[pred, node]["confidence"]]
            heapq.heappush(heap, ((max(conf, ec), hops + 1), pred, node))

    found = sorted((best[e] + (ENTRY_PRIORITY.get(k, 9),), e) for e, k in entries.items() if e in best and e not in targets)
    out: list[Path] = []
    for (conf, hops, _), entry in found[:max_paths]:
        nodes = [entry]
        while nodes[-1] in nxt:
            nodes.append(nxt[nodes[-1]])
        sites = [min(cg.g.edges[a, b]["sites"], key=lambda s: CONF_RANK[s.confidence]) for a, b in zip(nodes, nodes[1:])]
        out.append(Path(entry, entries[entry], nodes[-1], nodes, sites, [k for k, v in CONF_RANK.items() if v == conf][0]))
    return out
