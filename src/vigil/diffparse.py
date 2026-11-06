"""Map a fix commit's unified diff onto functions in the *vulnerable* version's source.

Line numbers in the diff refer to the parent commit, which rarely equals the released
version we analyse, so hunks are anchored by searching for their distinctive old-side
lines in the vulnerable file, then mapped to the enclosing function via the graph."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .codegraph import CodeGraph

_FILE = re.compile(r"^diff --git a/(\S+) b/(\S+)")
_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@ ?(.*)")
_TESTY = re.compile(r"(^|/)(tests?|testing|docs?|examples?|benchmarks?)/|(^|/)test_[^/]*\.py$|_test\.py$|conftest\.py$")


@dataclass
class Hunk:
    path: str
    header: str
    old_lines: list[str] = field(default_factory=list)   # context + removed
    removed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)


@dataclass
class ChangedFunction:
    qualname: str
    removed: list[str]
    added: list[str]


def parse(diff: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    path = None
    cur: Hunk | None = None
    for line in diff.splitlines():
        if m := _FILE.match(line):
            path = m.group(2)
            cur = None
        elif (m := _HUNK.match(line)) and path:
            cur = Hunk(path, m.group(3))
            hunks.append(cur)
        elif cur is not None:
            if line.startswith("-") and not line.startswith("---"):
                cur.removed.append(line[1:])
                cur.old_lines.append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                cur.added.append(line[1:])
            elif line.startswith(" "):
                cur.old_lines.append(line[1:])
    return [h for h in hunks if h.path.endswith(".py") and not _TESTY.search(h.path)]


def _module_for(cg: CodeGraph, path: str, package: str) -> str | None:
    parts = path[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    for i in range(len(parts)):
        name = ".".join(parts[i:])
        m = cg.modules.get(name)
        if m and m.package == package:
            return name
    return None


def changed_functions(cg: CodeGraph, diff: str, package: str) -> list[ChangedFunction]:
    out: dict[str, ChangedFunction] = {}
    for h in parse(diff):
        mod = _module_for(cg, h.path, package)
        if not mod:
            continue
        lines = cg.modules[mod].source.splitlines()
        anchors = sorted({l.strip() for l in (h.removed or h.old_lines) if len(l.strip()) > 12}, key=len, reverse=True)
        hit_lines: list[int] = []
        for a in anchors[:4]:
            hit_lines += [i + 1 for i, l in enumerate(lines) if l.strip() == a]
        fn = None
        if hit_lines:
            fn = _enclosing(cg, mod, hit_lines[0])
        if fn is None and (m := re.search(r"def (\w+)", h.header)):
            fn = next((q for q, n in cg.nodes.items() if q.startswith(mod + ".") and q.endswith("." + m[1])), None)
        if fn is None and (m := re.search(r"class (\w+)", h.header)):
            fn = f"{mod}.{m[1]}" if f"{mod}.{m[1]}" in cg.nodes else None
        if fn is None:
            fn = f"{mod}.<module>"
        cf = out.setdefault(fn, ChangedFunction(fn, [], []))
        cf.removed += h.removed
        cf.added += h.added
    return list(out.values())


def _enclosing(cg: CodeGraph, module: str, line: int) -> str | None:
    best = None
    for q, n in cg.nodes.items():
        if n.kind in ("function", "method", "class") and q.startswith(module + ".") \
                and n.lineno <= line <= n.end_lineno:
            if best is None or n.end_lineno - n.lineno < cg.nodes[best].end_lineno - cg.nodes[best].lineno:
                best = q
    return best
