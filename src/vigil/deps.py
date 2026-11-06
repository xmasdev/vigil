"""Dependency resolution: requirements -> pinned closure + package dependency graph.

Deterministic. Uses `uv pip compile` as the resolver so we get exact transitive
versions *without installing anything* (old, vulnerable versions often fail to
build on modern Pythons; we only need their source).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
from packaging.utils import canonicalize_name

ROOT = "<project>"


@dataclass
class Package:
    name: str  # canonical
    version: str
    direct: bool
    via: list[str] = field(default_factory=list)


@dataclass
class Resolution:
    packages: dict[str, Package]
    graph: nx.DiGraph  # edge A -> B means "A depends on B"; ROOT -> direct deps

    def chain_to(self, pkg: str) -> list[str]:
        """Shortest dependency chain from the project to `pkg`."""
        try:
            return nx.shortest_path(self.graph, ROOT, pkg)[1:]
        except nx.NetworkXNoPath:
            return [pkg]

    def packages_between(self, targets: set[str]) -> set[str]:
        """Every package on some path ROOT -> target. These are the libraries whose
        code we must index to follow calls from the app into a vulnerable package."""
        out: set[str] = set()
        for t in targets:
            if t not in self.graph:
                continue
            ancestors = nx.ancestors(self.graph, t) | {t}
            out |= {a for a in ancestors if a != ROOT}
        return out


_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)\s*(?:#\s*via\s+(.*))?$")


def parse_compiled(text: str) -> Resolution:
    packages: dict[str, Package] = {}
    g = nx.DiGraph()
    g.add_node(ROOT)
    for raw in text.splitlines():
        m = _LINE.match(raw.strip())
        if not m:
            continue
        name = canonicalize_name(m.group(1))
        via = [v.strip() for v in (m.group(3) or "").split(",") if v.strip()]
        direct = any(v.startswith("-r ") or v.startswith("-c ") or v == "pyproject.toml" for v in via)
        parents = [canonicalize_name(v) for v in via if not (v.startswith("-") or v.endswith(".toml"))]
        packages[name] = Package(name, m.group(2), direct, parents)
        g.add_node(name)
        if direct:
            g.add_edge(ROOT, name)
        for p in parents:
            g.add_edge(p, name)
    return Resolution(packages, g)


def resolve(project: Path, python_version: str = "3.12") -> Resolution:
    for candidate in ("requirements.txt", "pyproject.toml"):
        src = project / candidate
        if src.exists():
            break
    else:
        raise FileNotFoundError(f"No requirements.txt or pyproject.toml in {project}")
    proc = subprocess.run(
        ["uv", "pip", "compile", src.name, "--python-version", python_version,
         "--annotation-style", "line", "--no-header", "--quiet"],
        cwd=project, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"dependency resolution failed:\n{proc.stderr}")
    return parse_compiled(proc.stdout)
