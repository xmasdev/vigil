"""Upgrade impact analysis: "if I bump <package> to the fixed version, what breaks?"

1. Deterministic: collect every call site where the app calls into the package, resolve
   each called symbol in the new version, and compare signatures against how it is called
   (removed symbol, removed keyword, too many positionals, new required parameter).
2. RAG + LLM: chunk the changelog between the two versions, retrieve the entries most
   relevant to the APIs the app uses, and let the LLM flag behavioural breaking changes
   that signatures cannot show. Its citations are constrained to real call sites.
3. Optional: install the upgraded set in a throwaway venv and run the project's tests.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel

from . import deps, sources
from .codegraph import PROJECT, CallSite, CodeGraph
from .llm import LLM, StructuredOutputError
from .retrieval import Doc, Embedder, HybridIndex


@dataclass
class Usage:
    symbol: str
    sites: list[CallSite]


@dataclass
class ApiIssue:
    symbol: str
    kind: str        # removed | keyword_removed | too_many_positional | new_required_param | deprecated
    detail: str
    sites: list[str]  # file:line


@dataclass
class UpgradeReport:
    package: str
    from_version: str
    to_version: str
    usages: dict[str, list[str]]
    api_issues: list[ApiIssue]
    changelog_findings: list[dict] = field(default_factory=list)
    risk: str = "low"
    summary: str = ""
    tests: dict | None = None


class _ChangelogImpact(BaseModel):
    reasoning: str
    breaking: list[dict]
    risk: Literal["low", "medium", "high"]
    summary: str


def _graph(project: Path, package: str, version: str) -> CodeGraph:
    st = sources.fetch(package, version)
    cg = CodeGraph()
    cg.add_tree(project, PROJECT)
    cg.add_tree(st.root, package, st.top_level)
    return cg.build()


def usages(cg: CodeGraph, package: str) -> list[Usage]:
    out: dict[str, Usage] = {}
    for u, v, data in cg.g.edges(data=True):
        nu, nv = cg.nodes.get(u), cg.nodes.get(v)
        if nu and nv and nu.package == PROJECT and nv.package == package:
            out.setdefault(v, Usage(v, [])).sites.extend(data["sites"])
    return sorted(out.values(), key=lambda x: x.symbol)


def _check_call(site: CallSite, params: list[str], symbol_kind: str) -> list[tuple[str, str]]:
    if symbol_kind == "class" or not params:
        return []
    names = [p.rstrip("=").removeprefix("kw:") for p in params if not p.startswith("*")]
    has_varkw = any(p.startswith("**") for p in params)
    has_varpos = any(p.startswith("*") and not p.startswith("**") for p in params)
    positional = [p for p in params if not p.startswith(("*", "kw:"))]
    if positional and positional[0].rstrip("=") in ("self", "cls"):
        positional = positional[1:]
    issues = []
    for kw in site.keywords:
        if kw not in names and not has_varkw:
            issues.append(("keyword_removed", f"keyword argument '{kw}' no longer accepted"))
    if len(site.args) > len(positional) and not has_varpos and not any(a.startswith("*") for a in site.args):
        issues.append(("too_many_positional", f"called with {len(site.args)} positional args, new signature takes {len(positional)}"))
    supplied = set(site.keywords) | {p.rstrip("=") for p in positional[:len(site.args)]}
    for p in params:
        bare = p.removeprefix("kw:")
        if not p.startswith("*") and not bare.endswith("=") and bare not in supplied \
                and bare not in ("self", "cls") and not any(a.startswith("*") for a in site.args) \
                and not any(k is None for k in site.keywords):
            issues.append(("new_required_param", f"parameter '{bare}' is required but not passed"))
    return issues


def api_diff(old: CodeGraph, new: CodeGraph, package: str, rel) -> tuple[list[Usage], list[ApiIssue]]:
    used = usages(old, package)
    issues: list[ApiIssue] = []
    for u in used:
        target = new.resolve(u.symbol) or (u.symbol if u.symbol in new.nodes else None)
        sites = [f"{rel(s.file)}:{s.lineno}" for s in u.sites]
        if target is None:
            leaf = u.symbol.rsplit(".", 1)[-1]
            moved = [q for q, n in new.nodes.items() if n.package == package and q.endswith("." + leaf)]
            hint = f" (similar: {', '.join(moved[:3])})" if moved else ""
            issues.append(ApiIssue(u.symbol, "removed", f"no longer exists{hint}", sites))
            continue
        node = new.nodes[target]
        if node.kind == "class":
            init = new.lookup_method(target, "__init__")
            params = new.nodes[init].params if init else []
        else:
            params = node.params
        seen = set()
        for s in u.sites:
            if s.raw.startswith("<runtime>") or "(…" in s.raw:
                continue  # implicit/reference edges carry no real argument list
            for kind, detail in _check_call(s, params, "function"):
                key = (kind, detail)
                if key in seen:
                    continue
                seen.add(key)
                issues.append(ApiIssue(u.symbol, kind, detail,
                                       [f"{rel(x.file)}:{x.lineno}" for x in u.sites if (kind, detail) in _check_call(x, params, "function")]))
        if re.search(r"deprecat", node.doc, re.I):
            issues.append(ApiIssue(u.symbol, "deprecated", node.doc.split("\n")[0][:160], sites))
    return used, issues


_VERSION_HEADER = re.compile(r"^\s*(?:v(?:ersion)?\s*)?(\d+\.\d+(?:\.\d+)?(?:[a-z]+\d*)?)\b", re.I)


def changelog_between(text: str, old: str, new: str) -> list[str]:
    """Split a changelog into per-version sections and keep those in (old, new]."""
    try:
        vo, vn = Version(old), Version(new)
    except InvalidVersion:
        return []
    sections: list[tuple[Version, list[str]]] = []
    for line in text.splitlines():
        m = _VERSION_HEADER.match(line)
        if m and len(line.strip()) < 60:
            try:
                sections.append((Version(m.group(1)), [line]))
                continue
            except InvalidVersion:
                pass
        if sections:
            sections[-1][1].append(line)
    chunks = []
    for v, lines in sections:
        if vo < v <= vn:
            body = "\n".join(lines)
            # split long sections into bullet-sized chunks for retrieval
            parts = re.split(r"\n(?=\s*[-*] )", body)
            chunks += [f"[{v}] {p.strip()}" for p in parts
                       if p.strip() and p.strip() != lines[0].strip() and not set(p.strip()) <= set("=-~^ ")]
    return chunks


SYSTEM = """You assess whether upgrading a Python dependency will break a specific application.
You get: the APIs the application calls (with call sites), deterministic signature-check results, and the
changelog entries between the two versions that are most relevant to those APIs.
Report only changes that affect THIS application's calls (behaviour changes, removed defaults, changed
return values, new exceptions). Ignore changes to APIs it does not use. Be concise."""


def analyse(project: Path, package: str, to_version: str | None = None, llm: LLM | None = None,
            run_tests: bool = False, log=print) -> UpgradeReport:
    project = project.resolve()
    res = deps.resolve(project)
    if package not in res.packages:
        raise ValueError(f"{package} is not a dependency of {project}")
    old_v = res.packages[package].version
    if to_version is None:
        from . import osv
        fixed = [v for a in osv.match(res) if a.package == package for v in a.fixed_versions]
        to_version = str(max((Version(v) for v in fixed), default=Version(old_v)))
    log(f"{package}: {old_v} -> {to_version}")
    rel = lambda f: str(Path(f).resolve().relative_to(project)) if Path(f).resolve().is_relative_to(project) else f
    old_cg, new_cg = _graph(project, package, old_v), _graph(project, package, to_version)
    used, issues = api_diff(old_cg, new_cg, package, rel)
    report = UpgradeReport(package, old_v, to_version,
                           {u.symbol: [f"{rel(s.file)}:{s.lineno}" for s in u.sites] for u in used}, issues)
    log(f"{len(used)} package APIs used by the app, {len(issues)} signature-level issues")

    blocking = {"removed", "keyword_removed", "too_many_positional", "new_required_param"}
    report.risk = "high" if any(i.kind in blocking for i in issues) else "low"

    if llm and used:
        text = sources.fetch_changelog(package, to_version)
        chunks = changelog_between(text, old_v, to_version) if text else []
        log(f"changelog: {len(chunks)} entries between versions")
        relevant: list[str] = []
        if chunks:
            index = HybridIndex([Doc(str(i), c) for i, c in enumerate(chunks)], Embedder())
            seen: set[str] = set()
            for u in used:
                for d, _ in index.search(u.symbol.replace(".", " ") + " " + u.symbol.rsplit(".", 1)[-1], k=4):
                    if d.id not in seen:
                        seen.add(d.id)
                        relevant.append(d.text[:600])
        site_ids = sorted({s for sites in report.usages.values() for s in sites})
        schema = {"type": "object", "properties": {
            "reasoning": {"type": "string", "maxLength": 600},
            "breaking": {"type": "array", "maxItems": 6, "items": {"type": "object", "properties": {
                "api": {"type": "string", "enum": sorted(report.usages)},
                "change": {"type": "string", "maxLength": 300},
                "call_sites": {"type": "array", "items": {"type": "string", "enum": site_ids}},
                "fix": {"type": "string", "maxLength": 300}},
                "required": ["api", "change", "call_sites", "fix"]}},
            "risk": {"type": "string", "enum": ["low", "medium", "high"]},
            "summary": {"type": "string", "maxLength": 400}},
            "required": ["reasoning", "breaking", "risk", "summary"]}
        calls = []
        for u in used:
            for s in u.sites[:3]:
                if not s.raw.startswith("<runtime>"):
                    calls.append(f"- {u.symbol} at {rel(s.file)}:{s.lineno}: {s.raw}({', '.join(s.args + [f'{k}={v}' for k, v in s.keywords.items()])})")
        prompt = (f"Upgrade {package} {old_v} -> {to_version}.\n\nApplication call sites:\n" + "\n".join(calls[:40]) +
                  "\n\nSignature check results:\n" + ("\n".join(f"- {i.symbol}: {i.kind}: {i.detail} at {', '.join(i.sites)}" for i in issues) or "none") +
                  "\n\nRelevant changelog entries:\n" + ("\n\n".join(relevant[:12]) or "(changelog not available)"))
        try:
            out = llm.structured([{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                                 _ChangelogImpact, schema=schema, purpose=f"upgrade:{package}", max_tokens=900)
            report.changelog_findings = out.breaking
            report.summary = out.summary
            order = ["low", "medium", "high"]
            report.risk = max(report.risk, out.risk, key=order.index)
        except StructuredOutputError as e:
            report.summary = f"LLM changelog analysis failed: {e.errors[:1]}"

    if run_tests:
        report.tests = run_project_tests(project, package, to_version, log)
        if report.tests.get("returncode") not in (0, None):
            report.risk = "high"
    return report


def run_project_tests(project: Path, package: str, version: str, log=print) -> dict:
    """Install requirements with the upgraded pin into a throwaway venv and run pytest."""
    req = project / "requirements.txt"
    if not req.exists() or not any(project.rglob("test_*.py")):
        return {"skipped": "no requirements.txt or no tests"}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        lines = [l for l in req.read_text().splitlines() if not re.match(rf"^\s*{re.escape(package)}\b", l, re.I)]
        (tmp / "req.txt").write_text("\n".join(lines + [f"{package}=={version}", "pytest"]) + "\n")
        steps = [["uv", "venv", "-q", str(tmp / "venv")],
                 ["uv", "pip", "install", "-q", "-p", str(tmp / "venv"), "-r", str(tmp / "req.txt")]]
        for cmd in steps:
            p = subprocess.run(cmd, capture_output=True, text=True)
            if p.returncode:
                return {"returncode": p.returncode, "stage": "install", "output": p.stderr[-2000:]}
        log("running tests against upgraded dependencies…")
        p = subprocess.run([str(tmp / "venv" / "bin" / "python"), "-m", "pytest", "-q", "-x"], cwd=project,
                           capture_output=True, text=True, timeout=900)
        return {"returncode": p.returncode, "stage": "pytest", "output": p.stdout[-3000:]}
