"""Step A — advisory -> vulnerable symbols (+ trigger conditions).

Deterministic evidence is gathered first:
  * functions changed by the fix commit (diffparse)
  * public functions in the library that can reach those changed functions (graph)
  * functions whose names/docs match the advisory prose (hybrid retrieval)
The LLM then chooses among *only these candidates* — the JSON schema makes the
qualname field an enum, so it cannot invent symbols that don't exist.
"""

from __future__ import annotations

import re
from typing import Literal

import networkx as nx
from pydantic import BaseModel, Field

from . import diffparse, osv
from .codegraph import CodeGraph
from .llm import LLM, StructuredOutputError
from .retrieval import Doc, Embedder, HybridIndex


class VulnSymbol(BaseModel):
    qualname: str
    trigger: str = Field(description="Exact condition under which calling this is dangerous (args, flags, input)")


class VulnSpec(BaseModel):
    advisory: str
    package: str
    symbols: list[VulnSymbol]
    attacker_input: str = ""
    safe_usage: str = ""
    confidence: Literal["high", "medium", "low"] = "low"
    method: Literal["llm", "diff-only", "none"] = "none"
    changed: list[str] = []
    candidates: list[str] = []


class _LLMOut(BaseModel):
    reasoning: str
    symbols: list[VulnSymbol]
    attacker_input: str
    safe_usage: str
    confidence: Literal["high", "medium", "low"]


def _is_public(qn: str, pkg_modules: set[str]) -> bool:
    return not any(p.startswith("_") and not p.startswith("__") for p in qn.split("."))


def gather_candidates(cg: CodeGraph, adv: osv.Advisory, index: HybridIndex | None) -> tuple[list[str], list[str], dict[str, list[str]]]:
    """-> (changed functions, candidate list, tags per candidate)"""
    tags: dict[str, list[str]] = {}
    changed: list[str] = []
    for url in adv.fix_commits[:3]:
        diff = osv.fetch_diff(url)
        if not diff:
            continue
        for cf in diffparse.changed_functions(cg, diff, adv.package):
            if not cf.qualname.endswith("<module>") and cf.qualname not in changed:
                changed.append(cf.qualname)
                tags.setdefault(cf.qualname, []).append("changed-by-fix")

    pkg_modules = {n for n, m in cg.modules.items() if m.package == adv.package}
    # public API that reaches changed code (within the library)
    for fn in changed:
        if fn not in cg.g:
            continue
        sub = cg.g.reverse(copy=False)
        for anc, dist in nx.single_source_shortest_path_length(sub, fn, cutoff=4).items():
            n = cg.nodes.get(anc)
            if n and n.package == adv.package and n.kind in ("function", "method", "class") \
                    and dist > 0 and _is_public(anc, pkg_modules):
                tags.setdefault(anc, []).append(f"reaches-changed({dist})")

    if index:
        for doc, _ in index.search(f"{adv.summary}\n{adv.details[:1500]}", k=12):
            tags.setdefault(doc.id, []).append("matches-advisory-text")

    def rank(q: str) -> tuple:
        t = tags[q]
        return (-("changed-by-fix" in t) - ("matches-advisory-text" in t), -len(t), q.count("."))
    candidates = sorted(tags, key=rank)[:30]
    return changed, candidates, tags


def library_index(cg: CodeGraph, package: str, embedder: Embedder | None) -> HybridIndex:
    docs = []
    for q, n in cg.nodes.items():
        if n.package == package and n.kind in ("function", "method", "class") and _is_public(q, set()):
            docs.append(Doc(q, f"{q}{n.signature}\n{n.doc}"))
    return HybridIndex(docs, embedder)


SYSTEM = """You are a security engineer doing vulnerability reachability analysis.
Given an advisory for a Python library and candidate functions from that library's source,
identify which functions an APPLICATION would have to call for the vulnerability to be triggered.
Prefer the public entry points named or implied by the advisory (what application code calls),
plus the internal function that contains the flaw if it is a candidate.
For each symbol, state the exact trigger condition (which argument, flag, or input makes it dangerous;
e.g. "Loader is FullLoader or UnsafeLoader", "untrusted URL passed", "always").
Only choose from the candidate list. If none apply, return an empty list with low confidence.
Keep reasoning under 80 words."""


_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def named_in_advisory(adv: osv.Advisory, candidates: list[str], chosen: set[str]) -> list[VulnSymbol]:
    """Recall floor: candidates whose name the advisory literally mentions ("the full_load method
    or the FullLoader loader") are always kept, so the LLM can add symbols but never silently drop
    the obvious ones (a dropped symbol becomes a false 'not reachable')."""
    words = set(_IDENT.findall(f"{adv.summary} {adv.details}"))
    out = []
    for q in candidates:
        leaf = q.rsplit(".", 1)[-1]
        distinctive = "_" in leaf.strip("_") or (leaf[:1].isupper() and any(c.islower() for c in leaf) and sum(c.isupper() for c in leaf) > 1)
        if q not in chosen and leaf in words and distinctive and len(leaf) > 4:
            out.append(VulnSymbol(qualname=q, trigger="named in advisory text"))
    return out


def extract(cg: CodeGraph, adv: osv.Advisory, llm: LLM | None, index: HybridIndex | None) -> VulnSpec:
    changed, candidates, tags = gather_candidates(cg, adv, index)
    base = dict(advisory=adv.display_id, package=adv.package, changed=changed, candidates=candidates)
    if llm is None or not candidates:
        return VulnSpec(**base, symbols=[VulnSymbol(qualname=q, trigger="unknown (changed by fix)") for q in changed],
                        method="diff-only" if changed else "none")

    listing = []
    for q in candidates:
        n = cg.nodes[q]
        doc = n.doc.split("\n")[0][:120] if n.doc else ""
        listing.append(f"- {q}{n.signature[:100]}  [{', '.join(tags[q])}]  {doc}")
    changed_snips = []
    for q in changed[:3]:
        changed_snips.append(f"### {q}\n{cg.source_of(q, max_lines=40)}")
    user = (f"Advisory {adv.display_id} for {adv.package}=={adv.version} (fixed in {', '.join(adv.fixed_versions) or 'n/a'})\n"
            f"Summary: {adv.summary}\nDetails: {adv.details[:2000]}\n\n"
            f"Candidate functions:\n" + "\n".join(listing) +
            ("\n\nVulnerable-version source of functions changed by the fix:\n" + "\n".join(changed_snips) if changed_snips else ""))

    schema = {
        "type": "object",
        "properties": {
            "reasoning": {"type": "string", "maxLength": 600},
            "symbols": {"type": "array", "maxItems": 6, "items": {
                "type": "object",
                "properties": {"qualname": {"type": "string", "enum": candidates},
                               "trigger": {"type": "string", "maxLength": 200}},
                "required": ["qualname", "trigger"]}},
            "attacker_input": {"type": "string", "maxLength": 200},
            "safe_usage": {"type": "string", "maxLength": 200},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        },
        "required": ["reasoning", "symbols", "attacker_input", "safe_usage", "confidence"],
    }

    def validate(o: _LLMOut) -> list[str]:
        errs = [f"{s.qualname} is not a candidate" for s in o.symbols if s.qualname not in candidates]
        if len({s.qualname for s in o.symbols}) != len(o.symbols):
            errs.append("duplicate symbols")
        return errs

    try:
        out = llm.structured([{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                             _LLMOut, schema=schema, validate=validate, purpose=f"symbols:{adv.display_id}",
                             max_tokens=900)
    except StructuredOutputError:
        return VulnSpec(**base, symbols=[VulnSymbol(qualname=q, trigger="unknown") for q in changed]
                        + named_in_advisory(adv, candidates, set(changed)), method="diff-only")
    out.symbols += named_in_advisory(adv, candidates, {s.qualname for s in out.symbols})
    return VulnSpec(**base, symbols=out.symbols, attacker_input=out.attacker_input, safe_usage=out.safe_usage,
                    confidence=out.confidence, method="llm")
