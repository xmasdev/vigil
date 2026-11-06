"""End-to-end scan workflow.

  resolve deps ─► match advisories ─► fetch sources ─► build call graph
       │                                                    │
       └────────────► per advisory: extract symbols (A) ─► reachability ─► triage agent (B) ─► prioritise
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import deps, osv, sources, symbols
from .agent import Judgment, TriageAgent
from .codegraph import PROJECT, CodeGraph
from .llm import LLM, Tracer
from .reach import find_paths
from .retrieval import Embedder
from .workflow import TriageWorkflow

# final status per finding
STATUS_ORDER = ["exploitable", "needs_review", "trigger_not_met", "input_trusted", "not_reachable", "no_symbols"]
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, None: 4}


@dataclass
class Finding:
    advisory: str
    aliases: list[str]
    package: str
    version: str
    severity: str | None
    summary: str
    fixed_versions: list[str]
    dependency_chain: list[str]
    status: str
    spec: dict[str, Any] | None = None
    paths: list[dict[str, Any]] = field(default_factory=list)
    judgment: dict[str, Any] | None = None

    @property
    def priority(self) -> tuple:
        return (STATUS_ORDER.index(self.status), SEV_RANK.get(self.severity, 4))


@dataclass
class Report:
    project: str
    model: str | None
    findings: list[Finding]
    stats: dict[str, Any]
    graph_stats: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)


def _path_dict(p, agent: TriageAgent | None, cg: CodeGraph) -> dict:
    rel = (agent._rel if agent else (lambda f: f))
    return {"entry": p.entry, "entry_kind": p.entry_kind, "target": p.target, "confidence": p.confidence,
            "nodes": p.nodes,
            "hops": [{"caller": s.caller, "callee": s.callee, "file": rel(s.file), "line": s.lineno,
                      "confidence": s.confidence, "call": s.raw} for s in p.sites]}


def scan(project: Path, *, use_llm: bool = True, run_dir: Path | None = None, only: set[str] | None = None,
         triage: str = "workflow", log=print) -> Report:
    t0 = time.time()
    project = project.resolve()
    tracer = Tracer(run_dir / "trace.jsonl" if run_dir else None)
    llm = LLM(tracer=tracer) if use_llm else None

    with tracer.span("resolve"):
        res = deps.resolve(project)
    with tracer.span("match"):
        advisories = osv.match(res)
    if only:
        advisories = [a for a in advisories if a.display_id in only or a.id in only]
    log(f"{len(res.packages)} packages resolved, {len(advisories)} advisories matched")

    vuln_pkgs = {a.package for a in advisories}
    cg = CodeGraph()
    with tracer.span("graph"):
        cg.add_tree(project, PROJECT)
        for p in sorted(res.packages_between(vuln_pkgs)):
            try:
                st = sources.fetch(p, res.packages[p].version)
                cg.add_tree(st.root, p, st.top_level)
            except Exception as e:  # noqa: BLE001 - a missing source must not kill the scan
                tracer.emit("source_error", package=p, error=str(e))
        cg.build()
    log(f"call graph: {cg.g.number_of_nodes()} nodes, {cg.g.number_of_edges()} edges, "
        f"{len(cg.entry_points())} entry points, {cg.coverage():.0%} calls resolved")

    embedder = Embedder() if use_llm else None
    indexes: dict[str, Any] = {}
    agent = TriageAgent(cg, llm, project) if llm else None
    judge = (TriageWorkflow(agent).judge if triage == "workflow" else agent.judge) if agent else None
    findings: list[Finding] = []

    for adv in advisories:
        with tracer.span("advisory", advisory=adv.display_id, package=adv.package):
            if adv.package not in indexes:
                indexes[adv.package] = symbols.library_index(cg, adv.package, embedder) if use_llm else None
            spec = symbols.extract(cg, adv, llm, indexes[adv.package])
            targets = [q for s in spec.symbols if (q := cg.resolve(s.qualname) or s.qualname) in cg.g]
            paths = find_paths(cg, targets)
            f = Finding(adv.display_id, adv.aliases, adv.package, adv.version, adv.severity, adv.summary,
                        adv.fixed_versions, res.chain_to(adv.package), status="no_symbols",
                        spec=spec.model_dump(), paths=[_path_dict(p, agent, cg) for p in paths])
            if not spec.symbols:
                f.status = "no_symbols"
            elif not paths:
                f.status = "not_reachable"
            elif agent:
                j: Judgment = judge(spec, paths[0], adv.summary)
                f.judgment = j.model_dump()
                f.status = j.verdict
            else:
                f.status = "needs_review"  # reachable, no LLM to judge exploitability
            log(f"  {adv.display_id:<20} {adv.package:<10} {f.status}")
            findings.append(f)

    findings.sort(key=lambda f: f.priority)
    stats = {"seconds": round(time.time() - t0, 1), "packages": len(res.packages), "advisories": len(advisories),
             **{s: sum(f.status == s for f in findings) for s in STATUS_ORDER}, **tracer.totals}
    report = Report(str(project), llm.model if llm else None, findings, stats,
                    {**cg.stats, "nodes": cg.g.number_of_nodes(), "edges": cg.g.number_of_edges(),
                     "coverage": round(cg.coverage(), 3)})
    if run_dir:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "report.json").write_text(report.to_json())
    return report
