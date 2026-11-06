"""Benchmark harness.

Each case in benchmarks/cases/<name>/ is a small application plus labels.json giving,
for selected advisories, whether the app is truly affected. Only labeled advisories are
scored (every config, including the scanner baseline, sees the same set).

Configs (ablation ladder):
  scanner    flag every matched advisory                     (what pip-audit/Dependabot do)
  reach-diff fix-commit diff symbols + call-graph reachability (no LLM)
  reach-llm  LLM-extracted symbols + reachability             (LLM step A only)
  workflow   + structured triage workflow                      (A + B, default)
  agent      + free-form tool-using triage agent               (A + B')

Primary metrics: recall on truly affected (must stay ~1.0 — a missed exploitable vuln is
the costly error) and alert reduction (share of not-affected alerts suppressed).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from . import osv, sources, symbols
from .codegraph import CodeGraph
from .llm import LLM
from .pipeline import scan
from .retrieval import Embedder

FLAGGED = {"exploitable", "needs_review", "no_symbols"}
CONFIGS = ["scanner", "reach-diff", "reach-llm", "workflow", "agent"]


@dataclass
class Row:
    case: str
    advisory: str
    gold_affected: bool
    gold_reason: str
    status: str
    symbol_hit: bool | None
    evidence_verified: bool | None

    @property
    def pred_affected(self) -> bool:
        return self.status in FLAGGED


def _symbol_hit(spec: dict | None, gold: list[str] | None) -> bool | None:
    if not gold or spec is None:
        return None
    return any(s["qualname"].startswith(g) for s in spec["symbols"] for g in gold)


def run_config(cases_dir: Path, config: str, gold_symbols: dict, log=print) -> dict:
    rows: list[Row] = []
    totals = {"llm_calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "seconds": 0.0}
    for case in sorted(p for p in cases_dir.iterdir() if (p / "labels.json").exists()):
        labels = json.loads((case / "labels.json").read_text())["labels"]
        if config == "scanner":
            rows += [Row(case.name, a, l["affected"], l["reason"], "exploitable", None, None) for a, l in labels.items()]
            continue
        t0 = time.time()
        report = scan(case, use_llm=config != "reach-diff", only=set(labels),
                      triage={"reach-llm": "none", "reach-diff": "none"}.get(config, config),
                      run_dir=case / ".vigil" / "eval" / config, log=lambda m: None)
        totals["seconds"] += time.time() - t0
        for k in ("llm_calls", "prompt_tokens", "completion_tokens"):
            totals[k] += report.stats.get(k, 0)
        by_id = {f.advisory: f for f in report.findings}
        for adv, l in labels.items():
            f = by_id.get(adv)
            if f is None:
                log(f"  !! {case.name}: {adv} not matched by OSV")
                continue
            ev = f.judgment.get("evidence_verified") if f.judgment else None
            rows.append(Row(case.name, adv, l["affected"], l["reason"], f.status,
                            _symbol_hit(f.spec, gold_symbols.get(adv)), ev))
            mark = "✓" if (f.status in FLAGGED) == l["affected"] else "✗"
            log(f"  {mark} {case.name:<28} {adv:<16} gold={'AFFECTED' if l['affected'] else 'safe':<8} got={f.status}")
    return {"config": config, "rows": [r.__dict__ | {"pred_affected": r.pred_affected} for r in rows],
            "metrics": metrics(rows), "cost": {k: round(v, 1) for k, v in totals.items()}}


def metrics(rows: list[Row]) -> dict:
    tp = sum(r.gold_affected and r.pred_affected for r in rows)
    fn = sum(r.gold_affected and not r.pred_affected for r in rows)
    fp = sum(not r.gold_affected and r.pred_affected for r in rows)
    tn = sum(not r.gold_affected and not r.pred_affected for r in rows)
    sym = [r.symbol_hit for r in rows if r.symbol_hit is not None]
    reason = [r for r in rows if not r.gold_affected and not r.pred_affected]
    return {
        "n": len(rows), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": round(tp / max(1, tp + fn), 3),
        "precision": round(tp / max(1, tp + fp), 3),
        "alert_reduction": round(tn / max(1, tn + fp), 3),
        "accuracy": round((tp + tn) / max(1, len(rows)), 3),
        "needs_review_rate": round(sum(r.status == "needs_review" for r in rows) / max(1, len(rows)), 3),
        "symbol_hit_rate": round(sum(sym) / len(sym), 3) if sym else None,
        "reason_match": round(sum(r.status == r.gold_reason for r in reason) / len(reason), 3) if reason else None,
    }


# ---------------------------------------------------------------------------- retrieval
RETRIEVAL_PACKAGES = {"pyyaml": "5.3.1", "jinja2": "2.10", "pillow": "9.5.0", "lxml": "4.6.4",
                      "urllib3": "1.26.16", "flask": "2.0.1"}


def retrieval_eval(gold_symbols: dict, ks=(5, 10, 20)) -> dict:
    """recall@k of gold symbols when querying the library index with the advisory text."""
    embedder = Embedder()
    results: dict[str, dict] = {m: {f"recall@{k}": [] for k in ks} for m in ("bm25", "dense", "hybrid")}
    for pkg, ver in RETRIEVAL_PACKAGES.items():
        st = sources.fetch(pkg, ver)
        cg = CodeGraph()
        cg.add_tree(st.root, pkg, st.top_level)
        cg.build()
        index = symbols.library_index(cg, pkg, embedder)
        from .deps import Package, Resolution
        import networkx as nx
        res = Resolution({pkg: Package(pkg, ver, True)}, nx.DiGraph())
        for adv in osv.match(res):
            gold = gold_symbols.get(adv.display_id)
            if not gold:
                continue
            query = f"{adv.summary}\n{adv.details[:1500]}"
            for mode in results:
                hits = [d.id for d, _ in index.search(query, k=max(ks), mode=mode)]
                for k in ks:
                    results[mode][f"recall@{k}"].append(any(h.startswith(g) for h in hits[:k] for g in gold))
    return {m: {k: round(sum(v) / len(v), 3) for k, v in d.items()} | {"n": len(d[f"recall@{ks[0]}"])}
            for m, d in results.items()}


def render_markdown(results: list[dict], model: str, retrieval: dict | None) -> str:
    out = [f"### Triage benchmark — model `{model}`\n",
           "| config | recall (affected caught) | alert reduction | precision | accuracy | needs review | symbol hit | LLM calls | time (s) |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        m, c = r["metrics"], r["cost"]
        out.append(f"| {r['config']} | {m['recall']:.0%} ({m['tp']}/{m['tp'] + m['fn']}) | {m['alert_reduction']:.0%} "
                   f"({m['tn']}/{m['tn'] + m['fp']}) | {m['precision']:.0%} | {m['accuracy']:.0%} | "
                   f"{m['needs_review_rate']:.0%} | {'-' if m['symbol_hit_rate'] is None else f'{m['symbol_hit_rate']:.0%}'} | "
                   f"{c.get('llm_calls', 0):.0f} | {c.get('seconds', 0):.0f} |")
    if retrieval:
        out += ["\n### Retrieval — advisory text → vulnerable library symbol\n",
                "| method | recall@5 | recall@10 | recall@20 |", "|---|---|---|---|"]
        for mode, d in retrieval.items():
            out.append(f"| {mode} | {d['recall@5']:.0%} | {d['recall@10']:.0%} | {d['recall@20']:.0%} |")
        out.append(f"\n(n = {next(iter(retrieval.values()))['n']} advisories)")
    return "\n".join(out)


def run(cases_dir: Path, out_dir: Path, configs: list[str], with_retrieval: bool = True, log=print) -> str:
    gold = json.loads((cases_dir.parent / "gold_symbols.json").read_text())
    model = LLM().model if set(configs) - {"scanner", "reach-diff"} else "none"
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for cfg in configs:
        log(f"== {cfg}")
        r = run_config(cases_dir, cfg, gold, log)
        r["model"] = model
        (out_dir / f"{model}__{cfg}.json").write_text(json.dumps(r, indent=2))
        results.append(r)
    retrieval = retrieval_eval(gold) if with_retrieval else None
    if retrieval:
        (out_dir / "retrieval.json").write_text(json.dumps(retrieval, indent=2))
    md = render_markdown(results, model, retrieval)
    (out_dir / f"{model}.md").write_text(md + "\n")
    return md
