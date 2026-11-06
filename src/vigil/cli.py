from __future__ import annotations

import json
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(add_completion=False, help="vigil — reachability-aware dependency vulnerability triage (local LLM)")
console = Console()

STYLE = {"exploitable": "bold red", "needs_review": "yellow", "trigger_not_met": "green", "input_trusted": "green",
         "not_reachable": "dim green", "no_symbols": "dim"}


@app.command()
def scan(project: Path = typer.Argument(Path("."), exists=True, file_okay=False),
         no_llm: bool = typer.Option(False, "--no-llm", help="Deterministic only (diff-based symbols, no triage)"),
         only: list[str] = typer.Option(None, "--only", help="Restrict to advisory IDs"),
         out: Path = typer.Option(None, "--out", help="Run directory (report.json + trace.jsonl)"),
         triage: str = typer.Option("workflow", "--triage", help="workflow (structured) | agent (free-form tool use)"),
         verbose: bool = typer.Option(False, "-v")):
    """Scan a Python project and triage every dependency advisory by reachability and exploitability."""
    from .pipeline import scan as run_scan

    run_dir = out or project / ".vigil" / "runs" / time.strftime("%Y%m%d-%H%M%S")
    report = run_scan(project, use_llm=not no_llm, run_dir=run_dir, only=set(only) if only else None, triage=triage,
                      log=lambda m: console.print(f"[dim]{m}[/dim]"))
    t = Table(title=f"vigil: {len(report.findings)} advisories", show_lines=verbose)
    for col in ("status", "advisory", "package", "severity", "fix", "evidence"):
        t.add_column(col)
    for f in report.findings:
        ev = ""
        if f.paths:
            p = f.paths[0]
            ev = f"{p['entry']} → … → {p['target']} ({len(p['hops'])} hops, {p['confidence']})"
        if verbose and f.judgment:
            ev += f"\n[italic]{f.judgment['reasoning']}[/italic]"
        t.add_row(f"[{STYLE.get(f.status, '')}]{f.status}[/]", f.advisory, f"{f.package} {f.version}",
                  f.severity or "-", ",".join(f.fixed_versions[-1:]) or "-", ev)
    console.print(t)
    s = report.stats
    noise = 1 - (s["exploitable"] + s["needs_review"]) / max(1, s["advisories"])
    console.print(f"[bold]{s['exploitable']} exploitable[/], {s['needs_review']} need review, "
                  f"{noise:.0%} of alerts deprioritised with evidence. "
                  f"{s['llm_calls']} LLM calls, {s['seconds']}s. Report: {run_dir / 'report.json'}")


@app.command("eval")
def evaluate(cases: Path = typer.Option(Path("benchmarks/cases"), exists=True, file_okay=False),
             out: Path = typer.Option(Path("benchmarks/results")),
             config: list[str] = typer.Option(None, "--config", "-c", help="scanner reach-diff reach-llm workflow agent"),
             no_retrieval: bool = typer.Option(False, "--no-retrieval")):
    """Run the labeled benchmark and write metrics to benchmarks/results/."""
    from .evaluate import CONFIGS, run
    md = run(cases, out, config or CONFIGS, with_retrieval=not no_retrieval, log=lambda m: console.print(f"[dim]{m}[/dim]"))
    console.print(md)


@app.command()
def serve(project: Path = typer.Argument(Path("."), exists=True, file_okay=False),
          port: int = typer.Option(8765), results: Path = typer.Option(Path("benchmarks/results"))):
    """Open the web UI for a project's scans (and the benchmark results)."""
    import uvicorn
    from .web.server import create_app
    console.print(f"vigil UI → http://localhost:{port}")
    uvicorn.run(create_app(project, results.resolve()), host="127.0.0.1", port=port, log_level="warning")


@app.command()
def graph(project: Path = typer.Argument(Path("."), exists=True, file_okay=False)):
    """Print call-graph statistics and entry points for a project (no dependencies)."""
    from .codegraph import PROJECT, CodeGraph
    cg = CodeGraph()
    cg.add_tree(project, PROJECT)
    cg.build()
    console.print(json.dumps(cg.stats), cg.entry_points())


if __name__ == "__main__":
    app()
