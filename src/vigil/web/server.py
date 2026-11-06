"""Local web UI: browse scan runs, attack paths, evidence and agent traces; launch scans."""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

STATIC = Path(__file__).parent / "static"


def create_app(project: Path, results_dir: Path | None = None) -> FastAPI:
    project = project.resolve()
    runs_dir = project / ".vigil" / "runs"
    app = FastAPI(title="vigil")
    jobs: dict[str, dict] = {}

    def run_path(run_id: str) -> Path:
        p = (runs_dir / run_id).resolve()
        if p.parent != runs_dir.resolve() or not p.is_dir():
            raise HTTPException(404, "run not found")
        return p

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/runs")
    def runs():
        out = []
        for d in sorted(runs_dir.glob("*"), reverse=True):
            rp = d / "report.json"
            if rp.exists():
                r = json.loads(rp.read_text())
                out.append({"id": d.name, "project": r["project"], "model": r["model"], "stats": r["stats"]})
        return {"project": str(project), "runs": out}

    @app.get("/api/runs/{run_id}/report")
    def report(run_id: str):
        return json.loads((run_path(run_id) / "report.json").read_text())

    @app.get("/api/runs/{run_id}/trace")
    def trace(run_id: str, advisory: str | None = None):
        tp = run_path(run_id) / "trace.jsonl"
        if not tp.exists():
            return []
        events = [json.loads(l) for l in tp.read_text().splitlines() if l.strip()]
        if advisory:
            spans = {e["id"] for e in events if e["kind"] == "span_start" and e.get("advisory") == advisory}
            events = [e for e in events if e.get("span") in spans or e.get("id") in spans]
        return events

    @app.get("/api/source")
    def source(file: str, line: int, context: int = 6):
        p = (project / file).resolve()
        if not p.is_relative_to(project) or not p.is_file():
            raise HTTPException(404, "file not in project")
        lines = p.read_text(errors="replace").splitlines()
        start, end = max(1, line - context), min(len(lines), line + context)
        return {"file": file, "start": start, "highlight": line, "lines": lines[start - 1:end]}

    class ScanRequest(BaseModel):
        triage: str = "workflow"

    @app.post("/api/scan")
    def start_scan(req: ScanRequest):
        from ..pipeline import scan
        job = uuid.uuid4().hex[:8]
        run_id = time.strftime("%Y%m%d-%H%M%S")
        jobs[job] = {"status": "running", "log": [], "run": run_id}

        def work():
            try:
                scan(project, run_dir=runs_dir / run_id, triage=req.triage, log=jobs[job]["log"].append)
                jobs[job]["status"] = "done"
            except Exception as e:  # noqa: BLE001
                jobs[job].update(status="error", error=str(e))
        threading.Thread(target=work, daemon=True).start()
        return {"job": job}

    @app.get("/api/scan/{job}")
    def scan_status(job: str):
        if job not in jobs:
            raise HTTPException(404)
        return jobs[job]

    @app.get("/api/eval")
    def eval_results():
        d = results_dir or Path("benchmarks/results")
        if not d.exists():
            return {"results": [], "retrieval": None}
        res = [json.loads(p.read_text()) for p in sorted(d.glob("*__*.json"))]
        rp = d / "retrieval.json"
        return {"results": res, "retrieval": json.loads(rp.read_text()) if rp.exists() else None}

    return app
