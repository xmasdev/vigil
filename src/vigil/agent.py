"""Step B — exploitability triage agent.

Given a deterministic call path (entry point -> vulnerable symbol) and the extracted
trigger conditions, decide whether attacker-controlled data reaches the dangerous call
under the trigger condition. The agent can investigate with read-only tools.

Harness features:
  * step budget + forced structured finalisation when the budget runs out
  * duplicate-call detection (small models love to loop)
  * tool errors are returned to the model instead of crashing the run
  * evidence verification: every cited (file, line, code) must exist in the source,
    otherwise the verdict is rejected and the model must fix it
  * full trace of every step
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from .codegraph import CodeGraph, PROJECT
from .llm import LLM, StructuredOutputError
from .reach import Path as CallPath
from .symbols import VulnSpec

HIDDEN_FILES = {"labels.json"}  # benchmark ground truth must never reach the model
TEXT_SUFFIXES = {".html", ".htm", ".j2", ".jinja", ".jinja2", ".txt", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".env", ".json"}
Verdict = Literal["exploitable", "trigger_not_met", "input_trusted", "needs_review"]


class Evidence(BaseModel):
    file: str
    line: int
    code: str = Field(description="exact code text on that line")


class Judgment(BaseModel):
    verdict: Verdict
    attacker_controlled: str = Field(description="what data reaches the vulnerable call and where it comes from")
    reasoning: str
    evidence: list[Evidence]
    confidence: Literal["high", "medium", "low"]
    steps: int = 0
    evidence_verified: bool = False


SYSTEM = """You are an application security engineer triaging a dependency vulnerability alert.
A static call graph found a path from an application entry point to a vulnerable library function.
Decide, for THIS application, which verdict applies:
- exploitable: data an external attacker can control (HTTP request body/params/headers/files, uploaded files,
  CLI args from untrusted users, messages from a queue) reaches the vulnerable call AND the trigger condition holds.
- trigger_not_met: the call happens but the trigger condition does not hold (e.g. a safe flag/Loader is used).
- input_trusted: the data comes only from trusted sources (constants, files shipped with the app, admin-only config).
- needs_review: you cannot determine it from the code.
Use the tools to read code you have not seen (e.g. callers of a function, to see where an argument comes from).
Be efficient: usually 0-3 tool calls are enough. When done, call submit_verdict.
Evidence must cite exact lines from the code shown to you (file name and line number as displayed)."""

TOOLS = [
    {"type": "function", "function": {
        "name": "read_function", "description": "Read the source code of a function/method/class by qualified name.",
        "parameters": {"type": "object", "properties": {"qualname": {"type": "string"}}, "required": ["qualname"]}}},
    {"type": "function", "function": {
        "name": "find_callers", "description": "List the call sites that call a function (to trace where its arguments come from).",
        "parameters": {"type": "object", "properties": {"qualname": {"type": "string"}}, "required": ["qualname"]}}},
    {"type": "function", "function": {
        "name": "search_code", "description": "Regex search over the application's source files. Returns matching lines.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "submit_verdict", "description": "Submit the final verdict.",
        "parameters": {"type": "object", "properties": {
            "verdict": {"type": "string", "enum": ["exploitable", "trigger_not_met", "input_trusted", "needs_review"]},
            "attacker_controlled": {"type": "string"},
            "reasoning": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "object", "properties": {
                "file": {"type": "string"}, "line": {"type": "integer"}, "code": {"type": "string"}},
                "required": ["file", "line", "code"]}},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]}},
            "required": ["verdict", "attacker_controlled", "reasoning", "evidence", "confidence"]}}},
]


class TriageAgent:
    def __init__(self, cg: CodeGraph, llm: LLM, project_root: Path, max_steps: int = 6):
        self.cg, self.llm, self.root, self.max_steps = cg, llm, project_root.resolve(), max_steps

    # ------------------------------------------------------------------ tools
    def _rel(self, file: str) -> str:
        try:
            return str(Path(file).resolve().relative_to(self.root))
        except ValueError:
            return file.split("/site-packages/")[-1].split("/src/", 1)[-1]

    def _show(self, qualname: str, max_lines: int = 60) -> str:
        n = self.cg.nodes.get(qualname)
        if not n or not n.file:
            return f"(no source for {qualname})"
        return f"# {qualname}  ({self._rel(n.file)})\n{self.cg.source_of(qualname, max_lines=max_lines)}"

    def tool_read_function(self, qualname: str) -> str:
        q = self.cg.resolve(qualname) or qualname
        if q not in self.cg.nodes:
            close = [k for k in self.cg.nodes if k.endswith("." + qualname.split(".")[-1])][:8]
            return f"Unknown function {qualname!r}. Similar: {close}"
        return self._show(q)

    def tool_find_callers(self, qualname: str) -> str:
        q = self.cg.resolve(qualname) or qualname
        if q not in self.cg.g:
            return f"Unknown function {qualname!r}"
        rows = []
        for caller, _, data in self.cg.g.in_edges(q, data=True):
            for s in data["sites"][:3]:
                rows.append(f"{caller} at {self._rel(s.file)}:{s.lineno}: {s.raw}({', '.join(s.args + [f'{k}={v}' for k, v in s.keywords.items()])})")
        return "\n".join(rows[:20]) or "No callers found (may be an entry point or called dynamically)."

    def tool_search_code(self, pattern: str) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"Invalid regex: {e}"
        hits = []
        for rel, lines in self.project_files().items():
            for i, line in enumerate(lines, 1):
                if rx.search(line):
                    hits.append(f"{rel}:{i}: {line.strip()[:160]}")
        return "\n".join(hits[:30]) or "No matches."

    def project_files(self) -> dict[str, list[str]]:
        """Application source + templates/configs (vulnerable features often live in templates)."""
        if not hasattr(self, "_files"):
            self._files = {self._rel(str(m.file)): m.source.splitlines()
                           for m in self.cg.modules.values() if m.package == PROJECT}
            for f in sorted(self.root.rglob("*")):
                if f.suffix in TEXT_SUFFIXES and f.is_file() and f.name not in HIDDEN_FILES and not any(
                        part.startswith(".") or part in ("venv", "node_modules") for part in f.relative_to(self.root).parts):
                    self._files[self._rel(str(f))] = f.read_text(errors="replace").splitlines()
        return self._files

    # ------------------------------------------------------------------ evidence check
    def verify_evidence(self, ev: list[Evidence]) -> list[str]:
        errors = []
        norm = lambda s: re.sub(r"\s+", "", s)
        files = {self._rel(str(m.file)): m.source.splitlines() for m in self.cg.modules.values()} | self.project_files()
        for e in ev:
            lines = files.get(e.file) or next((v for k, v in files.items() if k.endswith("/" + e.file) or k.endswith(e.file)), None)
            if lines is None:
                errors.append(f"evidence file {e.file!r} not found")
                continue
            window = lines[max(0, e.line - 4): e.line + 3]
            if not any(norm(e.code) and norm(e.code) in norm(l) or (norm(l) and norm(l) in norm(e.code)) for l in window):
                errors.append(f"{e.file}:{e.line} does not contain {e.code!r}")
        return errors

    # ------------------------------------------------------------------ main loop
    def initial_context(self, spec: VulnSpec, path: CallPath, summary: str) -> str:
        hops = []
        for node, site in zip(path.nodes, [None, *path.sites]):
            n = self.cg.nodes.get(node)
            if n and n.package == PROJECT and n.kind != "module":
                hops.append(self._show(node, max_lines=40))
        last = path.sites[-1]
        call = f"{last.raw}({', '.join(last.args + [f'{k}={v}' for k, v in last.keywords.items()])})"
        triggers = "\n".join(f"- {s.qualname}: {s.trigger}" for s in spec.symbols)
        return (f"Advisory {spec.advisory} in {spec.package}: {summary}\n"
                f"Vulnerable symbols and trigger conditions:\n{triggers}\n"
                f"Attacker needs: {spec.attacker_input or 'n/a'}\nSafe usage: {spec.safe_usage or 'n/a'}\n\n"
                f"Call path found by static analysis ({path.confidence} confidence):\n{path.render()}\n\n"
                f"The call into the library: {call} at {self._rel(last.file)}:{last.lineno}\n\n"
                f"Application code along the path:\n" + "\n\n".join(hops))

    def judge(self, spec: VulnSpec, path: CallPath, summary: str) -> Judgment:
        msgs: list[dict] = [{"role": "system", "content": SYSTEM},
                            {"role": "user", "content": self.initial_context(spec, path, summary)}]
        seen_calls: dict[str, str] = {}
        tracer = self.llm.tracer
        for step in range(1, self.max_steps + 1):
            msg = self.llm.chat(msgs, tools=TOOLS, max_tokens=800, purpose=f"triage:{spec.advisory}:step{step}")
            calls = msg.tool_calls or []
            msgs.append({"role": "assistant", "content": msg.content or "",
                         **({"tool_calls": [{"id": c.id, "type": "function",
                                             "function": {"name": c.function.name, "arguments": c.function.arguments}}
                                            for c in calls]} if calls else {})})
            if not calls:
                msgs.append({"role": "user", "content": "Call a tool, or call submit_verdict with your final answer."})
                continue
            for c in calls:
                name = c.function.name
                try:
                    args = json.loads(c.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = None
                if args is None:
                    result = "Error: arguments were not valid JSON."
                elif name == "submit_verdict":
                    try:
                        j = Judgment(**args)
                    except ValidationError as e:
                        result = f"Invalid verdict: {str(e)[:400]}"
                    else:
                        errs = self.verify_evidence(j.evidence) if j.evidence else ["at least one evidence line is required"]
                        if not errs:
                            j.steps, j.evidence_verified = step, True
                            tracer.emit("verdict", advisory=spec.advisory, verdict=j.verdict, steps=step)
                            return j
                        tracer.emit("evidence_rejected", advisory=spec.advisory, errors=errs)
                        result = "Verdict rejected, evidence check failed:\n- " + "\n- ".join(errs) + \
                                 "\nCite exact lines from the code shown (file:line as displayed) and resubmit."
                else:
                    key = f"{name}:{json.dumps(args, sort_keys=True)}"
                    if key in seen_calls:
                        result = "You already made this exact call. Use the earlier result or submit_verdict.\n" + seen_calls[key][:500]
                    else:
                        fn = getattr(self, f"tool_{name}", None)
                        try:
                            result = fn(**args) if fn else f"Unknown tool {name}"
                        except TypeError as e:
                            result = f"Bad arguments: {e}"
                        seen_calls[key] = result
                    tracer.emit("tool", name=name, args=args, result=result[:2000])
                msgs.append({"role": "tool", "tool_call_id": c.id, "content": result[:6000]})
        return self._force_final(msgs, spec)

    def _force_final(self, msgs: list[dict], spec: VulnSpec) -> Judgment:
        """Budget exhausted: demand a schema-constrained verdict from the conversation so far."""
        self.llm.tracer.emit("budget_exhausted", advisory=spec.advisory)
        flat = [m for m in msgs if m["role"] in ("system", "user")][:2]
        notes = "\n\n".join(f"[{m['role']}] {m['content'][:3000]}" for m in msgs[2:] if m.get("content"))
        flat.append({"role": "user", "content": f"Investigation notes so far:\n{notes}\n\nGive your final verdict now."})
        try:
            j = self.llm.structured(flat, Judgment, schema=_judgment_schema(), validate=lambda j: self.verify_evidence(j.evidence),
                                    purpose=f"triage-final:{spec.advisory}", max_tokens=700)
            j.steps, j.evidence_verified = self.max_steps, True
            return j
        except StructuredOutputError as e:
            return Judgment(verdict="needs_review", attacker_controlled="", reasoning=f"agent failed: {e.errors[:2]}",
                            evidence=[], confidence="low", steps=self.max_steps)


def _judgment_schema() -> dict:
    return TOOLS[-1]["function"]["parameters"]
