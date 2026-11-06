"""Step B (alternative) — structured triage workflow.

Small local models are unreliable at open-ended tool use (see traces: they wander into
library internals). This workflow decomposes triage into fixed, narrow questions; each
LLM call answers one schema-constrained question, and deterministic code combines the
answers into a verdict. The eval compares it against the free-form TriageAgent.

  path kind?  ─ direct ──► Q1 trigger condition at the call site?  ─► Q2 source of the data?
     (det.)   └ runtime ─► Q3 search patterns for the feature ─► harness runs searches ─► Q4 feature used?
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from .agent import Evidence, Judgment, TriageAgent
from .codegraph import PROJECT
from .llm import LLM, StructuredOutputError
from .reach import Path as CallPath
from .symbols import VulnSpec

ATTACKER_SOURCES = {"http_request", "uploaded_file", "untrusted_cli_or_env", "network_message", "external_url"}


class _Trigger(BaseModel):
    reasoning: str
    trigger_holds: Literal["yes", "no", "unknown"]
    evidence_line: int = Field(description="line number of the call site or argument that decides it")
    evidence_code: str


class _Source(BaseModel):
    reasoning: str
    data_source: Literal["http_request", "uploaded_file", "untrusted_cli_or_env", "network_message", "external_url",
                         "file_shipped_with_app", "constant", "admin_config", "unknown"]
    evidence_file: str
    evidence_line: int
    evidence_code: str


class _Patterns(BaseModel):
    patterns: list[str] = Field(max_length=4)


def _clean_pattern(p: str) -> str:
    """Models often answer with Python literals: r'session\\[' -> session\\["""
    p = p.strip()
    m = re.fullmatch(r"""[rRbB]?(['"])(.*)\1""", p, flags=re.S)
    return m.group(2) if m else p


class _FeatureUse(BaseModel):
    reasoning: str
    feature_used: Literal["yes", "no", "unknown"]
    attacker_can_trigger: Literal["yes", "no", "unknown"]


SYSTEM = "You are an application security engineer. Answer only the question asked, precisely and briefly."


class TriageWorkflow:
    def __init__(self, agent: TriageAgent):
        self.a = agent  # reuse tools, rendering and evidence verification
        self.llm: LLM = agent.llm

    def _ask(self, prompt: str, model, purpose: str, schema: dict | None = None, validate=None):
        return self.llm.structured([{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                                   model, schema=schema, validate=validate, purpose=purpose, max_tokens=600)

    def judge(self, spec: VulnSpec, path: CallPath, summary: str) -> Judgment:
        ctx = self.a.initial_context(spec, path, summary)
        runtime = any(s.raw.startswith("<runtime>") for s in path.sites)
        try:
            return self._runtime(spec, path, ctx) if runtime else self._direct(spec, path, ctx)
        except StructuredOutputError as e:
            return Judgment(verdict="needs_review", attacker_controlled="", reasoning=f"workflow failed: {e.errors[:2]}",
                            evidence=[], confidence="low")

    # ---------------------------------------------------------------- direct call into the library
    def _direct(self, spec: VulnSpec, path: CallPath, ctx: str) -> Judgment:
        # the hop where application code calls into the library
        hop = next((s for s in reversed(path.sites)
                    if self.a.cg.nodes.get(s.caller) and self.a.cg.nodes[s.caller].package == PROJECT), path.sites[-1])
        hop_file = self.a._rel(hop.file)
        call = f"{hop.raw}({', '.join(hop.args + [f'{k}={v}' for k, v in hop.keywords.items()])})"
        steps = 0

        t: _Trigger = self._ask(
            f"{ctx}\n\nQUESTION: At the application call `{call}` ({hop_file}:{hop.lineno}), does the trigger condition "
            f"hold? Consider the exact function called and its arguments/flags. Cite the deciding line.",
            _Trigger, f"wf-trigger:{spec.advisory}",
            validate=lambda o: self.a.verify_evidence([Evidence(file=hop_file, line=o.evidence_line, code=o.evidence_code)]))
        steps += 1
        ev = [Evidence(file=hop_file, line=t.evidence_line, code=t.evidence_code)]
        if t.trigger_holds == "no":
            return Judgment(verdict="trigger_not_met", attacker_controlled="n/a", reasoning=t.reasoning, evidence=ev,
                            confidence="high", steps=steps, evidence_verified=True)

        s: _Source = self._ask(
            f"{ctx}\n\nQUESTION: Trace the data passed to `{call}` back through the application code above to where it "
            f"originates. Which category is its source? Cite the line where it originates.",
            _Source, f"wf-source:{spec.advisory}",
            validate=lambda o: self.a.verify_evidence([Evidence(file=o.evidence_file, line=o.evidence_line, code=o.evidence_code)]))
        steps += 1
        ev.append(Evidence(file=s.evidence_file, line=s.evidence_line, code=s.evidence_code))
        reasoning = f"{t.reasoning} {s.reasoning}"
        if s.data_source in ATTACKER_SOURCES:
            verdict = "exploitable" if t.trigger_holds == "yes" else "needs_review"
        elif s.data_source == "unknown":
            verdict = "needs_review"
        else:
            verdict = "input_trusted"
        if verdict == "input_trusted" and self._entry_reads_request(path):
            verdict = "needs_review"
            reasoning += f" [downgraded: entry point {path.entry} is an HTTP handler that reads request data]"
        return Judgment(verdict=verdict, attacker_controlled=s.data_source, reasoning=reasoning, evidence=ev,
                        confidence="high" if verdict != "needs_review" else "low", steps=steps, evidence_verified=True)

    def _entry_reads_request(self, path: CallPath) -> bool:
        """Deterministic sanity check on the LLM's data-source answer."""
        if path.entry_kind != "http":
            return False
        src = self.a.cg.source_of(path.entry, max_lines=200)
        return bool(re.search(r"\brequest\.(files|form|data|args|values|json|get_data|get_json|body|POST|GET|FILES)\b", src))

    # ---------------------------------------------------------------- framework runtime path
    def _anchors(self, spec: VulnSpec, path: CallPath) -> list[str]:
        """Deterministic search terms: short names of the vulnerable API and of any library class
        on the path that the app instantiates. Model-chosen patterns can be useless (fully
        qualified internals never appear in app code), so 'no matches' alone is weak evidence."""
        cg = self.a.cg
        names: list[str] = []
        add = lambda n: names.append(n) if n not in names and len(n) > 3 and not n.startswith("__") else None
        for q in [n for n in path.nodes if n in cg.classes]:          # library classes the app instantiates
            add(q.rsplit(".", 1)[-1])
        for q in [s.qualname for s in spec.symbols] + [path.target]:
            for key in sorted(cg.registry_names.get(q, ())):          # name it is registered under (template filters)
                add(key)
            parts = q.split(".")
            add(parts[-1])
            if ".".join(parts[:-1]) in cg.classes:                      # method -> also its class name
                add(parts[-2])
        return [rf"\b{re.escape(n)}\b" for n in names[:8]]

    def _runtime(self, spec: VulnSpec, path: CallPath, ctx: str) -> Judgment:
        def valid_patterns(o: _Patterns) -> list[str]:
            errs = []
            o.patterns = [_clean_pattern(p) for p in o.patterns]
            for p in o.patterns:
                try:
                    re.compile(p)
                except re.error as e:
                    errs.append(f"invalid regex {p!r}: {e}")
            return errs or ([] if o.patterns else ["give at least one pattern"])

        pats: _Patterns = self._ask(
            f"{ctx}\n\nThe vulnerable code runs inside the framework/library runtime, not from a direct application call. "
            f"Whether the app is affected depends on whether it USES the feature or configuration in the trigger "
            f"conditions. QUESTION: give up to 4 BROAD regex patterns that would find ANY use of that feature in the "
            f"application code (match the feature itself, not one specific value; e.g. for a session bug: \\bsession\\b). "
            f"Plain regex text, no quotes.",
            _Patterns, f"wf-patterns:{spec.advisory}", validate=valid_patterns)
        anchors = self._anchors(spec, path)
        results = {p: self.a.tool_search_code(p) for p in dict.fromkeys(pats.patterns + anchors)}
        anchor_hits = [p for p in anchors if results[p] != "No matches."]
        self.llm.tracer.emit("tool", name="search_code(batch)", args=pats.patterns, result=str(results)[:2000])
        shown = "\n".join(f"search {p!r}:\n{r}" for p, r in results.items())
        f: _FeatureUse = self._ask(
            f"{ctx}\n\nSearch results over ALL of the application's source files:\n{shown}\n\nQUESTION: Does the "
            f"application use the feature/configuration required by the trigger condition, and if so can an external "
            f"attacker trigger it? The searches cover the entire application, so no matches means the app's code does "
            f"not use that feature.",
            _FeatureUse, f"wf-feature:{spec.advisory}")
        ev = []
        for p, r in results.items():
            if r != "No matches.":
                first = r.splitlines()[0]
                file, line, code = first.split(":", 2)
                ev.append(Evidence(file=file, line=int(line), code=code.strip()))
        negative = [p for p, r in results.items() if r == "No matches."]
        reasoning = f.reasoning + (f" (no matches in app code for: {', '.join(negative)})" if negative else "")
        if f.feature_used == "no":
            verdict = "trigger_not_met"
        elif f.feature_used == "yes" and f.attacker_can_trigger == "yes":
            verdict = "exploitable"
        elif f.feature_used == "yes" and f.attacker_can_trigger == "no":
            verdict = "trigger_not_met"
        else:
            verdict = "needs_review"
        # 'not used' must be backed by searches that really returned nothing, including the
        # deterministic anchors (the vulnerable API's own names)
        if verdict == "trigger_not_met" and f.feature_used == "no" and (anchor_hits or not negative):
            verdict = "needs_review"
            reasoning += (f" [downgraded: the app references {', '.join(anchor_hits)}, contradicting 'feature not used']"
                          if anchor_hits else " [downgraded: no negative search evidence]")
        return Judgment(verdict=verdict, attacker_controlled="framework runtime", reasoning=reasoning, evidence=ev,
                        confidence="medium", steps=3, evidence_verified=True)
