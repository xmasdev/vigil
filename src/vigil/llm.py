"""LLM client for llama-server (OpenAI-compatible) with tracing and validated structured output."""

from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, TypeVar

from openai import OpenAI
from pydantic import BaseModel, ValidationError

CHAT_URL = os.environ.get("VIGIL_CHAT_URL", "http://localhost:8080/v1")
T = TypeVar("T", bound=BaseModel)


class Tracer:
    """Append-only JSONL trace of every span / LLM call / tool call in a run."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self.events: list[dict] = []
        self._stack: list[str] = []
        self.totals = {"llm_calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "llm_seconds": 0.0}

    def emit(self, kind: str, **data: Any) -> None:
        ev = {"t": time.time(), "kind": kind, "span": self._stack[-1] if self._stack else None, **data}
        self.events.append(ev)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(json.dumps(ev, default=str) + "\n")

    @contextmanager
    def span(self, name: str, **attrs: Any):
        sid = f"{name}:{uuid.uuid4().hex[:6]}"
        self.emit("span_start", name=name, id=sid, **attrs)
        self._stack.append(sid)
        t0 = time.time()
        try:
            yield sid
        finally:
            self._stack.pop()
            self.emit("span_end", name=name, id=sid, seconds=round(time.time() - t0, 3))


NULL_TRACER = Tracer()


class LLM:
    def __init__(self, base_url: str = CHAT_URL, tracer: Tracer = NULL_TRACER, thinking: bool = False,
                 temperature: float = 0.2):
        self.client = OpenAI(base_url=base_url, api_key="local", timeout=300)
        self.tracer = tracer
        self.thinking = thinking
        self.temperature = temperature
        self._model: str | None = None

    @property
    def model(self) -> str:
        if self._model is None:
            try:
                self._model = Path(self.client.models.list().data[0].id).name
            except Exception:
                self._model = "unknown"
        return self._model

    def chat(self, messages: list[dict], *, tools: list[dict] | None = None, schema: dict | None = None,
             max_tokens: int = 1024, purpose: str = "") -> Any:
        kwargs: dict[str, Any] = dict(model="local", messages=messages, max_tokens=max_tokens,
                                      temperature=self.temperature,
                                      extra_body={"chat_template_kwargs": {"enable_thinking": self.thinking}})
        if tools:
            kwargs["tools"] = tools
        if schema:
            kwargs["response_format"] = {"type": "json_schema", "json_schema": {"name": "out", "schema": schema}}
        t0 = time.time()
        resp = self.client.chat.completions.create(**kwargs)
        dt = time.time() - t0
        u = resp.usage
        self.tracer.totals["llm_calls"] += 1
        self.tracer.totals["prompt_tokens"] += u.prompt_tokens if u else 0
        self.tracer.totals["completion_tokens"] += u.completion_tokens if u else 0
        self.tracer.totals["llm_seconds"] += dt
        msg = resp.choices[0].message
        self.tracer.emit("llm", purpose=purpose, seconds=round(dt, 2),
                         prompt_tokens=u.prompt_tokens if u else None, completion_tokens=u.completion_tokens if u else None,
                         messages=messages[-2:], output=msg.content,
                         tool_calls=[{"name": tc.function.name, "args": tc.function.arguments} for tc in (msg.tool_calls or [])])
        return msg

    def structured(self, messages: list[dict], model: type[T], *, schema: dict | None = None,
                   validate: Callable[[T], list[str]] | None = None, retries: int = 2,
                   max_tokens: int = 1024, purpose: str = "") -> T:
        """Grammar-constrained JSON -> pydantic model -> semantic validation, with
        feedback-driven retries. Raises if it still fails after `retries`."""
        schema = schema or model.model_json_schema()
        msgs = list(messages)
        errors: list[str] = []
        for attempt in range(retries + 1):
            msg = self.chat(msgs, schema=schema, max_tokens=max_tokens, purpose=f"{purpose}#{attempt}")
            try:
                obj = model.model_validate_json(msg.content or "")
                errors = validate(obj) if validate else []
            except ValidationError as e:
                errors = [str(e)[:500]]
            if not errors:
                return obj
            self.tracer.emit("validation_failed", purpose=purpose, attempt=attempt, errors=errors)
            msgs = msgs + [{"role": "assistant", "content": msg.content or ""},
                           {"role": "user", "content": "Your answer failed validation:\n- " + "\n- ".join(errors)
                            + "\nFix these problems and answer again."}]
        raise StructuredOutputError(purpose, errors)


class StructuredOutputError(RuntimeError):
    def __init__(self, purpose: str, errors: list[str]):
        super().__init__(f"{purpose}: {errors}")
        self.errors = errors
