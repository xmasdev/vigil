"""Static call graph over the project + selected dependency sources.

Every edge carries a *confidence*:
  exact     - callee resolved through imports/definitions/re-exports
  inferred  - resolved through simple local type inference, self/super, or a
              function/class passed as a value (callback, Loader=FullLoader)
  name      - unresolved attribute call matched by method name only (few candidates)

Paths are only as strong as their weakest edge; the report surfaces this instead
of pretending static analysis of Python is exact.
"""

from __future__ import annotations

import ast
import builtins
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

PROJECT = "<project>"
CONF_RANK = {"exact": 0, "inferred": 1, "name": 2}
HTTP_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "websocket", "api_route", "head", "options"}
CLI_DECORATORS = {"command", "callback", "group"}
TASK_DECORATORS = {"task", "shared_task", "job"}
NAME_FALLBACK_MAX = 3
NAME_FALLBACK_BLOCK = {"get", "set", "read", "write", "close", "open", "append", "update", "items", "keys", "values",
                       "copy", "pop", "join", "split", "strip", "format", "encode", "decode", "run", "send", "start",
                       "add", "remove", "load", "dump", "__init__", "__call__", "lower", "upper", "replace"}
BUILTINS = set(dir(builtins))


@dataclass
class Node:
    qualname: str
    kind: str  # function | method | class | module | main | external
    package: str
    file: str | None = None
    lineno: int = 0
    end_lineno: int = 0
    entry: str | None = None  # http | cli | task | main | import
    signature: str = ""
    doc: str = ""
    params: list[str] = field(default_factory=list)  # "x", "x=" (default), "*args", "**kw", "kw:x", "kw:x="


@dataclass
class CallSite:
    caller: str
    callee: str
    raw: str
    file: str
    lineno: int
    confidence: str
    keywords: dict[str, str] = field(default_factory=dict)
    args: list[str] = field(default_factory=list)


@dataclass
class _Module:
    name: str
    file: Path
    package: str
    is_pkg: bool
    tree: ast.Module
    source: str
    bindings: dict[str, str] = field(default_factory=dict)  # local name -> dotted target
    star_imports: list[str] = field(default_factory=list)
    instances: dict[str, str] = field(default_factory=dict)  # module global -> dotted constructor (`http = PoolManager()`)


@dataclass
class _Class:
    qualname: str
    module: str
    bases: list[str]  # dotted (unresolved)
    methods: dict[str, str] = field(default_factory=dict)


def _params(a: ast.arguments) -> list[str]:
    pos = a.posonlyargs + a.args
    n_def = len(a.defaults)
    out = [p.arg + ("=" if i >= len(pos) - n_def else "") for i, p in enumerate(pos)]
    if a.vararg:
        out.append("*" + a.vararg.arg)
    out += ["kw:" + k.arg + ("=" if d is not None else "") for k, d in zip(a.kwonlyargs, a.kw_defaults)]
    if a.kwarg:
        out.append("**" + a.kwarg.arg)
    return out


def _dotted(expr: ast.AST) -> list[str] | None:
    parts = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if isinstance(expr, ast.Name):
        parts.append(expr.id)
        return parts[::-1]
    return None


def _children_no_nested(node: ast.AST):
    """Walk a scope without descending into nested function/class/lambda scopes."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(n))


class CodeGraph:
    def __init__(self) -> None:
        self.modules: dict[str, _Module] = {}
        self.nodes: dict[str, Node] = {}
        self.classes: dict[str, _Class] = {}
        self.g = nx.DiGraph()
        self.stats = {"calls": 0, "exact": 0, "inferred": 0, "name": 0, "unresolved": 0, "parse_errors": 0}
        self._methods_by_name: dict[str, list[str]] = {}
        self.address_taken: set[str] = set()  # functions stored as values (registries, callbacks)

    # ------------------------------------------------------------------ indexing
    def add_tree(self, root: Path, package: str, top_level: list[str] | None = None) -> None:
        root = root.resolve()
        files: list[Path] = []
        if top_level is None:
            files = [p for p in root.rglob("*.py") if not any(part.startswith(".") or part in {"venv", ".venv", "node_modules", "site-packages"} for part in p.relative_to(root).parts)]
        else:
            for t in top_level:
                if (root / t).is_dir():
                    files += [p for p in (root / t).rglob("*.py") if not {"tests", "test"} & set(p.relative_to(root).parts)]
                elif (root / f"{t}.py").exists():
                    files.append(root / f"{t}.py")
        for f in files:
            rel = f.relative_to(root).with_suffix("")
            parts = list(rel.parts)
            is_pkg = parts[-1] == "__init__"
            if is_pkg:
                parts = parts[:-1]
            if not parts:
                continue
            name = ".".join(parts)
            try:
                src = f.read_text(errors="replace")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    tree = ast.parse(src, filename=str(f))
            except (SyntaxError, ValueError):
                self.stats["parse_errors"] += 1
                continue
            self.modules[name] = _Module(name, f, package, is_pkg, tree, src)

    def build(self) -> "CodeGraph":
        for m in self.modules.values():
            self._collect_defs(m)
        for m in self.modules.values():
            self._collect_calls(m)
        # instantiating a class runs its __init__
        for cq in self.classes:
            init = self.lookup_method(cq, "__init__")
            if init:
                self._edge(CallSite(cq, init, f"{cq}()", self.nodes[cq].file or "", self.nodes[cq].lineno, "exact"))
        self._add_lifecycle_edges()
        return self

    def _add_lifecycle_edges(self) -> None:
        """Inversion of control: when the app instantiates a *library* class (Flask(...),
        Session(), PoolManager()), the library/runtime may invoke any of its public or
        dunder methods (a WSGI server calls Flask.__call__ -> wsgi_app). Over-approximate
        with 'inferred' edges class -> methods so framework-internal CVEs aren't
        silently dismissed as unreachable; the triage agent then judges them."""
        instantiated = {v for u, v in self.g.edges
                        if v in self.classes and self.nodes[u].package == PROJECT and self.nodes[v].package != PROJECT}
        for cq in instantiated:
            seen: set[str] = set()
            stack = [cq]
            while stack:
                c = self.classes.get(stack.pop())
                if not c or c.qualname in seen:
                    continue
                seen.add(c.qualname)
                for name, mq in c.methods.items():
                    if not name.startswith("_") or (name.startswith("__") and name.endswith("__")):
                        if not self.g.has_edge(cq, mq):
                            n = self.nodes[cq]
                            self._edge(CallSite(cq, mq, f"<runtime> {cq.rsplit('.', 1)[-1]}.{name}", n.file or "", n.lineno, "inferred"))
                mod = self.modules.get(c.module)
                stack += [b for base in c.bases if mod and (b := self._resolve_in_module(mod, base))]

    # ------------------------------------------------------------------ pass 1
    def _add_node(self, n: Node) -> None:
        self.nodes[n.qualname] = n
        self.g.add_node(n.qualname)

    def _abs_import(self, m: _Module, module: str | None, level: int) -> str:
        if level == 0:
            return module or ""
        base = m.name.split(".")
        if not m.is_pkg:
            base = base[:-1]
        base = base[: len(base) - (level - 1)] if level > 1 else base
        return ".".join(base + ([module] if module else []))

    def _import_bindings(self, m: _Module, stmt: ast.AST) -> dict[str, str]:
        out = {}
        if isinstance(stmt, ast.Import):
            for a in stmt.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    out[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(stmt, ast.ImportFrom):
            base = self._abs_import(m, stmt.module, stmt.level)
            for a in stmt.names:
                if a.name == "*":
                    m.star_imports.append(base)
                else:
                    out[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
        return out

    def _collect_defs(self, m: _Module) -> None:
        file = str(m.file)
        self._add_node(Node(f"{m.name}.<module>", "module", m.package, file, 1, len(m.source.splitlines()),
                            entry="import" if m.package == PROJECT else None))

        def visit_scope(body: list[ast.stmt], prefix: str, cls: _Class | None, module_scope: bool) -> None:
            for stmt in body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qn = f"{prefix}.{stmt.name}"
                    kind = "method" if cls else "function"
                    self._add_node(Node(qn, kind, m.package, file, stmt.lineno, stmt.end_lineno or stmt.lineno,
                                        entry=self._entry_kind(m, stmt, cls),
                                        signature=f"({ast.unparse(stmt.args)})", doc=(ast.get_docstring(stmt) or "")[:400],
                                        params=_params(stmt.args)))
                    if cls:
                        cls.methods[stmt.name] = qn
                        self._methods_by_name.setdefault(stmt.name, []).append(qn)
                    elif module_scope:
                        m.bindings[stmt.name] = qn
                    visit_scope(stmt.body, qn, None, False)
                elif isinstance(stmt, ast.ClassDef):
                    qn = f"{prefix}.{stmt.name}"
                    bases = [".".join(d) for b in stmt.bases if (d := _dotted(b))]
                    c = _Class(qn, m.name, bases)
                    self.classes[qn] = c
                    self._add_node(Node(qn, "class", m.package, file, stmt.lineno, stmt.end_lineno or stmt.lineno,
                                        signature=f"({', '.join(bases)})", doc=(ast.get_docstring(stmt) or "")[:400]))
                    if module_scope:
                        m.bindings[stmt.name] = qn
                    visit_scope(stmt.body, qn, c, False)
                elif module_scope and isinstance(stmt, (ast.Import, ast.ImportFrom)):
                    m.bindings.update(self._import_bindings(m, stmt))
                elif module_scope and isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                        and isinstance(stmt.targets[0], ast.Name) and isinstance(stmt.value, ast.Call) \
                        and (d := _dotted(stmt.value.func)):
                    m.instances[stmt.targets[0].id] = ".".join(d)
                elif module_scope and isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                        and isinstance(stmt.targets[0], ast.Name) and (d := _dotted(stmt.value)):
                    # alias:  load = _load   /   Loader = loader.FullLoader
                    m.bindings.setdefault(stmt.targets[0].id, f"__alias__:{'.'.join(d)}")
                elif module_scope and isinstance(stmt, (ast.If, ast.Try)):
                    # conditional imports/defs at module level (try: import x except ...)
                    blocks = [stmt.body, stmt.orelse] + ([h.body for h in stmt.handlers] if isinstance(stmt, ast.Try) else [])
                    for b in blocks:
                        if self._is_main_guard(stmt):
                            break
                        visit_scope(b, prefix, cls, True)

        visit_scope(m.tree.body, m.name, None, True)
        # resolve module-level aliases to dotted targets in this module's namespace
        for k, v in list(m.bindings.items()):
            if v.startswith("__alias__:"):
                head, *rest = v[len("__alias__:"):].split(".")
                base = m.bindings.get(head)
                if base and not base.startswith("__alias__:"):
                    m.bindings[k] = ".".join([base, *rest])
                else:
                    del m.bindings[k]

    @staticmethod
    def _is_main_guard(stmt: ast.stmt) -> bool:
        return (isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Compare)
                and isinstance(stmt.test.left, ast.Name) and stmt.test.left.id == "__name__")

    def _entry_kind(self, m: _Module, fn: ast.AST, cls: _Class | None) -> str | None:
        if m.package != PROJECT:
            return None
        for dec in fn.decorator_list:  # type: ignore[attr-defined]
            target = dec.func if isinstance(dec, ast.Call) else dec
            d = _dotted(target)
            if not d:
                continue
            last = d[-1]
            if last in HTTP_DECORATORS and len(d) > 1:
                return "http"
            if last in CLI_DECORATORS:
                return "cli"
            if last in TASK_DECORATORS:
                return "task"
        # Django-style function views
        if m.file.name == "views.py" and not cls and fn.args.args and fn.args.args[0].arg == "request":  # type: ignore[attr-defined]
            return "http"
        return None

    # ------------------------------------------------------------------ resolution
    def lookup_method(self, cls_qn: str, name: str, depth: int = 0) -> str | None:
        c = self.classes.get(cls_qn)
        if not c or depth > 10:
            return None
        if name in c.methods:
            return c.methods[name]
        mod = self.modules.get(c.module)
        for b in c.bases:
            bq = self._resolve_in_module(mod, b) if mod else None
            if bq and bq in self.classes:
                found = self.lookup_method(bq, name, depth + 1)
                if found:
                    return found
        return None

    def _resolve_in_module(self, m: _Module, dotted: str) -> str | None:
        head, *rest = dotted.split(".")
        base = m.bindings.get(head)
        if base is None:
            return self.resolve(f"{m.name}.{dotted}")  # follows `from x import *`
        return self.resolve(".".join([base, *rest]))

    def resolve(self, dotted: str, depth: int = 0) -> str | None:
        """Resolve a fully-qualified dotted name (following re-exports) to a node."""
        if depth > 12:
            return None
        if dotted in self.nodes:
            return dotted
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            mod = ".".join(parts[:i])
            if mod in self.modules:
                rest = parts[i:]
                break
        else:
            return None
        if not rest:
            return None
        m = self.modules[mod]
        binding = m.bindings.get(rest[0])
        if binding is None:
            for star in m.star_imports:
                r = self.resolve(".".join([star, *rest]), depth + 1)
                if r:
                    return r
            return None
        if binding != f"{mod}.{rest[0]}":
            return self.resolve(".".join([binding, *rest[1:]]), depth + 1)
        current = binding
        for attr in rest[1:]:
            if current in self.classes:
                nxt = self.lookup_method(current, attr)
                if not nxt:
                    return None
                current = nxt
            else:
                return None
        return current

    def external_name(self, m: _Module, dotted: list[str], scope_imports: dict[str, str]) -> str | None:
        """For calls into packages we did not index, keep the import-qualified name."""
        target = scope_imports.get(dotted[0]) or m.bindings.get(dotted[0])
        if target and not target.startswith("__alias__") and target not in self.nodes:
            root = target.split(".")[0]
            if not any(k == root or k.startswith(root + ".") for k in self.modules):
                return ".".join([target, *dotted[1:]])
        return None

    # ------------------------------------------------------------------ pass 2
    def _edge(self, cs: CallSite) -> None:
        if self.g.has_edge(cs.caller, cs.callee):
            data = self.g.edges[cs.caller, cs.callee]
            data["sites"].append(cs)
            if CONF_RANK[cs.confidence] < CONF_RANK[data["confidence"]]:
                data["confidence"] = cs.confidence
        else:
            self.g.add_edge(cs.caller, cs.callee, sites=[cs], confidence=cs.confidence)

    def _collect_calls(self, m: _Module) -> None:
        seg = lambda n: (ast.get_source_segment(m.source, n) or "")[:200]

        def handle_scope(scope_node: ast.AST, qn: str, cls_qn: str | None, local_defs: dict[str, str],
                         self_name: str | None, inherited_imports: dict[str, str]) -> None:
            imports = dict(inherited_imports)
            var_types: dict[str, str] = {}   # var -> class qualname (instance)
            var_refs: dict[str, str] = {}    # var -> symbol qualname (the object itself)
            nodes = list(_children_no_nested(scope_node))
            nodes.sort(key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))

            def resolve_expr(d: list[str]) -> tuple[str | None, str, bool]:
                """-> (qualname, confidence, is_instance)"""
                head, rest = d[0], d[1:]
                if head == self_name and cls_qn:
                    if not rest:
                        return cls_qn, "inferred", True
                    meth = self.lookup_method(cls_qn, rest[0])
                    return (meth, "inferred", False) if meth and len(rest) == 1 else (None, "", False)
                if head in var_types:
                    if rest and len(rest) == 1:
                        meth = self.lookup_method(var_types[head], rest[0])
                        return (meth, "inferred", False) if meth else (None, "", False)
                    return (var_types[head], "inferred", True) if not rest else (None, "", False)
                if head in m.instances and head not in var_refs and head not in local_defs and head not in imports:
                    cq = self._resolve_in_module(m, m.instances[head])
                    if cq in self.classes:
                        if not rest:
                            return cq, "inferred", True
                        if len(rest) == 1 and (meth := self.lookup_method(cq, rest[0])):
                            return meth, "inferred", False
                        return None, "", False
                if head in var_refs:
                    r = self.resolve(".".join([var_refs[head], *rest]))
                    return (r, "inferred", False) if r else (None, "", False)
                if head in local_defs:
                    r = self.resolve(".".join([local_defs[head], *rest])) or (local_defs[head] if not rest else None)
                    return (r, "exact", False) if r else (None, "", False)
                target = imports.get(head) or m.bindings.get(head)
                if target and not target.startswith("__alias__"):
                    r = self.resolve(".".join([target, *rest]))
                    if r:
                        return r, "exact", False
                return None, "", False

            for n in nodes:
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    imports.update(self._import_bindings(m, n))
                elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                    var = n.targets[0].id
                    val = n.value
                    if isinstance(val, ast.Call) and (d := _dotted(val.func)):
                        r, _, _ = resolve_expr(d)
                        if r in self.classes:
                            var_types[var] = r
                    elif (d := _dotted(val)):
                        r, _, inst = resolve_expr(d)
                        if r and not inst:
                            var_refs[var] = r
                elif isinstance(n, ast.withitem) and isinstance(n.optional_vars, ast.Name) \
                        and isinstance(n.context_expr, ast.Call) and (d := _dotted(n.context_expr.func)):
                    r, _, _ = resolve_expr(d)
                    if r in self.classes:
                        var_types[n.optional_vars.id] = r
                elif isinstance(n, ast.Call):
                    self._handle_call(m, n, qn, cls_qn, resolve_expr, seg, imports)
                if isinstance(n, (ast.Dict, ast.List, ast.Tuple, ast.Set, ast.Assign)):
                    vals = n.values if isinstance(n, ast.Dict) else [n.value] if isinstance(n, ast.Assign) else n.elts
                    for v in vals:
                        if v is not None and (d := _dotted(v)):
                            r, _, inst = resolve_expr(d)
                            if r and not inst and self.nodes.get(r) and self.nodes[r].kind in ("function", "method"):
                                self.address_taken.add(r)

            # recurse into nested scopes (module-level defs are named mod.f, nested ones outer.f)
            prefix = m.name if isinstance(scope_node, ast.Module) else qn
            for stmt in _nested_scopes(scope_node):
                child_qn = f"{prefix}.{stmt.name}"
                if isinstance(stmt, ast.ClassDef):
                    if child_qn in self.classes:
                        handle_class_body(stmt, child_qn, local_defs, imports)
                    continue
                if child_qn not in self.nodes:
                    continue
                nested_defs = dict(local_defs)
                for s in stmt.body:
                    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        nested_defs[s.name] = f"{child_qn}.{s.name}"
                handle_scope(stmt, child_qn, None, nested_defs, None, imports)

        def handle_class_body(cls_node: ast.ClassDef, cqn: str, local_defs: dict[str, str], imports: dict[str, str]):
            for stmt in cls_node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    child_qn = f"{cqn}.{stmt.name}"
                    nested_defs = dict(local_defs)
                    for s in stmt.body:
                        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            nested_defs[s.name] = f"{child_qn}.{s.name}"
                    is_static = any(_dotted(dd) == ["staticmethod"] for dd in stmt.decorator_list)
                    first = stmt.args.args[0].arg if stmt.args.args else None
                    handle_scope(stmt, child_qn, cqn, nested_defs, None if is_static else first, imports)
                elif isinstance(stmt, ast.ClassDef) and f"{cqn}.{stmt.name}" in self.classes:
                    handle_class_body(stmt, f"{cqn}.{stmt.name}", local_defs, imports)

        module_defs = {k: v for k, v in m.bindings.items() if v.startswith(m.name + ".")}
        mod_qn = f"{m.name}.<module>"
        main_body: list[ast.stmt] = []
        for stmt in m.tree.body:
            if self._is_main_guard(stmt):
                main_body += stmt.body
        handle_scope(_ModuleNoMain(m.tree), mod_qn, None, module_defs, None, {})
        if main_body and m.package == PROJECT:
            main_qn = f"{m.name}.<main>"
            self._add_node(Node(main_qn, "main", m.package, str(m.file), main_body[0].lineno,
                                main_body[-1].end_lineno or main_body[0].lineno, entry="main"))
            handle_scope(ast.Module(body=main_body, type_ignores=[]), main_qn, None, module_defs, None, {})

    def _handle_call(self, m, call: ast.Call, caller: str, cls_qn, resolve_expr, seg, imports) -> None:
        self.stats["calls"] += 1
        keywords = {k.arg: seg(k.value) for k in call.keywords if k.arg}
        args = [seg(a) for a in call.args]
        raw = seg(call.func)
        callee, conf = None, ""

        # super().meth(...)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call) \
                and _dotted(call.func.value.func) == ["super"] and cls_qn:
            c = self.classes.get(cls_qn)
            mod = self.modules.get(c.module) if c else None
            for b in (c.bases if c else []):
                bq = self._resolve_in_module(mod, b) if mod else None
                if bq and (meth := self.lookup_method(bq, call.func.attr)):
                    callee, conf = meth, "inferred"
                    break
        elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call) \
                and (d := _dotted(call.func.value.func)):
            # Engine().run(...): method on a freshly constructed instance
            r, _, _ = resolve_expr(d)
            if r in self.classes and (meth := self.lookup_method(r, call.func.attr)):
                callee, conf = meth, "inferred"
        elif (d := _dotted(call.func)):
            if d[0] in BUILTINS and len(d) == 1 and d[0] not in m.bindings:
                self.stats["calls"] -= 1
                return
            r, c, _ = resolve_expr(d)
            if r:
                callee, conf = r, c
            elif (ext := self.external_name(m, d, imports)):
                callee, conf = ext, "exact"
                if ext not in self.nodes:
                    self._add_node(Node(ext, "external", ext.split(".")[0]))
        if callee is None and isinstance(call.func, ast.Attribute):
            cands = self._methods_by_name.get(call.func.attr, [])
            if call.func.attr not in NAME_FALLBACK_BLOCK and 0 < len(cands) <= NAME_FALLBACK_MAX:
                for cand in cands:
                    self._edge(CallSite(caller, cand, raw, str(m.file), call.lineno, "name", keywords, args))
                self.stats["name"] += 1
            else:
                self.stats["unresolved"] += 1
        elif callee is None:
            self.stats["unresolved"] += 1
        else:
            self.stats[conf] += 1
            self._edge(CallSite(caller, callee, raw, str(m.file), call.lineno, conf, keywords, args))

        # functions/classes passed as values: callbacks, Loader=FullLoader, view_func=...
        for val in [*call.args, *(k.value for k in call.keywords)]:
            if (d := _dotted(val)):
                r, _, inst = resolve_expr(d)
                if r and not inst and self.nodes.get(r) and self.nodes[r].kind in ("function", "method", "class"):
                    if self.nodes[r].kind != "class":
                        self.address_taken.add(r)  # passed as a callback / registered
                    self._edge(CallSite(caller, r, f"{raw}(…{'.'.join(d)}…)", str(m.file), call.lineno,
                                        "inferred", keywords, args))

    # ------------------------------------------------------------------ queries
    def entry_points(self) -> list[str]:
        return [q for q, n in self.nodes.items() if n.entry]

    def source_of(self, qualname: str, context: int = 0, max_lines: int = 80) -> str:
        n = self.nodes.get(qualname)
        if not n or not n.file:
            return ""
        lines = Path(n.file).read_text(errors="replace").splitlines()
        start = max(0, n.lineno - 1 - context)
        end = min(len(lines), n.end_lineno + context, start + max_lines)
        return "\n".join(f"{i + 1:5d}  {lines[i]}" for i in range(start, end))

    def coverage(self) -> float:
        s = self.stats
        return (s["exact"] + s["inferred"]) / s["calls"] if s["calls"] else 1.0


class _ModuleNoMain(ast.Module):
    """Module body minus the `if __name__ == '__main__':` block (handled as <main>)."""
    def __init__(self, tree: ast.Module):
        super().__init__(body=[s for s in tree.body if not CodeGraph._is_main_guard(s)], type_ignores=[])


def _nested_scopes(scope_node: ast.AST):
    """Direct nested function/class definitions of a scope (looking through if/try/with blocks)."""
    stack = list(ast.iter_child_nodes(scope_node))
    while stack:
        n = stack.pop(0)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield n
        elif isinstance(n, (ast.stmt, ast.excepthandler)):
            stack.extend(c for c in ast.iter_child_nodes(n) if isinstance(c, (ast.stmt, ast.excepthandler)))
