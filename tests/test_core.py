"""Deterministic core: no network, no LLM."""

from pathlib import Path
from textwrap import dedent

import pytest

from vigil import deps, diffparse
from vigil.codegraph import PROJECT, CodeGraph
from vigil.reach import find_paths


def write(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(dedent(body))
    return root


@pytest.fixture
def lib_and_app(tmp_path):
    lib = write(tmp_path / "site", {
        "lib/__init__.py": """
            from .api import load, Loader
            from .core import *
        """,
        "lib/api.py": """
            from .core import Engine

            class Loader:
                def __init__(self, data):
                    self.data = data

            def load(data, loader=Loader):
                return Engine().run(data)

            def safe_load(data):
                return data
        """,
        "lib/core.py": """
            class Base:
                def run(self, data):
                    return self._dangerous(data)

                def _dangerous(self, data):
                    return eval(data)

            class Engine(Base):
                pass

            def register(fn):
                HANDLERS.append(fn)

            def handler(x):
                return x

            HANDLERS = [handler]
        """,
        "lib/framework.py": """
            class App:
                def __call__(self, environ):
                    return self.dispatch(environ)

                def dispatch(self, environ):
                    return environ
        """,
    })
    app = write(tmp_path / "proj", {
        "web.py": """
            from flask import Flask, request
            import lib
            from helpers import parse
            from lib.framework import App

            app = Flask(__name__)
            runtime = App()

            @app.route("/x", methods=["POST"])
            def endpoint():
                return parse(request.data)
        """,
        "helpers.py": """
            import lib as L

            def parse(raw):
                return L.load(raw)

            def unused(raw):
                return L.safe_load(raw)
        """,
    })
    cg = CodeGraph()
    cg.add_tree(app, PROJECT)
    cg.add_tree(lib, "lib", ["lib"])
    return cg.build()


def test_resolves_reexports_aliases_and_inheritance(lib_and_app):
    cg = lib_and_app
    assert cg.resolve("lib.load") == "lib.api.load"
    assert cg.resolve("lib.Engine") == "lib.core.Engine"          # via star import
    assert cg.lookup_method("lib.core.Engine", "run") == "lib.core.Base.run"
    assert cg.g.has_edge("helpers.parse", "lib.api.load")         # `import lib as L` alias
    edge = cg.g.edges["lib.api.load", "lib.core.Base.run"]        # Engine().run -> inherited method
    assert edge["confidence"] == "inferred"


def test_entry_points_detected(lib_and_app):
    entries = {q: cg_n.entry for q, cg_n in lib_and_app.nodes.items() if cg_n.entry}
    assert entries["web.endpoint"] == "http"
    assert entries["web.<module>"] == "import"


def test_reachability_finds_path_through_library_internals(lib_and_app):
    paths = find_paths(lib_and_app, ["lib.core.Base._dangerous"])
    assert paths, "expected a path"
    p = paths[0]
    assert p.entry == "web.endpoint" and p.entry_kind == "http"
    assert p.nodes == ["web.endpoint", "helpers.parse", "lib.api.load", "lib.core.Base.run", "lib.core.Base._dangerous"]


def test_unreachable_when_only_unused_code_calls_it(lib_and_app):
    assert find_paths(lib_and_app, ["lib.api.safe_load"]) == []


def test_default_argument_class_is_not_an_edge_but_callbacks_are_address_taken(lib_and_app):
    cg = lib_and_app
    assert "lib.core.handler" in cg.address_taken                 # stored in HANDLERS list


def test_framework_lifecycle_edges(lib_and_app):
    cg = lib_and_app
    # the app instantiates lib.framework.App, so its public/dunder methods are runtime-reachable
    assert cg.g.has_edge("lib.framework.App", "lib.framework.App.__call__")
    assert cg.g.edges["lib.framework.App", "lib.framework.App.dispatch"]["confidence"] == "inferred"


def test_diff_maps_hunks_to_functions_in_vulnerable_version(lib_and_app):
    diff = dedent("""\
        diff --git a/src/lib/core.py b/src/lib/core.py
        --- a/src/lib/core.py
        +++ b/src/lib/core.py
        @@ -40,7 +40,7 @@ class Base:
             def _dangerous(self, data):
        -        return eval(data)
        +        return literal_eval(data)
        diff --git a/tests/test_core.py b/tests/test_core.py
        @@ -1,1 +1,1 @@
        -assert x
        +assert y
        """)
    changed = diffparse.changed_functions(lib_and_app, diff, "lib")
    assert [c.qualname for c in changed] == ["lib.core.Base._dangerous"]


def test_parse_uv_compile_output():
    text = dedent("""\
        certifi==2026.10.23       # via requests
        flask==2.0.1              # via -r requirements.txt
        markupsafe==3.0.4         # via jinja2, werkzeug
        jinja2==3.1.6             # via flask
        requests==2.25.1          # via -r requirements.txt
        werkzeug==3.1.9           # via flask
        """)
    res = deps.parse_compiled(text)
    assert res.packages["flask"].direct and not res.packages["jinja2"].direct
    assert res.chain_to("markupsafe") in (["flask", "jinja2", "markupsafe"], ["flask", "werkzeug", "markupsafe"])
    assert res.packages_between({"markupsafe"}) == {"flask", "jinja2", "werkzeug", "markupsafe"}


def test_module_level_instance_method_calls_resolve(tmp_path):
    root = write(tmp_path, {
        "lib/__init__.py": "from .pool import PoolManager\n",
        "lib/pool.py": """
            class PoolManager:
                def request(self, method, url, **kw):
                    return self.urlopen(method, url, **kw)

                def urlopen(self, method, url, redirect=True, **kw):
                    return url
        """,
        "app.py": """
            import lib

            http = lib.PoolManager()

            def fetch(url):
                return http.request("GET", url, headers={"Cookie": "x"})
        """,
    })
    cg = CodeGraph()
    cg.add_tree(root, PROJECT, ["app"])
    cg.add_tree(root, "lib", ["lib"])
    cg.build()
    assert cg.g.has_edge("app.fetch", "lib.pool.PoolManager.request")
    site = cg.g.edges["app.fetch", "lib.pool.PoolManager.request"]["sites"][0]
    assert site.keywords == {"headers": '{"Cookie": "x"}'}
