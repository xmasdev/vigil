from vigil.codegraph import CallSite
from vigil.upgrade import _check_call, changelog_between


def site(args=(), **kw):
    return CallSite("app.f", "lib.g", "lib.g", "app.py", 3, "exact", dict(kw), list(args))


def test_new_required_param_detected():
    # PyYAML 6: def load(stream, Loader)
    assert [k for k, _ in _check_call(site(["fh"]), ["stream", "Loader"], "function")] == ["new_required_param"]
    assert _check_call(site(["fh"], Loader="yaml.SafeLoader"), ["stream", "Loader"], "function") == []
    assert _check_call(site(["fh", "yaml.FullLoader"]), ["stream", "Loader"], "function") == []


def test_removed_keyword_and_positional_overflow():
    issues = _check_call(site(["a", "b", "c"], verbose="True"), ["self", "a", "b="], "function")
    assert {k for k, _ in issues} == {"keyword_removed", "too_many_positional"}
    assert _check_call(site(["a", "b", "c"], verbose="1"), ["a", "*args", "**kw"], "function") == []


def test_changelog_sections_between_versions():
    text = "6.0 (2021-10-13)\n- Make Loader required for load()\n- drop py2\n\n5.4 (2021-01-19)\n- fix CVE\n\n5.3.1\n- old\n"
    chunks = changelog_between(text, "5.3.1", "6.0")
    assert any("Loader required" in c for c in chunks) and any("fix CVE" in c for c in chunks)
    assert not any("old" in c for c in chunks)
