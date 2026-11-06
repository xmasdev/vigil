"""OSV advisory matching (deterministic) + fix-commit discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from .cache import cached_json, cached_text
from .deps import Resolution

OSV = "https://api.osv.dev/v1"
_COMMIT = re.compile(r"https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})")
_PULL = re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)")


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    package: str
    version: str
    summary: str
    details: str
    severity: str | None
    fixed_versions: list[str]
    fix_commits: list[str] = field(default_factory=list)  # URLs to .diff

    @property
    def cve(self) -> str | None:
        return next((a for a in [self.id, *self.aliases] if a.startswith("CVE-")), None)

    @property
    def display_id(self) -> str:
        return self.cve or self.id


def _get_vuln(vid: str) -> dict:
    return cached_json("osv-vuln", vid, lambda: httpx.get(f"{OSV}/vulns/{vid}", timeout=30).raise_for_status().json())


def _query(name: str, version: str) -> list[str]:
    def fetch():
        r = httpx.post(f"{OSV}/query", json={"package": {"name": name, "ecosystem": "PyPI"}, "version": version}, timeout=30)
        return [v["id"] for v in r.raise_for_status().json().get("vulns", [])]
    return cached_json("osv-query", f"{name}=={version}", fetch)


def _fix_commits(vuln: dict) -> list[str]:
    urls = []
    for ref in vuln.get("references", []):
        u = ref["url"]
        if m := _COMMIT.match(u):
            urls.append(f"https://github.com/{m[1]}/{m[2]}/commit/{m[3]}.diff")
        elif ref.get("type") == "FIX" and (m := _PULL.match(u)):
            urls.append(f"https://github.com/{m[1]}/{m[2]}/pull/{m[3]}.diff")
    return list(dict.fromkeys(urls))


def _fixed_versions(vuln: dict, pkg: str) -> list[str]:
    out = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower().replace("_", "-") != pkg:
            continue
        for rng in aff.get("ranges", []):
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(out))


def _severity(vuln: dict) -> str | None:
    sev = (vuln.get("database_specific") or {}).get("severity")
    return sev.upper() if isinstance(sev, str) else None


def match(resolution: Resolution) -> list[Advisory]:
    """All advisories affecting the resolved packages, de-duplicated across aliases
    (GHSA / PYSEC / CVE describe the same bug; prefer the GHSA record)."""
    advisories: list[Advisory] = []
    for pkg in resolution.packages.values():
        ids = _query(pkg.name, pkg.version)
        vulns = sorted((_get_vuln(i) for i in ids), key=lambda v: (not v["id"].startswith("GHSA"), v["id"]))
        seen: set[str] = set()
        for v in vulns:
            keys = {v["id"], *v.get("aliases", [])}
            if keys & seen:
                # merge fix commits from duplicate records
                for a in advisories:
                    if a.package == pkg.name and ({a.id, *a.aliases} & keys):
                        a.fix_commits = list(dict.fromkeys(a.fix_commits + _fix_commits(v)))
                continue
            seen |= keys
            advisories.append(Advisory(
                id=v["id"], aliases=v.get("aliases", []), package=pkg.name, version=pkg.version,
                summary=v.get("summary") or v.get("details", "")[:120], details=v.get("details", ""),
                severity=_severity(v), fixed_versions=_fixed_versions(v, pkg.name),
                fix_commits=_fix_commits(v),
            ))
    return advisories


def fetch_diff(url: str) -> str | None:
    def fetch() -> str:
        r = httpx.get(url, timeout=30, follow_redirects=True)
        return r.text if r.status_code == 200 else ""
    text = cached_text("diff", url, fetch)
    return text or None
