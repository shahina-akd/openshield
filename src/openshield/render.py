"""render.py -- Assessment -> text. No I/O: returns strings, callers print.

Returning strings rather than printing is what makes the layout testable, and
it keeps the single print site in cli.py -- so §11.3's output-mode branch has
one place to live when --json arrives in M3.

This module is on the analysis path. §4: nothing on the analysis path may
execute an install. Enforced structurally in tests/test_render.py.
"""
from __future__ import annotations

from .models import Assessment, Evidence, Severity, Unresolvable, Vulnerability


_ORDER: tuple[Severity, ...] = ("critical", "high", "unknown", "moderate", "low")

_ALWAYS_SHOWN = frozenset({"critical", "high", "unknown"})

_CAP = 5


def _grouped(vulns: list[Vulnerability]) -> list[tuple[Severity, list[Vulnerability]]]:
    """Severity -> findings, in display order, skipping empty groups."""
    buckets: dict[Severity, list[Vulnerability]] = {s: [] for s in _ORDER}
    for v in vulns:
        buckets[v.severity].append(v)
    return [(s, buckets[s]) for s in _ORDER if buckets[s]]


def _counts_line(groups) -> str:
    total = sum(len(v) for _, v in groups)
    parts = ", ".join(f"{len(v)} {s}" for s, v in groups)
    noun = "finding" if total == 1 else "findings"
    return f"{total} {noun}: {parts}"

def _marker(a: Assessment) -> str:
    if not a.evidence.sources:
        return "[--]"
    return "[ok]" if a.risk == "low" else "[!!]"


def render_assessment(a: Assessment) -> str:
    ev = a.evidence
    out: list[str] = []

    # 1. DEGRADED FIRST
    if ev.partial:
        n = len(ev.degraded_sources)
        out.append(f"[!!] DEGRADED -- {n} source{'' if n == 1 else 's'} failed")
        out.extend(f"     {d}" for d in ev.degraded_sources)
        out.append("     the result below is incomplete")
        out.append("")

    # 2. Identity -- canonical, always. Never the specifier the user typed.
    out.append(ev.package.canonical)

    # 3. Score and risk.
    if not ev.sources:
        out.append(f"{_marker(a)} no evidence")
        out.append("     every source failed; nothing is known either way")
        return "\n".join(out)

    out.append(f"{_marker(a)} {a.score}/100 -- {a.risk}")

    # 4. Findings, grouped, capped, never silently truncated.
    groups = _grouped(ev.vulnerabilities)
    if not groups:
        out.append("     no known vulnerabilities")
        out.append("     (nothing known against this -- not the same as safe)")
    else:
        out.append(f"     {_counts_line(groups)}")
        for severity, found in groups:
            out.append("")
            out.append(f"     {severity}")
            limit = len(found) if severity in _ALWAYS_SHOWN else _CAP
            for v in found[:limit]:
                fixed = (f"fixed in {', '.join(v.fixed_versions)}"
                         if v.fixed_versions else "no fix published")
                out.append(f"       {v.id}   {fixed}")
                if v.summary:
                    out.append(f"         {v.summary}")
            hidden = len(found) - limit
            if hidden > 0:
                out.append(f"       ... {hidden} more")

    # 5. Sources.
    out.append("")
    out.append("sources")
    for s in ev.sources:
        state = "cached" if s.from_cache else "live"
        out.append(f"  {s.name}   fetched {s.fetched_at:%Y-%m-%dT%H:%M:%SZ}   {state}")

    return "\n".join(out)

_REASON_HELP = {
    "range": "ranges are not resolved -- pin an exact version to review it",
    "tag": "dist-tags are not resolved -- pin an exact version",
    "alias": "package aliases are not resolved",
    "local_path": "local paths are not reviewed",
    "vcs": "git and GitHub shorthand specifiers are not reviewed",
    "tarball": "tarball URLs are not reviewed",
    "not_found": "no such package or version in the registry",
    "network": "the registry could not be reached",
    "unknown": "this specifier form is not recognised",
}


def render_unresolvable(u: Unresolvable) -> str:
    out = [f"[--] {u.specifier} -- unresolvable ({u.reason})"]
    if u.detail:
        out.append(f"     {u.detail}")
    help_text = _REASON_HELP.get(u.reason)
    if help_text:
        out.append(f"     {help_text}")
    return "\n".join(out)