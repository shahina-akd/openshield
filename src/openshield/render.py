"""Render assessments as plain text. Returns strings; callers print.

On the analysis path, so it must not import anything that can execute an
install.
"""
from __future__ import annotations

from .models import Assessment, Severity, Unresolvable, Vulnerability
from .score import PARTIAL_CEILING


_ORDER: tuple[Severity, ...] = ("critical", "high", "unknown", "moderate", "low")

_ALWAYS_SHOWN = frozenset({"critical", "high", "unknown"})

_CAP = 5


# ============================== the score line ================================

# "low" deliberately avoids implying the package is safe.
_BAND_GLOSS = {
    "critical": "serious problems found",
    "high": "problems found",
    "medium": "some concerns",
    "low": "nothing known against this",
}

# Used when the partial-evidence ceiling set the score.
_PARTIAL_GLOSS = "capped -- evidence incomplete"

# Bounds the label column so the table width is content-sized but finite.
_MAX_LABEL = 44


def band_summary(a: Assessment) -> str:
    """'11/100 -- critical: serious problems found'"""
    # `partial` alone is not enough: a partial result scoring below the ceiling
    # was not capped, and saying so would hide the real reason. The DEGRADED
    # block still reports the incompleteness.
    capped = a.evidence.partial and a.score == PARTIAL_CEILING
    gloss = _PARTIAL_GLOSS if capped else _BAND_GLOSS[a.risk]
    return f"{a.score}/100 -- {a.risk}: {gloss}"


def render_score_table(a: Assessment) -> list[str]:
    """One row per contribution, then the total.

    The first row (the starting point) is unsigned because it is a baseline,
    not an adjustment.
    """
    if not a.contributions:
        return []
    width = min(_MAX_LABEL, max(len(c.label) for c in a.contributions))
    out = ["", "     score"]
    for index, row in enumerate(a.contributions):
        label = row.label[:width]
        number = f"{row.points}" if index == 0 else f"{row.points:+}"
        out.append(f"       {label:<{width}}  {number:>4}")
    out.append(f"       {'total':<{width}}  {a.score:>4}")
    return out


# ========================= maintainer declarations ============================
#
# Shown between the score line and the findings, since a deprecation changes
# how the findings should be read.

_DECLARATIONS = {
    "deprecated": "the maintainer has asked you to stop using this package",
    "disabled": "GitHub has disabled this repository",
    "archived": "the maintainer has archived this repository",
}


def render_declarations(a: Assessment) -> list[str]:
    """Declaration lines, or [] when there are none.

    The maintainer's message is quoted and attributed so it cannot be mistaken
    for the tool's own output. It is already sanitised by npm.parse, so it
    cannot break out of the quotes.
    """
    registry = a.evidence.registry
    repository = a.evidence.repository
    out: list[str] = []

    if registry is not None and registry.deprecated:
        out.append(f"  !  {_DECLARATIONS['deprecated']}")
        out.append(f'       the maintainer says: "{registry.deprecated}"')

    if repository is not None and repository.disabled is True:
        out.append(f"  !  {_DECLARATIONS['disabled']}")
        # GitHub does not say why, so no reason is guessed.
        out.append("       GitHub does not say why; check the repository page")

    if repository is not None and repository.archived is True:
        out.append(f"  !  {_DECLARATIONS['archived']}")

    return ["", *out] if out else []


# ================================= findings ===================================

def _grouped(vulns: list[Vulnerability]) -> list[tuple[Severity, list[Vulnerability]]]:
    """Findings grouped by severity in display order, omitting empty groups."""
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
    """Status marker. Never "[ok]", which would imply the package is safe."""
    if not a.evidence.sources:
        return "[--]"
    return "[--]" if a.risk == "low" else "[!!]"


def render_assessment(a: Assessment) -> str:
    ev = a.evidence
    out: list[str] = []

    if ev.partial:
        n = len(ev.degraded_sources)
        out.append(f"[!!] DEGRADED -- {n} source{'' if n == 1 else 's'} failed")
        out.extend(f"     {d}" for d in ev.degraded_sources)
        out.append("     the result below is incomplete")
        out.append("")

    # Always the canonical identity, never the specifier as typed.
    out.append(ev.package.canonical)

    if not ev.sources:
        out.append(f"{_marker(a)} no evidence")
        out.append("     every source failed; nothing is known either way")
        return "\n".join(out)

    out.append(f"{_marker(a)} {band_summary(a)}")
    out.extend(render_declarations(a))
    out.extend(render_score_table(a))

    # Findings: grouped, capped per group, with hidden counts stated.
    out.append("")
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

    out.append("")
    out.append("sources")
    for s in ev.sources:
        state = "cached" if s.from_cache else "live"
        out.append(f"  {s.name}   fetched {s.fetched_at:%Y-%m-%dT%H:%M:%SZ}   {state}")

    return "\n".join(out)


# ============================== unresolvables =================================

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