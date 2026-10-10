"""render.py -- Assessment -> text. No I/O: returns strings, callers print.

Returning strings rather than printing is what makes the layout testable, and
it keeps the single print site in cli.py -- so §11.3's output-mode branch has
one place to live when --json arrives in M3.

This module is on the analysis path. §4: nothing on the analysis path may
execute an install. Enforced structurally in tests/test_render.py.
"""
from __future__ import annotations

from .models import Assessment, Severity, Unresolvable, Vulnerability
from .score import PARTIAL_CEILING


_ORDER: tuple[Severity, ...] = ("critical", "high", "unknown", "moderate", "low")

_ALWAYS_SHOWN = frozenset({"critical", "high", "unknown"})

_CAP = 5


# ============================== the score line ================================

# A short gloss per band. The band word says HOW bad; the gloss says what kind,
# which is what a reader scanning output needs.
#
# "low" carries §3.3.2's exact framing deliberately. The whole reason that band
# exists is that it does NOT mean safe, and "low risk" on its own reads as a
# clean bill of health.
_BAND_GLOSS = {
    "critical": "serious problems found",
    "high": "problems found",
    "medium": "some concerns",
    "low": "nothing known against this",
}

# When the ceiling ACTUALLY BOUND, the gloss says why the band is what it is
# rather than characterising the package. "some concerns" would be a claim
# about the package; the concern is that we could not finish looking, and §9.1
# is explicit that those must not read alike.
_PARTIAL_GLOSS = "capped -- evidence incomplete"

# Labels longer than this are the author's fault, not the terminal's. Capping
# keeps the number column off the right edge on a narrow terminal WITHOUT
# assuming a terminal width (§11.3): the column is sized from the content, and
# the content is bounded.
_MAX_LABEL = 44


def band_summary(a: Assessment) -> str:
    """'11/100 -- critical: serious problems found'

    The NUMBER stays, because a number is comparable between runs and across
    packages in a way a word is not. The band and gloss are added because a
    number alone gives the reader nothing to calibrate against: 47/100 means
    something only once you know where the lines are.
    """
    # `partial` ALONE IS THE WRONG CONDITION, and the first version of this
    # function used it. A degraded package with a critical finding scores 0,
    # the ceiling of 69 never binds, and "capped -- evidence incomplete" then
    # tells the reader the score would be higher if we had looked harder --
    # while hiding the real reason, which is that serious problems were found.
    # Confidently wrong in the reassuring direction, which is the one failure
    # shape this project keeps finding.
    #
    # Whether the ceiling bound is not a guess: it sets the score to exactly
    # PARTIAL_CEILING, so equality IS the condition. And the incompleteness is
    # never lost by dropping this gloss -- render_assessment prints the
    # DEGRADED block above every partial result.
    capped = a.evidence.partial and a.score == PARTIAL_CEILING
    gloss = _PARTIAL_GLOSS if capped else _BAND_GLOSS[a.risk]
    return f"{a.score}/100 -- {a.risk}: {gloss}"


def render_score_table(a: Assessment) -> list[str]:
    """The arithmetic, one weight per line, summing to the score.

    Width comes from the LONGEST LABEL, never a guessed terminal size.

    The first row prints without a sign: a starting point is not an adjustment,
    and "+60" reads as a bonus somebody earned.
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
# Placed AFTER the score line and BEFORE the findings, because it changes how
# everything below it reads. "No known vulnerabilities" means something
# different once you know the author has stopped maintaining the package: the
# first is a fact about today, and the second tells you nobody is looking.
#
# Below the findings it would be a footnote. Above the score it would displace
# the number the reader came for.

# Our headline for each signal, saying what it MEANS. Kept in one dict so the
# three statements read as one family rather than three ad-hoc strings.
_DECLARATIONS = {
    "deprecated": "the maintainer has asked you to stop using this package",
    "disabled": "GitHub has disabled this repository",
    "archived": "the maintainer has archived this repository",
}


def render_declarations(a: Assessment) -> list[str]:
    """The statements, quoted and attributed. [] when there are none.

    THE MESSAGE IS QUOTED, AND THAT IS A SECURITY DECISION, NOT A STYLE ONE.
    It is publisher-authored text sitting inside our own output, and a reader
    needs to see where our voice stops and theirs starts -- otherwise a message
    reading "all checks passed" borrows our authority. npm.py's sanitiser
    already guarantees the text cannot contain a quote-breaking newline or an
    escape sequence, so the quotes cannot be escaped out of; the two defences
    work together and neither is sufficient alone.

    The headline is OURS and says what the signal MEANS. "deprecated: true"
    is a field name; "the maintainer has asked you to stop using this package"
    is the same fact in a form someone can act on without knowing npm.
    """
    registry = a.evidence.registry
    repository = a.evidence.repository
    out: list[str] = []

    if registry is not None and registry.deprecated:
        out.append(f"  !  {_DECLARATIONS['deprecated']}")
        out.append(f'       the maintainer says: "{registry.deprecated}"')

    if repository is not None and repository.disabled is True:
        out.append(f"  !  {_DECLARATIONS['disabled']}")
        # No message to quote: GitHub does not say why, and GUESSING WHY WOULD
        # BE WORSE THAN SILENCE. It is DMCA, or terms-of-service, or abuse --
        # and naming the wrong one defames a maintainer over a trademark
        # dispute. We report the fact and say where to look.
        out.append("       GitHub does not say why; check the repository page")

    if repository is not None and repository.archived is True:
        out.append(f"  !  {_DECLARATIONS['archived']}")

    return ["", *out] if out else []


# ================================= findings ===================================

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
    """The glyph, which must not contradict the gloss beside it.

    `low` renders "nothing known against this", so the marker cannot be a
    tick: [ok] would reinstate exactly the clean-bill-of-health reading
    §3.3.2 forbids, two characters to the left of the sentence denying it.
    [--] means "nothing to flag", which is the honest claim.
    """
    if not a.evidence.sources:
        return "[--]"
    return "[--]" if a.risk == "low" else "[!!]"


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

    # 3. Score, band and gloss.
    if not ev.sources:
        out.append(f"{_marker(a)} no evidence")
        out.append("     every source failed; nothing is known either way")
        return "\n".join(out)

    out.append(f"{_marker(a)} {band_summary(a)}")

    # 4. What a human said about this package, before anything we inferred.
    out.extend(render_declarations(a))

    # 5. The arithmetic behind the number above.
    out.extend(render_score_table(a))

    # 6. Findings, grouped, capped, never silently truncated.
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

    # 7. Sources.
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