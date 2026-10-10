"""The 1.5b additions to render.py."""
from openshield.models import Assessment

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

# When evidence is incomplete, the gloss says WHY the band is what it is rather
# than characterising the package. "some concerns" would be a claim about the
# package; the concern is that we could not finish looking, and §9.1 is
# explicit that those must not read alike.
_PARTIAL_GLOSS = "capped -- evidence incomplete"

# Labels longer than this are the author's fault, not the terminal's. Capping
# keeps the number column off the right edge on a narrow terminal WITHOUT
# assuming a terminal width (§11.3): the column is sized from the content, and
# the content is bounded.
_MAX_LABEL = 44


def band_summary(a: Assessment) -> str:
    """'11/100 -- critical: serious problems found'"""
    gloss = _PARTIAL_GLOSS if a.evidence.partial else _BAND_GLOSS[a.risk]
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