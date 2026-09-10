"""score.py -- Evidence -> Assessment. PURE.

No network, no file I/O, no clock, no randomness. §9.2 requires this and
tests/test_score.py enforces it structurally: the module's own imports are
parsed and anything that can read the world fails the suite.

A score that depends on when you ran it cannot be golden-tested and cannot
explain a decision you made three months ago -- which is exactly what §10.3
stores scoring_version in order to do.
"""
from __future__ import annotations

from .models import Assessment, Evidence, RiskLevel, Severity

# Bump on ANY weight or banding change. Stamped on every Assessment (§9.2) and
# stored with every decision from M2 (§10.3), so a past decision stays
# explicable after the table moves under it.
SCORING_VERSION = "0.1.0"

# §9.3. Subtract-only from 100, which M1 replaces wholesale -- see the note at
# the end of this file's tests about what 31 findings do to this table.
_WEIGHTS: dict[Severity, int] = {
    "critical": 40,
    "high": 20,
    "moderate": 10,
    "low": 3,
    # A finding whose severity could not be determined costs nothing. That is
    # fail-open, and it is only acceptable because render.py shows the finding
    # by ID regardless -- see NOTES-0_4.md §1.1(4).
    "unknown": 0,
}

def score(evidence: Evidence) -> Assessment:
    """§9.3: start at 100, subtract per finding, clamp to [0, 100]."""
    points = 100
    for vuln in evidence.vulnerabilities:
        points -= _WEIGHTS[vuln.severity]
    points = max(0, min(100, points))

    return Assessment(
        evidence=evidence,
        score=points,
        risk=risk_of(points, evidence),
        scoring_version=SCORING_VERSION,
    )

# §9.5, ordered ascending so "at least X" is an index comparison rather than a
# chain of ifs. The ordering is what makes the override composable: M1 adds no
# new mechanism, and the malware override in a later milestone is one more call
# to _at_least().
_ORDER: tuple[RiskLevel, ...] = ("low", "medium", "high", "critical")


def _band(points: int) -> RiskLevel:
    """§9.5's thresholds. Note the vocabulary: bands are low/medium/high/
    critical -- 'medium', not 'moderate'. 'moderate' is a severity."""
    if points < 25:
        return "critical"
    if points < 45:
        return "high"
    if points < 70:
        return "medium"
    return "low"


def _at_least(level: RiskLevel, floor: RiskLevel) -> RiskLevel:
    """Raise a band to a floor, never lower it."""
    return level if _ORDER.index(level) >= _ORDER.index(floor) else floor


def _has_unfixed_critical(evidence: Evidence) -> bool:
    """A critical-severity finding with no published fix. Empty fixed_versions
    is the signal -- and per NOTES-0_4.md §8.2 it is a fact OSV states, not an
    absence of data."""
    return any(
        v.severity == "critical" and not v.fixed_versions
        for v in evidence.vulnerabilities
    )


def risk_of(points: int, evidence: Evidence) -> RiskLevel:
    """§9.5. The override is an explicit branch, NOT a large weight.

    A weight can always be out-earned: enough downloads and contributors will
    eventually out-argue any number you subtract for an unfixable critical, and
    the one finding that should never be softened by popularity is exactly that
    one. An early return cannot be out-earned.

    This is also the ancestor of the malware override (§9.5 forward note):
    score floored at 0, risk forced critical, M3's amendment path disabled
    outright. When that lands it is another branch here, not another row in
    _WEIGHTS.
    """
    band = _band(points)
    if _has_unfixed_critical(evidence):
        return _at_least(band, "high")
    return band