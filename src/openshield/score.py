"""score.py -- Evidence -> Assessment. PURE.

No network, no file I/O, no clock, no randomness. §9.2 requires this and
tests/test_score.py enforces it structurally: this module's own imports are
parsed, and anything that can read the world fails the suite.

A score that depends on when you ran it cannot be golden-tested and cannot
explain a decision you made three months ago -- which is exactly what §10.3
stores scoring_version in order to do. M1 adds age signals, which is the
moment someone reaches for datetime.now(). The age belongs in the COLLECTOR's
parse(), which is where it is (NOTES-M1 B.2); this module receives integers and
never learns what day it is.
"""
from __future__ import annotations

from typing import Literal

from .models import Assessment, Evidence, RiskLevel, Severity

# Bump on ANY weight or banding change. Stamped on every Assessment (§9.2) and
# stored with every decision from M2 (§10.3), so a past decision stays
# explicable after the table moves under it.
#
# 0.1.0 -> 0.2.0: §9.3's subtract-from-100 replaced by §9.4's start-at-60 with
# per-severity caps, plus maintenance, community and licensing signals.
SCORING_VERSION = "0.2.0"

# §9.4. Starting below the midpoint is the first of two structural fixes for
# the saturation recorded in NOTES-0_5 §2: a package about which nothing is
# known now lands mid-scale, and positive signals must be EARNED. That encodes
# §3.3.2 -- "nothing known against this" is not "this is safe" -- in the
# arithmetic rather than only in a line of rendered text.
BASE = 60

# Per-finding costs, and the CAP on each severity's total contribution. The cap
# is the second structural fix: in M0, axios@1.7.2's nineteen moderates cost
# 190 points and collapsed every package with a long tail onto zero, so a
# package with one critical and a package with thirty moderates scored
# identically. Capped, one critical still outweighs a pile of moderates --
# which is what "ordering your attention" (§3.3.4) actually requires.
_VULN_WEIGHTS: dict[Severity, tuple[int, int]] = {
    #              per finding, cap
    "critical":    (30, 60),
    "high":        (12, 36),
    "moderate":    (4, 12),
    "low":         (1, 5),
    # A finding whose severity could not be determined costs nothing. That is
    # fail-open, and it is only acceptable because render.py shows the finding
    # by ID regardless -- see NOTES-0_4 §1.1(4).
    "unknown":     (0, 0),
}

# Every critical/high finding has a published fix. §9.4 specifies this credit;
# NOTES-0_5 §3 records why it is uncomfortable (the tool cannot ACT on a fix
# until M3's edit action) and lists the alternatives. Kept as specified, set to
# a single place so the decision is one number rather than a code change.
FIX_CREDIT = 5

# §9.4 maintenance, community, licensing. Tuples of (threshold, points),
# evaluated in order, first match wins -- so a package published 900 days ago
# takes -15 and not -15 AND -8.
_PUBLISH_AGE = ((730, -15), (365, -8))
_PUBLISH_FRESH = (90, 8)
_DOWNLOADS = ((1_000_000, 10), (100_000, 5))
_DOWNLOADS_FLOOR = (1_000, -10)
_ARCHIVED = -20
_CONTRIBUTORS = (20, 8)
_SOLE_MAINTAINER = -8
_MANY_MAINTAINERS = (3, 5)
_NO_LICENSE = -5

# A package whose evidence is incomplete cannot reach "low". NOTES-M1 A.2:
# a failed GitHub lookup leaves `archived` as None, so an abandoned package
# simply does not receive its -20 -- ABSENCE OF A NEGATIVE SIGNAL READS AS A
# POSITIVE ONE. A ceiling makes "clean" unreachable when we could not look,
# which is the honest claim, and it is enforced by the code rather than by the
# reader noticing a warning. 69 is the top of "medium" under §9.5.
PARTIAL_CEILING = 69

# §9.5's thresholds, and the band vocabulary. Note "medium", not "moderate":
# a finding is moderate, a package's risk is medium (models.py keeps them as
# separate Literals so a mix-up is a type error).
_BANDS = ((25, "critical"), (45, "high"), (70, "medium"))

# Ascending, so "at least X" is an index comparison rather than a chain of ifs.
# This ordering is what makes the override composable: the malware override in
# a later milestone is one more call to _at_least(), not a new mechanism.
_ORDER: tuple[RiskLevel, ...] = ("low", "medium", "high", "critical")


# ------------------------------- the pieces -----------------------------------

def _vulnerability_points(evidence: Evidence) -> int:
    """Sum the per-severity costs, each capped at its own ceiling."""
    totals: dict[Severity, int] = {}
    for vuln in evidence.vulnerabilities:
        per_finding, _ = _VULN_WEIGHTS[vuln.severity]
        totals[vuln.severity] = totals.get(vuln.severity, 0) + per_finding

    points = 0
    for severity, raw in totals.items():
        _, cap = _VULN_WEIGHTS[severity]
        points -= min(raw, cap)
    return points


def _fix_credit(evidence: Evidence) -> int:
    """§9.4's credit when every critical/high finding has a published fix.

    No critical or high findings at all means no credit: the credit rewards a
    remediable situation, not the absence of one. A clean package is already
    being rewarded by not losing points.
    """
    serious = [v for v in evidence.vulnerabilities
               if v.severity in ("critical", "high")]
    if not serious:
        return 0
    return FIX_CREDIT if all(v.fixed_versions for v in serious) else 0


def _maintenance_points(evidence: Evidence) -> int:
    points = 0
    repository = evidence.repository
    registry = evidence.registry

    # `is True` is for the reader, not for safety: archived is bool|None by
    # the time it arrives here (Pydantic coerces, and github.parse() already
    # maps any non-bool to None), so `if repository.archived:` would behave
    # identically. Mutation-tested and confirmed neutral. Kept because the
    # explicit form says what the three states ARE.
    #
    # The property that DOES matter is below: archived=None contributes
    # NOTHING. An abandoned package whose GitHub lookup failed therefore does
    # not receive its -20, which is absence of a negative signal reading as a
    # positive one -- and is precisely what PARTIAL_CEILING contains
    # (NOTES-M1 A.2).
    if repository is not None and repository.archived is True:
        points += _ARCHIVED

    days = registry.days_since_last_publish if registry else None
    if days is not None:
        for threshold, weight in _PUBLISH_AGE:
            if days > threshold:
                points += weight
                break
        else:
            if days < _PUBLISH_FRESH[0]:
                points += _PUBLISH_FRESH[1]
    return points


def _community_points(evidence: Evidence) -> int:
    points = 0
    registry = evidence.registry
    repository = evidence.repository

    if registry is not None:
        downloads = registry.weekly_downloads
        if downloads is not None:
            for threshold, weight in _DOWNLOADS:
                if downloads >= threshold:
                    points += weight
                    break
            else:
                if downloads < _DOWNLOADS_FLOOR[0]:
                    points += _DOWNLOADS_FLOOR[1]

        maintainers = registry.maintainer_count
        if maintainers is not None:
            if maintainers >= _MANY_MAINTAINERS[0]:
                points += _MANY_MAINTAINERS[1]
            elif maintainers == 1:
                points += _SOLE_MAINTAINER

    if repository is not None and repository.contributors is not None:
        if repository.contributors >= _CONTRIBUTORS[0]:
            points += _CONTRIBUTORS[1]
    return points


def _license_points(evidence: Evidence) -> int:
    """Charged only when the registry ANSWERED and reported no licence.

    registry=None means the lookup failed, and charging -5 for that would be
    penalising a package for our own network trouble. §9.4's weights describe
    the package, never the collection.
    """
    if evidence.registry is None:
        return 0
    return 0 if evidence.registry.license else _NO_LICENSE


# -------------------------------- banding -------------------------------------

def _band(points: int) -> RiskLevel:
    for threshold, level in _BANDS:
        if points < threshold:
            return level  # type: ignore[return-value]
    return "low"


def _at_least(level: RiskLevel, floor: RiskLevel) -> RiskLevel:
    """Raise a band to a floor, never lower it."""
    return level if _ORDER.index(level) >= _ORDER.index(floor) else floor


def _has_unfixed_critical(evidence: Evidence) -> bool:
    """A critical finding with no published fix.

    Empty fixed_versions is the signal -- and per NOTES-0_4 §8.2 it is a fact
    OSV states, not an absence of data.
    """
    return any(v.severity == "critical" and not v.fixed_versions
               for v in evidence.vulnerabilities)


def risk_of(points: int, evidence: Evidence) -> RiskLevel:
    """§9.5. The override is an explicit branch, NOT a large weight.

    A weight can always be out-earned: enough downloads and contributors will
    eventually out-argue any number subtracted for an unfixable critical, and
    the one finding that should never be softened by popularity is exactly that
    one. An early return cannot be out-earned.

    This is also the ancestor of the malware override (§9.5's forward note):
    score floored at 0, risk forced critical, M3's amendment path disabled
    outright. When that lands it is another branch here, not another row in
    _VULN_WEIGHTS.
    """
    band = _band(points)
    if _has_unfixed_critical(evidence):
        return _at_least(band, "high")
    return band


# --------------------------------- the API ------------------------------------

def score(evidence: Evidence) -> Assessment:
    """§9.4 + §9.5. Pure: same evidence, same Assessment, forever."""
    points = BASE
    points += _vulnerability_points(evidence)
    points += _fix_credit(evidence)
    points += _maintenance_points(evidence)
    points += _community_points(evidence)
    points += _license_points(evidence)

    points = max(0, min(100, points))

    # The ceiling applies AFTER the clamp and BEFORE banding, so a degraded
    # package can never present as "low" however good its surviving signals.
    if evidence.partial:
        points = min(points, PARTIAL_CEILING)

    return Assessment(
        evidence=evidence,
        score=points,
        risk=risk_of(points, evidence),
        scoring_version=SCORING_VERSION,
    )