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

EVERY WEIGHT APPLIED PRODUCES A Contribution. The score is the sum of those
rows, so the table render.py displays IS the calculation rather than a second
account of it (§4). tests/test_score.py asserts the sum.
"""
from __future__ import annotations

from .models import Assessment, Contribution, Evidence, RiskLevel, Severity

# Bump on ANY weight or banding change. Stamped on every Assessment (§9.2) and
# stored with every decision from M2 (§10.3), so a past decision stays
# explicable after the table moves under it.
#
# 0.1.0 -> 0.2.0: §9.3's subtract-from-100 replaced by §9.4's start-at-60 with
#                 per-severity caps, plus maintenance, community and licensing.
# 0.2.0 -> 0.2.1: per-weight Contribution rows. No weight changed, but a stored
#                 score is now explicable at the row level, so the version
#                 moves to say which shape a stored Assessment has.
# 0.2.1 -> 0.3.0: maintainer and host DECLARATIONS -- npm `deprecated` (-25)
#                 and GitHub `disabled` (-25). New weights, so a minor bump:
#                 a score stored under 0.2.x cannot be reproduced under this
#                 table, which is exactly what §10.3 stores the version for.
SCORING_VERSION = "0.3.0"

# §9.4. Starting below the midpoint is the first of two structural fixes for
# the saturation recorded in NOTES-0_5 §2: a package about which nothing is
# known lands mid-scale, and positive signals must be EARNED. That encodes
# §3.3.2 -- "nothing known against this" is not "this is safe" -- in the
# arithmetic rather than only in a line of rendered text.
BASE = 60

# Per-finding cost, and the CAP on each severity's total. The cap is the second
# structural fix: in M0, axios@1.7.2's nineteen moderates cost 190 points and
# collapsed every long-tailed package onto zero, so one critical and thirty
# moderates scored identically. Capped, one critical still outweighs a pile of
# moderates -- which is what §3.3.4's "order your attention" requires.
_VULN_WEIGHTS: dict[Severity, tuple[int, int]] = {
    #              per finding, cap
    "critical":    (30, 60),
    "high":        (12, 36),
    "moderate":    (4, 12),
    "low":         (1, 5),
    # A finding whose severity could not be determined costs nothing. That is
    # fail-open, and only acceptable because render.py shows the finding by ID
    # regardless -- NOTES-0_4 §1.1(4).
    "unknown":     (0, 0),
}

# §9.4 specifies this; NOTES-0_5 §3 records why it is uncomfortable (the tool
# cannot ACT on a fix until M3's edit action) and lists the alternatives. Kept
# as specified, in one place, so the decision is a number rather than a rewrite.
FIX_CREDIT = 5

_PUBLISH_AGE = ((730, -15), (365, -8))
_PUBLISH_FRESH = (90, 8)
_DOWNLOADS = ((1_000_000, 10), (100_000, 5))
_DOWNLOADS_FLOOR = (1_000, -10)
# DECLARATIONS -- things a human deliberately said about this package, as
# opposed to signals inferred from activity. They are weighted heavier than any
# inference, because an inference can be wrong about intent and a statement
# cannot: "stop using this" is not a guess about staleness.
_DEPRECATED = -25        # the package's own maintainer
_DISABLED = -25          # GitHub, for DMCA / terms-of-service / abuse
_ARCHIVED = -20          # the maintainer, saying the repository is finished
_CONTRIBUTORS = (20, 8)
_SOLE_MAINTAINER = -8
_MANY_MAINTAINERS = (3, 5)
_NO_LICENSE = -5

# A package whose evidence is incomplete cannot reach "low". NOTES-M1 A.2: a
# failed GitHub lookup leaves `archived` as None, so an abandoned package never
# receives its -20 -- ABSENCE OF A NEGATIVE SIGNAL READS AS A POSITIVE ONE. A
# ceiling makes "clean" unreachable when we could not look, enforced by the
# code rather than by the reader noticing a warning. 69 is the top of "medium".
PARTIAL_CEILING = 69

# §9.5's thresholds. Note "medium", not "moderate": a finding is moderate, a
# package's risk is medium (models.py keeps them as separate Literals).
_BANDS = ((25, "critical"), (45, "high"), (70, "medium"))

# Ascending, so "at least X" is an index comparison rather than a chain of ifs.
# That ordering is what makes the override composable: the malware override in
# a later milestone is one more call to _at_least(), not a new mechanism.
_ORDER: tuple[RiskLevel, ...] = ("low", "medium", "high", "critical")


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


# ------------------------------- the pieces -----------------------------------

def _vulnerability_rows(evidence: Evidence) -> list[Contribution]:
    """One row per severity present, in display order (worst first).

    The label says when a cap applied, because "19 moderate findings" costing
    only 12 points is surprising unless the reason is on the line.
    """
    counts: dict[Severity, int] = {}
    for vuln in evidence.vulnerabilities:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1

    rows: list[Contribution] = []
    for severity in ("critical", "high", "moderate", "low", "unknown"):
        count = counts.get(severity, 0)  # type: ignore[arg-type]
        if not count:
            continue
        per_finding, cap = _VULN_WEIGHTS[severity]  # type: ignore[index]
        raw = count * per_finding
        capped = min(raw, cap)
        if capped == 0:
            # `unknown` weighs zero. Show the row anyway: a finding that costs
            # nothing still needs to appear, or the reader wonders why the
            # count in the header exceeds the rows in the table.
            rows.append(Contribution(
                label=f"{_plural(count, f'{severity} finding')} (not rated)",
                points=0))
            continue
        suffix = f" (capped at -{cap})" if raw > cap else ""
        rows.append(Contribution(
            label=f"{_plural(count, f'{severity} finding')}{suffix}",
            points=-capped))
    return rows


def _fix_credit_row(evidence: Evidence) -> Contribution | None:
    """§9.4's credit when every critical/high finding has a published fix.

    No critical or high findings at all means no credit: the credit rewards a
    REMEDIABLE situation, not the absence of one. A clean package is already
    rewarded by not losing points, and paying it twice would make "no findings"
    and "findings, all fixed" indistinguishable.
    """
    serious = [v for v in evidence.vulnerabilities
               if v.severity in ("critical", "high")]
    if not serious or not all(v.fixed_versions for v in serious):
        return None
    return Contribution(label="every serious finding has a published fix",
                        points=FIX_CREDIT)


def _declaration_rows(evidence: Evidence) -> list[Contribution]:
    """Statements, not inferences. Shown first after the findings.

    A deprecation notice is the only signal in the whole table that is a direct
    human statement of intent. Every other row is the tool inferring something
    from activity -- downloads, dates, counts -- and an inference can be wrong
    about intent in a way a statement cannot.

    The label carries the maintainer's MESSAGE, not just the fact, because the
    message usually says what to do instead ("use String.prototype.padStart()")
    and no weight can convey that.
    """
    rows: list[Contribution] = []
    registry = evidence.registry
    repository = evidence.repository

    if registry is not None and registry.deprecated:
        # The LABEL explains the number; the MESSAGE is rendered separately.
        # Interpolating the message here would push a 200-character string into
        # a 44-character table column and truncate the one part of it that is
        # actionable -- usually the "use X instead" at the end.
        rows.append(Contribution(label="deprecated by its maintainer",
                                 points=_DEPRECATED))

    if repository is not None and repository.disabled is True:
        rows.append(Contribution(
            label="repository disabled by GitHub", points=_DISABLED))

    # `is True` is for the reader, not for safety: archived is bool|None by the
    # time it arrives (Pydantic coerces, and github.parse() maps any non-bool
    # to None), so plain truthiness behaves identically. Mutation-tested and
    # confirmed neutral. Kept because the explicit form says what the three
    # states ARE.
    #
    # The property that DOES matter: archived=None contributes NOTHING, so an
    # abandoned package whose GitHub lookup failed never receives its -20 --
    # which is precisely what PARTIAL_CEILING contains (NOTES-M1 A.2).
    if repository is not None and repository.archived is True:
        rows.append(Contribution(label="repository is archived",
                                 points=_ARCHIVED))
    return rows


def _maintenance_rows(evidence: Evidence) -> list[Contribution]:
    rows: list[Contribution] = []
    registry = evidence.registry
    days = registry.days_since_last_publish if registry else None
    if days is not None:
        for threshold, weight in _PUBLISH_AGE:
            if days > threshold:
                rows.append(Contribution(
                    label=f"this version published {days} days ago",
                    points=weight))
                break
        else:
            if days < _PUBLISH_FRESH[0]:
                rows.append(Contribution(
                    label=f"published recently ({days} days ago)",
                    points=_PUBLISH_FRESH[1]))
    return rows


def _community_rows(evidence: Evidence) -> list[Contribution]:
    rows: list[Contribution] = []
    registry = evidence.registry
    repository = evidence.repository

    if registry is not None:
        downloads = registry.weekly_downloads
        if downloads is not None:
            for threshold, weight in _DOWNLOADS:
                if downloads >= threshold:
                    rows.append(Contribution(
                        label=f"{downloads:,} weekly downloads", points=weight))
                    break
            else:
                if downloads < _DOWNLOADS_FLOOR[0]:
                    rows.append(Contribution(
                        label=f"only {downloads:,} weekly downloads",
                        points=_DOWNLOADS_FLOOR[1]))

        maintainers = registry.maintainer_count
        if maintainers is not None:
            if maintainers >= _MANY_MAINTAINERS[0]:
                rows.append(Contribution(
                    label=f"{_plural(maintainers, 'npm maintainer')}",
                    points=_MANY_MAINTAINERS[1]))
            elif maintainers == 1:
                # The axios observation (NOTES-1_5 §2): one publishing account
                # with 114M weekly downloads. Worded to name the risk, not just
                # the count.
                rows.append(Contribution(
                    label="a single npm maintainer account",
                    points=_SOLE_MAINTAINER))

    if repository is not None and repository.contributors is not None:
        if repository.contributors >= _CONTRIBUTORS[0]:
            rows.append(Contribution(
                label=f"{repository.contributors:,} repository contributors",
                points=_CONTRIBUTORS[1]))
    return rows


def _license_row(evidence: Evidence) -> Contribution | None:
    """Charged only when the registry ANSWERED and reported no licence.

    registry=None means the lookup failed, and charging -5 for that would
    penalise a package for our own network trouble. §9.4's weights describe
    the package, never the collection.
    """
    if evidence.registry is None or evidence.registry.license:
        return None
    return Contribution(label="no licence declared", points=_NO_LICENSE)


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
    score floored at 0, risk forced critical, M3's amendment path disabled.
    When that lands it is another branch here.
    """
    band = _band(points)
    if _has_unfixed_critical(evidence):
        return _at_least(band, "high")
    return band


# --------------------------------- the API ------------------------------------

def score(evidence: Evidence) -> Assessment:
    """§9.4 + §9.5. Pure: same evidence, same Assessment, forever.

    The returned contributions sum EXACTLY to the returned score, including the
    clamp and the partial ceiling, which appear as their own rows. That makes
    the rendered table self-checking: if the column does not add up, something
    is wrong with the tool rather than with the reader's arithmetic.
    """
    rows: list[Contribution] = [Contribution(label="starting point", points=BASE)]
    rows.extend(_vulnerability_rows(evidence))

    credit = _fix_credit_row(evidence)
    if credit is not None:
        rows.append(credit)

    # Declarations before inferences: a reader scanning top-down should meet
    # "the maintainer told you to stop" before "it has a lot of downloads".
    rows.extend(_declaration_rows(evidence))
    rows.extend(_maintenance_rows(evidence))
    rows.extend(_community_rows(evidence))

    licence = _license_row(evidence)
    if licence is not None:
        rows.append(licence)

    raw = sum(row.points for row in rows)
    points = max(0, min(100, raw))
    if points != raw:
        # Shown rather than hidden: "the arithmetic said -22 and the scale stops
        # at 0" is a fact about this package, and a column that silently failed
        # to add up would undermine every other row.
        edge = "0" if raw < 0 else "100"
        rows.append(Contribution(
            label=f"the scale stops at {edge} (raw total {raw})",
            points=points - raw))

    if evidence.partial and points > PARTIAL_CEILING:
        # The most informative row in a degraded result: it says what the score
        # WOULD have been, which is how a reader learns the cap cost something
        # rather than that the package is mediocre.
        rows.append(Contribution(
            label=f"capped at {PARTIAL_CEILING}: evidence incomplete",
            points=PARTIAL_CEILING - points))
        points = PARTIAL_CEILING

    return Assessment(
        evidence=evidence,
        contributions=rows,
        score=points,
        risk=risk_of(points, evidence),
        scoring_version=SCORING_VERSION,
    )