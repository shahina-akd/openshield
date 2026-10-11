"""Evidence -> Assessment. Pure: no network, I/O, clock or randomness.

Every weight applied produces a Contribution row, and the rows sum to the
score, so the displayed table is the calculation itself.
"""
from __future__ import annotations

from .models import Assessment, Contribution, Evidence, RiskLevel, Severity

# Bump on any weight or banding change; stored with each assessment so past
# scores remain explicable.
SCORING_VERSION = "0.3.0"

# Starting below the midpoint means positive signals must be earned: a package
# with no known information is not scored as safe.
BASE = 60

# (cost per finding, cap per severity). The cap stops many moderate findings
# from outweighing a single critical.
_VULN_WEIGHTS: dict[Severity, tuple[int, int]] = {
    #              per finding, cap
    "critical":    (30, 60),
    "high":        (12, 36),
    "moderate":    (4, 12),
    "low":         (1, 5),
    # Costs nothing, but is still shown by ID in the findings list.
    "unknown":     (0, 0),
}

FIX_CREDIT = 5

_PUBLISH_AGE = ((730, -15), (365, -8))
_PUBLISH_FRESH = (90, 8)
_DOWNLOADS = ((1_000_000, 10), (100_000, 5))
_DOWNLOADS_FLOOR = (1_000, -10)
# Explicit statements are weighted above inferred signals.
_DEPRECATED = -25        # by the maintainer
_DISABLED = -25          # by GitHub
_ARCHIVED = -20          # by the maintainer
_CONTRIBUTORS = (20, 8)
_SOLE_MAINTAINER = -8
_MANY_MAINTAINERS = (3, 5)
_NO_LICENSE = -5

# Incomplete evidence cannot score "low": a missing signal (e.g. an unknown
# archived state) must not read as a clean one. 69 is the top of "medium".
PARTIAL_CEILING = 69

_BANDS = ((25, "critical"), (45, "high"), (70, "medium"))

# Ascending, so "at least X" is an index comparison.
_ORDER: tuple[RiskLevel, ...] = ("low", "medium", "high", "critical")


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


# ------------------------------- the pieces -----------------------------------

def _vulnerability_rows(evidence: Evidence) -> list[Contribution]:
    """One row per severity present, worst first, noting when a cap applied."""
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
            # Shown so the table accounts for every finding counted.
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
    """Credit when every critical or high finding has a published fix.

    Not given when there are no such findings, so "no findings" and "all
    findings fixed" stay distinguishable.
    """
    serious = [v for v in evidence.vulnerabilities
               if v.severity in ("critical", "high")]
    if not serious or not all(v.fixed_versions for v in serious):
        return None
    return Contribution(label="every serious finding has a published fix",
                        points=FIX_CREDIT)


def _declaration_rows(evidence: Evidence) -> list[Contribution]:
    """Rows for explicit statements: deprecation, disabled, archived."""
    rows: list[Contribution] = []
    registry = evidence.registry
    repository = evidence.repository

    if registry is not None and registry.deprecated:
        # The message is rendered separately; the label must fit the table.
        rows.append(Contribution(label="deprecated by its maintainer",
                                 points=_DEPRECATED))

    if repository is not None and repository.disabled is True:
        rows.append(Contribution(
            label="repository disabled by GitHub", points=_DISABLED))

    # archived=None (unknown) contributes nothing; PARTIAL_CEILING covers it.
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
    """Charged only when the registry answered and declared no licence, so a
    failed lookup is not penalised."""
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
    return any(v.severity == "critical" and not v.fixed_versions
               for v in evidence.vulnerabilities)


def risk_of(points: int, evidence: Evidence) -> RiskLevel:
    """Band the score, forcing at least "high" for an unfixed critical.

    This is a separate rule rather than a large weight, so positive signals
    can never offset it.
    """
    band = _band(points)
    if _has_unfixed_critical(evidence):
        return _at_least(band, "high")
    return band


# --------------------------------- the API ------------------------------------

def score(evidence: Evidence) -> Assessment:
    """Score evidence. The returned rows sum exactly to the score, including
    clamping and the partial ceiling, which appear as their own rows."""
    rows: list[Contribution] = [Contribution(label="starting point", points=BASE)]
    rows.extend(_vulnerability_rows(evidence))

    credit = _fix_credit_row(evidence)
    if credit is not None:
        rows.append(credit)

    # Explicit statements are listed before inferred signals.
    rows.extend(_declaration_rows(evidence))
    rows.extend(_maintenance_rows(evidence))
    rows.extend(_community_rows(evidence))

    licence = _license_row(evidence)
    if licence is not None:
        rows.append(licence)

    raw = sum(row.points for row in rows)
    points = max(0, min(100, raw))
    if points != raw:
        edge = "0" if raw < 0 else "100"
        rows.append(Contribution(
            label=f"the scale stops at {edge} (raw total {raw})",
            points=points - raw))

    if evidence.partial and points > PARTIAL_CEILING:
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