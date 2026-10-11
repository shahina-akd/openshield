"""score.py --  weights, bands, and the override.

One file, because the weights, the bands and the override all break when the
same two spec sections move, and SCORING_VERSION covers all three.

Every fixture is HAND-BUILT Evidence. No network, no respx, no cache --
score() is pure, so a test that needed any of those would be testing something
else.
"""
from datetime import datetime, timezone
from typing import get_args

import pytest

from openshield.models import (
    Evidence,
    PackageRef,
    RegistryInfo,
    RepositoryInfo,
    RiskLevel,
    Severity,
    SourceRef,
    Vulnerability,
)
from openshield.score import (
    BASE,
    FIX_CREDIT,
    PARTIAL_CEILING,
    SCORING_VERSION,
    _at_least,
    _band,
    _VULN_WEIGHTS,
    score,
)

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")


def vuln(severity, fixed=("9.9.9",), id="GHSA-x"):
    return Vulnerability(id=id, severity=severity,
                         fixed_versions=list(fixed), source=SOURCE)


def vulns(severity, count, fixed=("9.9.9",)):
    return [vuln(severity, fixed, id=f"GHSA-{severity}-{i}") for i in range(count)]


def ev(*vulnerabilities, registry=None, repository=None,
       partial=False, degraded=()):
    return Evidence(
        package=REF,
        vulnerabilities=list(vulnerabilities),
        registry=registry,
        repository=repository,
        sources=[SOURCE],
        partial=partial,
        degraded_sources=list(degraded),
    )


# Reusable signal bundles.
HEALTHY_REGISTRY = RegistryInfo(maintainer_count=5, license="MIT",
                                weekly_downloads=50_000_000,
                                days_since_last_publish=30,
                                repository_owner="axios", repository_name="axios")
HEALTHY_REPO = RepositoryInfo(archived=False, days_since_last_push=3,
                              contributors=400, stars=100_000)
ABANDONED_REGISTRY = RegistryInfo(maintainer_count=1, license=None,
                                  weekly_downloads=200,
                                  days_since_last_publish=1_200)
ABANDONED_REPO = RepositoryInfo(archived=True, days_since_last_push=1_100,
                                contributors=3, stars=40)


# ------------------------------------------------------------------------------
# 1. The vocabulary -- structural, before any arithmetic
# ------------------------------------------------------------------------------

def test_every_severity_has_a_weight_and_a_cap():
    assert set(_VULN_WEIGHTS) == set(get_args(Severity))


def test_every_band_is_a_valid_risk_level():
    for points in (0, 24, 25, 44, 45, 69, 70, 100):
        assert _band(points) in get_args(RiskLevel)


def test_severity_and_risk_stay_different_vocabularies():
    assert "medium" not in get_args(Severity)       # band
    assert "moderate" not in get_args(RiskLevel)    # finding


# ------------------------------------------------------------------------------
# 2. Golden scores -- fixed Evidence in, exact number out
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("evidence,expected", [
    # Nothing collected, nothing known. The headline change from M0: a package
    # about which we know nothing lands MID-SCALE, not at a perfect 100.
    (ev(), BASE),

    # One finding of each severity, each with a fix.
    (ev(vuln("critical")), 60 - 30 + FIX_CREDIT),
    (ev(vuln("high")), 60 - 12 + FIX_CREDIT),
    (ev(vuln("moderate")), 60 - 4),
    (ev(vuln("low")), 60 - 1),
    (ev(vuln("unknown")), 60),              # weighted zero, deliberately

    # THE CAPS -- the fix for NOTES-0_5 §2's saturation.
    (ev(*vulns("critical", 5)), 60 - 60 + FIX_CREDIT),      # -150 capped to -60
    (ev(*vulns("high", 10)), 60 - 36 + FIX_CREDIT),         # -120 capped to -36
    (ev(*vulns("moderate", 19)), 60 - 12),                  # -76  capped to -12
    (ev(*vulns("low", 20)), 60 - 5),                        # -20  capped to -5

    # Caps are PER SEVERITY, not shared. Chosen to stay inside [0,100] so
    # this row tests the caps rather than the clamp, which has its own test:
    # ten highs cap at -36, ten moderates cap at -12, and 60-36-12+5 = 17.
    (ev(*vulns("high", 10), *vulns("moderate", 10)),
     60 - 36 - 12 + FIX_CREDIT),
])
def test_golden_scores(evidence, expected):
    assert score(evidence).score == expected


def test_a_healthy_popular_package_lands_in_low():
    result = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO))
    assert result.score == 91
    assert result.risk == "low"


def test_an_abandoned_unpopular_package_lands_in_high_or_worse():
    result = score(ev(registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO))
    assert result.score == 2
    assert result.risk == "critical"


def test_one_high_with_a_fix_on_an_otherwise_healthy_package():
    result = score(ev(vuln("high"), registry=HEALTHY_REGISTRY,
                      repository=HEALTHY_REPO))
    assert result.score == 84
    assert result.risk == "low"


@pytest.mark.parametrize("count", [3, 10, 60])
def test_the_scale_is_clamped_not_overflowed(count):
    assert score(ev(*vulns("critical", count),
                    registry=ABANDONED_REGISTRY,
                    repository=ABANDONED_REPO)).score == 0


def test_the_same_evidence_scores_identically_twice():
    evidence = ev(vuln("high"), registry=HEALTHY_REGISTRY)
    first, second = score(evidence), score(evidence)
    assert (first.score, first.risk, first.scoring_version) == \
           (second.score, second.risk, second.scoring_version)


def test_the_assessment_is_stamped_with_the_new_version():
    assert score(ev()).scoring_version == SCORING_VERSION == "0.3.0"


# ------------------------------------------------------------------------------
# 3. None is not False, and not zero -- NOTES-M1 A.2 at the scoring site
# ------------------------------------------------------------------------------

def test_archived_None_and_False_both_contribute_nothing_and_True_costs_20():
    not_collected = ev(repository=RepositoryInfo(archived=None))
    looked_and_fine = ev(repository=RepositoryInfo(archived=False))
    looked_and_archived = ev(repository=RepositoryInfo(archived=True))

    assert score(not_collected).score == BASE
    assert score(looked_and_fine).score == BASE
    assert score(looked_and_archived).score == BASE - 20


def test_a_missing_registry_is_not_charged_for_having_no_licence():
    assert score(ev(registry=None)).score == BASE
    assert score(ev(registry=RegistryInfo(license=None))).score == BASE - 5


@pytest.mark.parametrize("field,value,unchanged", [
    ("weekly_downloads", None, True),
    ("weekly_downloads", 0, False),          # a real measurement: -10
    ("maintainer_count", None, True),
    ("maintainer_count", 1, False),          # a real measurement: -8
    ("days_since_last_publish", None, True),
    ("days_since_last_publish", 2_000, False),
])
def test_absent_signals_contribute_nothing_while_measured_ones_count(
        field, value, unchanged):
    registry = RegistryInfo(license="MIT", **{field: value})
    result = score(ev(registry=registry)).score
    if unchanged:
        assert result == BASE
    else:
        assert result < BASE


def test_contributors_None_earns_no_credit():
    assert score(ev(repository=RepositoryInfo(archived=False,
                                              contributors=None))).score == BASE
    assert score(ev(repository=RepositoryInfo(archived=False,
                                              contributors=50))).score == BASE + 8


# ------------------------------------------------------------------------------
# 4. Bands, boundaries, and the override
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("points,expected", [
    (100, "low"), (70, "low"),
    (69, "medium"), (45, "medium"),
    (44, "high"), (25, "high"),
    (24, "critical"), (0, "critical"),
])
def test_band_boundaries(points, expected):
    assert _band(points) == expected


def test_the_override_raises_but_never_lowers():
    assert (_at_least("medium", "high"), _at_least("high", "high"),
            _at_least("critical", "high")) == ("high", "high", "critical")


def test_an_unfixed_critical_is_forced_to_at_least_high():
    evidence = ev(vuln("critical", fixed=()),
                  registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO)
    result = score(evidence)
    assert result.score == 61
    assert _band(61) == "medium"
    assert result.risk == "high"


def test_a_fixed_critical_on_the_same_package_is_not_overridden():
    result = score(ev(vuln("critical", fixed=("1.7.3",)),
                      registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO))
    assert result.score == 66          # 91 - 30 + 5 credit
    assert result.risk == "medium"


def test_the_override_does_not_downgrade_a_critical_band():
    evidence = ev(*vulns("critical", 3, fixed=()),
                  registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO)
    assert score(evidence).risk == "critical"


def test_the_override_cannot_be_out_earned():
    perfect = RegistryInfo(maintainer_count=20, license="MIT",
                           weekly_downloads=500_000_000,
                           days_since_last_publish=1)
    stellar = RepositoryInfo(archived=False, days_since_last_push=0,
                             contributors=5_000, stars=400_000)
    result = score(ev(vuln("critical", fixed=()), registry=perfect,
                      repository=stellar))
    assert result.risk == "high"


# ------------------------------------------------------------------------------
# 5. The fix credit
# ------------------------------------------------------------------------------

def test_the_credit_applies_only_when_every_serious_finding_has_a_fix():
    both_fixed = ev(vuln("critical", id="a"), vuln("high", id="b"))
    one_unfixed = ev(vuln("critical", id="a"), vuln("high", fixed=(), id="b"))
    assert score(both_fixed).score == 60 - 30 - 12 + FIX_CREDIT
    assert score(one_unfixed).score == 60 - 30 - 12


def test_a_clean_package_earns_no_fix_credit():
    assert score(ev()).score == BASE


def test_moderate_and_low_findings_do_not_gate_the_credit():
    evidence = ev(vuln("critical", id="a"), vuln("moderate", fixed=(), id="b"))
    assert score(evidence).score == 60 - 30 - 4 + FIX_CREDIT


# ------------------------------------------------------------------------------
# 6. Partial evidence -- Decision 1, NOTES-M1 A.2
# ------------------------------------------------------------------------------

def test_degraded_evidence_cannot_reach_the_low_band():
    clean = ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO)
    degraded = ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                  partial=True, degraded=["github: 404 not found"])

    assert score(clean).score == 91 and score(clean).risk == "low"
    assert score(degraded).score == PARTIAL_CEILING
    assert score(degraded).risk == "medium"


def test_the_ceiling_only_lowers_never_raises():
    degraded = ev(*vulns("critical", 2, fixed=()),
                  registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO,
                  partial=True, degraded=["osv: timeout"])
    assert score(degraded).score == 0
    assert score(degraded).risk == "critical"


def test_the_ceiling_does_not_mask_the_override():
    evidence = ev(vuln("critical", fixed=()),
                  registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                  partial=True, degraded=["npm-registry: 503"])
    result = score(evidence)
    assert result.score == 61            # under the ceiling already
    assert result.risk == "high"         # override still fires


def test_a_partial_result_is_distinguishable_from_a_clean_one_by_score_alone():
    clean = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO))
    degraded = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                        partial=True, degraded=["github: 403"]))
    assert clean.score != degraded.score


# ------------------------------------------------------------------------------
# 7. Purity -- the promise, checked structurally
# ------------------------------------------------------------------------------

_ALLOWED_IMPORTS = {"__future__", "typing", "models"}


def test_score_imports_nothing_that_can_read_the_world():
    import ast
    import inspect

    import openshield.score

    tree = ast.parse(inspect.getsource(openshield.score))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    unexpected = imported - _ALLOWED_IMPORTS
    assert not unexpected, f"score.py must stay pure; unexpected: {unexpected}"


# ------------------------------------------------------------------------------
# 8. The breakdown -- §4's explainability, made arithmetic
# ------------------------------------------------------------------------------

def _rows(assessment):
    return {c.label: c.points for c in assessment.contributions}


@pytest.mark.parametrize("evidence", [
    ev(),
    ev(vuln("high")),
    ev(*vulns("moderate", 19)),
    ev(*vulns("critical", 5, fixed=())),                       # clamps at 0
    ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO),
    ev(registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO),
    ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
       partial=True, degraded=["github: 404"]),                # hits the ceiling
    ev(*vulns("high", 14), *vulns("moderate", 19), vuln("low"),
       registry=RegistryInfo(maintainer_count=1, license="MIT",
                             weekly_downloads=114_018_597,
                             days_since_last_publish=871),
       repository=RepositoryInfo(archived=False, days_since_last_push=0,
                                 contributors=674, stars=109_345)),
])
def test_the_rows_always_sum_to_the_score(evidence):
    result = score(evidence)
    assert sum(c.points for c in result.contributions) == result.score


def test_every_weight_that_applied_has_a_row():
    result = score(ev(*vulns("high", 14), *vulns("moderate", 19), vuln("low"),
                      registry=RegistryInfo(maintainer_count=1, license="MIT",
                                            weekly_downloads=114_018_597,
                                            days_since_last_publish=871),
                      repository=RepositoryInfo(archived=False,
                                                days_since_last_push=0,
                                                contributors=674)))
    rows = _rows(result)

    assert rows["starting point"] == 60
    assert rows["14 high findings (capped at -36)"] == -36
    assert rows["19 moderate findings (capped at -12)"] == -12
    assert rows["1 low finding"] == -1
    assert rows["every serious finding has a published fix"] == 5
    assert rows["this version published 871 days ago"] == -15
    assert rows["114,018,597 weekly downloads"] == 10
    assert rows["a single npm maintainer account"] == -8
    assert rows["674 repository contributors"] == 8
    assert result.score == 11          # the observed axios@1.7.2 figure


def test_a_signal_that_did_not_apply_has_no_row():
    rows = _rows(score(ev()))
    assert set(rows) == {"starting point"}


def test_unrated_findings_get_a_zero_row_rather_than_vanishing():
    rows = _rows(score(ev(vuln("unknown"), vuln("high"))))
    assert rows["1 unknown finding (not rated)"] == 0


def test_a_cap_says_so_on_the_line():
    assert "capped" in str(_rows(score(ev(*vulns("moderate", 19)))))
    assert "capped" not in str(_rows(score(ev(*vulns("moderate", 2)))))


def test_the_clamp_appears_as_its_own_row():
    result = score(ev(*vulns("critical", 5, fixed=()),
                      registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO))
    assert result.score == 0
    assert any("scale stops at 0" in c.label for c in result.contributions)
    assert sum(c.points for c in result.contributions) == 0


def test_the_partial_ceiling_appears_as_its_own_row_and_says_the_cost():
    result = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                      partial=True, degraded=["github: 404 not found"]))
    assert result.score == PARTIAL_CEILING
    ceiling = [c for c in result.contributions if "evidence incomplete" in c.label]
    assert len(ceiling) == 1
    assert ceiling[0].points == PARTIAL_CEILING - 91     # 91 was the real score


def test_the_rows_are_in_display_order_worst_findings_first():
    result = score(ev(vuln("low", id="l"), vuln("critical", id="c"),
                      vuln("moderate", id="m"), vuln("high", id="h")))
    labels = [c.label for c in result.contributions]
    order = [next(i for i, l in enumerate(labels) if sev in l)
             for sev in ("critical", "high", "moderate", "low")]
    assert order == sorted(order)
    assert labels[0] == "starting point"


def test_contributions_are_frozen():
    from pydantic import ValidationError
    row = score(ev()).contributions[0]
    with pytest.raises(ValidationError):
        row.points = 999


def test_the_breakdown_does_not_change_any_score():
    assert score(ev()).score == 60
    assert score(ev(vuln("high"))).score == 60 - 12 + FIX_CREDIT
    assert score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO)).score == 91