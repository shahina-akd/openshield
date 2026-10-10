"""score.py -- §9.4's weights, §9.5's bands, and the override.

One file, because the weights, the bands and the override all break when the
same two spec sections move, and SCORING_VERSION covers all three.

Every fixture is HAND-BUILT Evidence (§15). No network, no respx, no cache --
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
    """Defaults to HAVING a fix, so §9.5's override fires only where a test
    asks for it. A fixture that triggers the override by accident is a golden
    test asserting the wrong branch."""
    return Vulnerability(id=id, severity=severity,
                         fixed_versions=list(fixed), source=SOURCE)


def vulns(severity, count, fixed=("9.9.9",)):
    return [vuln(severity, fixed, id=f"GHSA-{severity}-{i}") for i in range(count)]


def ev(*vulnerabilities, registry=None, repository=None,
       partial=False, degraded=()):
    """Evidence with NOTHING collected unless a test says otherwise.

    registry=None and repository=None mean "not collected", which is the
    honest default for a unit test: every signal a test does not mention
    contributes zero rather than silently contributing a default.
    """
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
    """_VULN_WEIGHTS is indexed directly, so a severity added to the Literal
    without a weight is a KeyError at scoring time -- on real evidence, in
    front of a user, at the moment they are deciding whether to install
    something.

    Not a superset either: a stale key means a severity was renamed and
    something still emits the old one."""
    assert set(_VULN_WEIGHTS) == set(get_args(Severity))


def test_every_band_is_a_valid_risk_level():
    for points in (0, 24, 25, 44, 45, 69, 70, 100):
        assert _band(points) in get_args(RiskLevel)


def test_severity_and_risk_stay_different_vocabularies():
    """'moderate' is a finding; 'medium' is a band. Pinning the difference
    stops a future tidy-up from merging them."""
    assert "medium" not in get_args(Severity)
    assert "moderate" not in get_args(RiskLevel)


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
    """§15: fixed input, exact output. Makes a weight change VISIBLE rather
    than accidental. If one of these moves, SCORING_VERSION moves too."""
    assert score(evidence).score == expected


def test_a_healthy_popular_package_lands_in_low():
    """§9.4's first golden fixture. 60 +8 fresh +10 downloads +5 maintainers
    +8 contributors = 91."""
    result = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO))
    assert result.score == 91
    assert result.risk == "low"


def test_an_abandoned_unpopular_package_lands_in_high_or_worse():
    """§9.4's third golden fixture: archived, two years unpublished, 200
    downloads a week, sole maintainer, no licence.
    60 -20 archived -15 stale -10 downloads -8 sole -5 licence = 2."""
    result = score(ev(registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO))
    assert result.score == 2
    assert result.risk == "critical"


def test_one_high_with_a_fix_on_an_otherwise_healthy_package():
    """§9.4's second golden fixture. 91 -12 +5 = 84."""
    result = score(ev(vuln("high"), registry=HEALTHY_REGISTRY,
                      repository=HEALTHY_REPO))
    assert result.score == 84
    assert result.risk == "low"


@pytest.mark.parametrize("count", [3, 10, 60])
def test_the_scale_is_clamped_not_overflowed(count):
    """§9.3's clamp survives §9.4. Assessment's Field(ge=0) would raise a
    ValidationError if it did not, which is the backstop -- but the clamp is
    the specified behaviour, not the crash."""
    assert score(ev(*vulns("critical", count),
                    registry=ABANDONED_REGISTRY,
                    repository=ABANDONED_REPO)).score == 0


def test_the_same_evidence_scores_identically_twice():
    """Looks pointless. It is the test that catches the datetime.now() someone
    adds in this very step, when the age signals arrive."""
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
    """A.2 at the scoring site, stated precisely.

    None and False SCORE THE SAME, and that is correct -- neither is a reason
    to subtract. The dangerous consequence is one level up: an abandoned
    package whose GitHub lookup FAILED has archived=None, so it never receives
    its -20, and absence of a negative signal reads as a positive one. That is
    what PARTIAL_CEILING contains, and it is tested in section 6.

    (An earlier version of this docstring claimed the `is True` spelling in
    score.py was what prevented the bug. Mutation testing showed otherwise:
    Pydantic coerces archived to bool|None, so `is True` and plain truthiness
    are equivalent here. The protection lives in the model and in
    github.parse(), not in the scorer.)
    """
    not_collected = ev(repository=RepositoryInfo(archived=None))
    looked_and_fine = ev(repository=RepositoryInfo(archived=False))
    looked_and_archived = ev(repository=RepositoryInfo(archived=True))

    assert score(not_collected).score == BASE
    assert score(looked_and_fine).score == BASE
    assert score(looked_and_archived).score == BASE - 20


def test_a_missing_registry_is_not_charged_for_having_no_licence():
    """§9.4's weights describe the PACKAGE, never the collection. Charging -5
    because our own lookup failed would be penalising a package for our
    network trouble."""
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
    """0 maintainers or 0 downloads is a MEASUREMENT, and an alarming one. A
    missing field is an absence. §9.4 must never treat them alike."""
    registry = RegistryInfo(license="MIT", **{field: value})
    result = score(ev(registry=registry)).score
    if unchanged:
        assert result == BASE
    else:
        assert result < BASE


def test_contributors_None_earns_no_credit():
    """The inverse direction: a failed contributor lookup must not be rewarded
    either. None is no signal, in both directions."""
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
    """Both sides of every threshold. An off-by-one here changes a risk level
    and is invisible in ordinary use."""
    assert _band(points) == expected


def test_the_override_raises_but_never_lowers():
    assert (_at_least("medium", "high"), _at_least("high", "high"),
            _at_least("critical", "high")) == ("high", "high", "critical")


def test_an_unfixed_critical_is_forced_to_at_least_high():
    """§9.5, and the one place M1 takes a position the arithmetic would not
    reach.

    Deliberately excellent signals -- 50M downloads, 400 contributors, five
    maintainers, published last month -- so the override is genuinely tested
    rather than passing because the score was low anyway. 91 - 30 = 61, which
    bands as 'medium'; the override forces 'high'.

    The SCORE IS UNCHANGED: the override moves the band, not the number, so
    the evidence and the arithmetic both stay legible.
    """
    evidence = ev(vuln("critical", fixed=()),
                  registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO)
    result = score(evidence)
    assert result.score == 61
    assert _band(61) == "medium"
    assert result.risk == "high"


def test_a_fixed_critical_on_the_same_package_is_not_overridden():
    """The control. Without it, the test above passes even against an override
    that fires on every critical regardless of fix status."""
    result = score(ev(vuln("critical", fixed=("1.7.3",)),
                      registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO))
    assert result.score == 66          # 91 - 30 + 5 credit
    assert result.risk == "medium"


def test_the_override_does_not_downgrade_a_critical_band():
    """Three unfixed criticals on a weak package score 0 -> band 'critical'.
    A naive `return "high"` would LOWER it. §9.5 says 'at least high'."""
    evidence = ev(*vulns("critical", 3, fixed=()),
                  registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO)
    assert score(evidence).risk == "critical"


def test_the_override_cannot_be_out_earned():
    """Why it is a branch and not a weight. No amount of popularity should
    soften an unfixable critical -- and a weight of any size eventually loses
    to enough positive signals."""
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
    """The credit rewards a REMEDIABLE situation, not the absence of one. A
    clean package is already rewarded by not losing points -- paying it twice
    would make 'no findings' and 'findings, all fixed' indistinguishable."""
    assert score(ev()).score == BASE


def test_moderate_and_low_findings_do_not_gate_the_credit():
    """§9.4 says critical/high. An unfixed moderate is not the thing the
    credit is about, and gating on it would make the credit near-unreachable
    for any package with a long tail."""
    evidence = ev(vuln("critical", id="a"), vuln("moderate", fixed=(), id="b"))
    assert score(evidence).score == 60 - 30 - 4 + FIX_CREDIT


# ------------------------------------------------------------------------------
# 6. Partial evidence -- Decision 1, NOTES-M1 A.2
# ------------------------------------------------------------------------------

def test_degraded_evidence_cannot_reach_the_low_band():
    """DECISION 1, and the test that REPLACES M0's
    `test_degraded_evidence_currently_scores_as_if_clean`.

    That test was written with a docstring saying the behaviour was documented,
    not endorsed, and that it would fail here. It did. This is the replacement.

    A ceiling is structural where a warning is advisory: it relies on the code
    rather than on the reader noticing a banner, and §9.1's whole point is that
    missing evidence must never look like good evidence.
    """
    clean = ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO)
    degraded = ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                  partial=True, degraded=["github: 404 not found"])

    assert score(clean).score == 91 and score(clean).risk == "low"
    assert score(degraded).score == PARTIAL_CEILING
    assert score(degraded).risk == "medium"


def test_the_ceiling_only_lowers_never_raises():
    """A degraded package that scored badly keeps its bad score. The ceiling
    is a cap, not a normalisation."""
    degraded = ev(*vulns("critical", 2, fixed=()),
                  registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO,
                  partial=True, degraded=["osv: timeout"])
    assert score(degraded).score == 0
    assert score(degraded).risk == "critical"


def test_the_ceiling_does_not_mask_the_override():
    """Both can apply. The ceiling moves the number, the override moves the
    band, and neither should silently cancel the other."""
    evidence = ev(vuln("critical", fixed=()),
                  registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                  partial=True, degraded=["npm-registry: 503"])
    result = score(evidence)
    assert result.score == 61            # under the ceiling already
    assert result.risk == "high"         # override still fires


def test_a_partial_result_is_distinguishable_from_a_clean_one_by_score_alone():
    """§9.1 expressed as arithmetic. Two packages with identical surviving
    signals, one degraded -- and the numbers differ, so the distinction
    survives even if the renderer loses it."""
    clean = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO))
    degraded = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                        partial=True, degraded=["github: 403"]))
    assert clean.score != degraded.score


# ------------------------------------------------------------------------------
# 7. Purity -- the promise, checked structurally
# ------------------------------------------------------------------------------

_ALLOWED_IMPORTS = {"__future__", "typing", "models"}


def test_score_imports_nothing_that_can_read_the_world():
    """§9.2: no network, no file I/O, no clock, no randomness.

    Checked at the IMPORT BOUNDARY because that is where it is decidable. A
    module that never imports datetime, httpx, random, os or pathlib cannot
    reach any of them, and this fails the moment someone adds one -- rather
    than in M2 when a golden test mysteriously expires.

    M1 is exactly when this is tempted: the step adds age signals, and the
    obvious way to get an age is datetime.now(). The age belongs in the
    collector's parse() (NOTES-M1 B.2). DO NOT WIDEN THE ALLOWLIST.
    """
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
    """THE invariant, and the reason the breakdown is built in score() rather
    than recomputed in render.py.

    Two implementations of the same arithmetic can disagree, and a table that
    contradicts its own total is worse than no table -- the reader stops
    trusting both. These rows ARE the calculation, so the rendered column adds
    up by construction, including the clamp and the ceiling.
    """
    result = score(evidence)
    assert sum(c.points for c in result.contributions) == result.score


def test_every_weight_that_applied_has_a_row():
    """§4: every number shown traces to a visible evidence field. If a weight
    could fire without producing a row, the total would be unexplainable --
    which is the failure the whole breakdown exists to prevent."""
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
    """An absent signal must not appear as a zero. A row saying
    `repository archived  0` would imply we looked and it was fine, which is
    exactly the None-versus-False confusion A.2 is about."""
    rows = _rows(score(ev()))
    assert set(rows) == {"starting point"}


def test_unrated_findings_get_a_zero_row_rather_than_vanishing():
    """`unknown` weighs zero (§9.4), but the header counts it -- so without a
    row the table would appear to have lost a finding, and a reader checking
    the arithmetic would distrust the whole column."""
    rows = _rows(score(ev(vuln("unknown"), vuln("high"))))
    assert rows["1 unknown finding (not rated)"] == 0


def test_a_cap_says_so_on_the_line():
    """`19 moderate findings` costing 12 points is surprising unless the reason
    is on the row. An uncapped count must NOT claim a cap."""
    assert "capped" in str(_rows(score(ev(*vulns("moderate", 19)))))
    assert "capped" not in str(_rows(score(ev(*vulns("moderate", 2)))))


def test_the_clamp_appears_as_its_own_row():
    """A column that silently failed to add up would undermine every other
    row. '-22, and the scale stops at 0' is a fact about this package."""
    result = score(ev(*vulns("critical", 5, fixed=()),
                      registry=ABANDONED_REGISTRY, repository=ABANDONED_REPO))
    assert result.score == 0
    assert any("scale stops at 0" in c.label for c in result.contributions)
    assert sum(c.points for c in result.contributions) == 0


def test_the_partial_ceiling_appears_as_its_own_row_and_says_the_cost():
    """The most informative row in a degraded result: it tells the reader what
    the score WOULD have been, so they learn the cap cost something rather
    than that the package is mediocre."""
    result = score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO,
                      partial=True, degraded=["github: 404 not found"]))
    assert result.score == PARTIAL_CEILING
    ceiling = [c for c in result.contributions if "evidence incomplete" in c.label]
    assert len(ceiling) == 1
    assert ceiling[0].points == PARTIAL_CEILING - 91     # 91 was the real score


def test_the_rows_are_in_display_order_worst_findings_first():
    """The reader scans top-down and should meet the biggest subtraction
    first. Dict iteration order is not a layout decision."""
    result = score(ev(vuln("low", id="l"), vuln("critical", id="c"),
                      vuln("moderate", id="m"), vuln("high", id="h")))
    labels = [c.label for c in result.contributions]
    order = [next(i for i, l in enumerate(labels) if sev in l)
             for sev in ("critical", "high", "moderate", "low")]
    assert order == sorted(order)
    assert labels[0] == "starting point"


def test_contributions_are_frozen():
    """They are a record of a calculation already performed. Editing one after
    the fact would make the score and its explanation disagree."""
    from pydantic import ValidationError
    row = score(ev()).contributions[0]
    with pytest.raises(ValidationError):
        row.points = 999


def test_the_breakdown_does_not_change_any_score():
    """The whole §1.5 golden table was computed before contributions existed.
    Adding an explanation must not alter what is being explained."""
    assert score(ev()).score == 60
    assert score(ev(vuln("high"))).score == 60 - 12 + FIX_CREDIT
    assert score(ev(registry=HEALTHY_REGISTRY, repository=HEALTHY_REPO)).score == 91