import pytest
import ast
import inspect
import openshield.score

from typing import get_args
from datetime import datetime, timezone

from openshield.models import RiskLevel, Severity
from openshield.models import Evidence, PackageRef, SourceRef, Vulnerability
from openshield.score import SCORING_VERSION, score
from openshield.score import _WEIGHTS, _at_least

# ----------------------------- vocabulary -----------------------------
def test_every_severity_has_a_weight():
    """_WEIGHTS is indexed directly, so a severity added to the Literal without
    a weight is a KeyError at scoring time -- on real evidence, in front of a
    user, at the moment they are deciding whether to install something.

    Same discipline as RESOLVABLE in models.py: the vocabulary is the source of
    truth and the lookup table must cover it exactly. Not a superset either --
    a stale key means a severity was renamed and something still emits the old
    one.
    """
    assert set(_WEIGHTS) == set(get_args(Severity))

def test_the_override_raises_but_never_lowers():
    below = _at_least("medium", "high")
    at = _at_least("high", "high")
    above = _at_least("critical", "high")
    assert (below, at, above) == ("high", "high", "critical")

# ----------------------------- the numbers -----------------------------
TS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")


def _vuln(severity, fixed=("9.9.9",), id="GHSA-x"):
    """Default to HAVING a fix, so the §9.5 override only fires where a test
    asks for it. A fixture that accidentally triggers the override is a golden
    test asserting the wrong branch."""
    return Vulnerability(id=id, severity=severity,
                         fixed_versions=list(fixed), source=SOURCE)


def _ev(*vulns, partial=False, degraded=()):
    return Evidence(package=REF, vulnerabilities=list(vulns),
                    sources=[SOURCE], partial=partial,
                    degraded_sources=list(degraded))


@pytest.mark.parametrize("evidence,expected", [
    (_ev(),                                                100),
    (_ev(_vuln("high")),                                    80),
    (_ev(_vuln("critical"), _vuln("critical")),             20),
    (_ev(_vuln("moderate")),                                90),
    (_ev(_vuln("low")),                                     97),
    (_ev(_vuln("unknown")),                                100),   # weighted zero
    (_ev(*[_vuln("critical") for _ in range(5)]),            0),   # clamped, not -100
])
def test_golden_scores(evidence, expected):
    """Fixed Evidence in, exact number out. §15: makes weight changes visible
    instead of accidental. If one of these moves, SCORING_VERSION moves too."""
    assert score(evidence).score == expected


def test_the_same_evidence_scores_identically_twice():
    """Looks pointless today. It is the test that catches the datetime.now()
    you will be tempted to add in M1 when the maintenance signals arrive."""
    ev = _ev(_vuln("high"), _vuln("moderate"))
    first, second = score(ev), score(ev)
    assert first.score == second.score
    assert first.risk == second.risk
    assert first.scoring_version == second.scoring_version


def test_the_assessment_is_stamped():
    assert score(_ev()).scoring_version == SCORING_VERSION

# ----------------------------- the bands -----------------------------
@pytest.mark.parametrize("points,expected", [
    (100, "low"), (70, "low"),
    (69, "medium"), (45, "medium"),
    (44, "high"), (25, "high"),
    (24, "critical"), (0, "critical"),
])
def test_band_boundaries(points, expected):
    """Off-by-one here changes a risk level and is invisible in ordinary use.
    Both sides of every threshold, deliberately."""
    from openshield.score import _band
    assert _band(points) == expected

# ----------------------------- the override -----------------------------
def test_an_unfixed_critical_is_forced_to_at_least_high():
    """The only place M0 takes a position the arithmetic would not reach.

    One critical scores 60, which bands as 'medium'. With no published fix,
    §9.5 forces 'high'. Note the score is UNCHANGED -- the override moves the
    band, not the number, so the evidence and the arithmetic stay legible.
    """
    ev = _ev(_vuln("critical", fixed=()))
    result = score(ev)
    assert result.score == 60
    assert result.risk == "high"


def test_a_fixed_critical_is_not_overridden():
    """The control. Without it, the test above passes even if the override
    fires on every critical regardless of fix status."""
    result = score(_ev(_vuln("critical", fixed=("1.7.3",))))
    assert result.score == 60
    assert result.risk == "medium"


def test_the_override_does_not_downgrade_a_critical_band():
    """Three unfixed criticals score 0 -> band 'critical'. A naive
    `return "high"` would LOWER it. §9.5 says 'at least high', a floor."""
    ev = _ev(*[_vuln("critical", fixed=(), id=f"GHSA-{i}") for i in range(3)])
    assert score(ev).risk == "critical"


# ----------------------------- the promise -----------------------------
_ALLOWED_IMPORTS = {"__future__", "typing", "models"}


def test_score_imports_nothing_that_can_read_the_world():
    """§9.2: no network, no file I/O, no clock, no randomness.

    Checked at the import boundary because that is where it is decidable. A
    module that never imports httpx, datetime, random, os, or pathlib cannot
    reach any of them, and this fails the moment someone adds one -- rather
    than in M1 when a golden test mysteriously expires.
    """
    tree = ast.parse(inspect.getsource(openshield.score))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert imported <= _ALLOWED_IMPORTS, (
        f"score.py must stay pure; unexpected imports: {imported - _ALLOWED_IMPORTS}"
    )