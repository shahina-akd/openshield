"""cvss.py -- base score arithmetic and banding.

Split from test_osv.py deliberately: the CVSS formula and OSV's schema fail for
entirely unrelated reasons, and a red file should name its own culprit.

Nothing here touches the network, so nothing here needs respx.
"""
import pytest

from openshield.collect.cvss import band, base_score

# Published vectors with published scores. These are the golden tests -- if the
# arithmetic drifts, these numbers are what catch it.
VECTORS = [
    # AV:N/AC:L/PR:N/UI:N/S:U, full impact. The canonical 9.8.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    # Scope:Changed. The row that matters most: it is the ONLY one exercising
    # the alternate privileges table, the exponent term, and the 1.08
    # multiplier. Testing only the 9.8 case leaves half the formula unverified.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    # No impact at all -> 0.0 by the early return, not by the formula.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    # v3.0 uses the same base equations as v3.1.
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
]


@pytest.mark.parametrize("vector,expected", VECTORS)
def test_base_score(vector, expected):
    assert base_score(vector) == expected


@pytest.mark.parametrize("vector", [
    # Different formula (v2) and a lookup table (v4). Declining both is
    # deliberate -- see the docstring. They fall through to "unknown".
    "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
    # Malformed
    "CVSS:3.1/AV:N/AC:L",                              # missing metrics
    "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",    # unknown metric value
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",        # no Scope
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             # no version prefix
    "not a vector",
    "",
    # Not even a string -- the field can be absent or wrongly typed
    None,
    7,
    {"score": "CVSS:3.1/…"},
    ["CVSS:3.1/…"],
])
def test_unparseable_vectors_return_none(vector):
    """None, never an exception. severity_of turns it into "unknown", which
    §9.4 scores as zero -- an honest answer rather than a guess."""
    assert base_score(vector) is None


def test_whitespace_is_tolerated():
    """Vectors arriving from JSON occasionally carry surrounding whitespace."""
    assert base_score("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ") == 9.8


@pytest.mark.parametrize("score,expected", [
    (10.0, "critical"),
    (9.0, "critical"),      # boundary, inclusive
    (8.9, "high"),
    (7.0, "high"),          # boundary, inclusive
    (6.9, "moderate"),
    (4.0, "moderate"),      # boundary, inclusive
    (3.9, "low"),
    (0.1, "low"),
    # CVSS rates 0.0 as "None", a level §9.1 does not have. "unknown" rather
    # than "low": inventing a rating the publisher did not give is worse than
    # admitting we do not have one.
    (0.0, "unknown"),
])
def test_band_boundaries(score, expected):
    """Off-by-one at a band boundary changes a risk level and is invisible
    without these rows."""
    assert band(score) == expected


def test_band_uses_the_severity_vocabulary_not_the_cvss_one():
    """CVSS says "Medium"; §9.1 says "moderate". The translation lives here, in
    one place, alongside _WORDS' translation of the publisher words."""
    from typing import get_args

    from openshield.models import Severity

    assert band(5.0) == "moderate"
    for score in (10.0, 9.0, 7.0, 4.0, 0.1, 0.0):
        assert band(score) in get_args(Severity)