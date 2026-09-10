from typing import get_args
from openshield.models import RiskLevel, Severity
from openshield.score import _WEIGHTS, _at_least


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