"""collect/base.py -- the shared machinery all three collectors depend on.

_as_list and _dig make "never let an unrecognised shape raise" true by
construction (NOTES-M1-inheritance.md B.4). After Step 1.1 they serve three
collectors, so a bug in either degrades all of them at once -- which is why they
get direct tests here rather than only being exercised through severity_of.

_survive is new in Step 1.1 and covered nowhere else.
"""
import pytest

from openshield.collect.base import CollectorResult, _as_list, _dig, _survive
from tests.conftest import RealNetworkAttempted


# ---------------------------------- _as_list -----------------------------------

@pytest.mark.parametrize("value,expected", [
    ([1, 2], [1, 2]),
    ([], []),
    (None, []),
    ({}, []),
    ({"a": 1}, []),
    ("abc", []),        # a string is iterable -- and still not a list
    (7, []),
    ((1, 2), []),       # a tuple is not what JSON produces; refuse it
])
def test_as_list(value, expected):
    assert _as_list(value) == expected


def test_as_list_never_returns_none():
    """Callers iterate the result directly. None here would be the TypeError
    this helper exists to prevent."""
    assert _as_list(None) is not None


# ------------------------------------ _dig -------------------------------------

@pytest.mark.parametrize("obj,keys,expected", [
    ({"a": {"b": 1}}, ("a", "b"), 1),
    ({"a": {"b": 1}}, ("a",), {"b": 1}),
    ({"a": {"b": 1}}, ("a", "c"), None),
    ({"a": {"b": 1}}, ("x", "b"), None),
    ({"a": "not-a-dict"}, ("a", "b"), None),   # the case that raises naively
    ({"a": ["list"]}, ("a", "b"), None),
    ({"a": None}, ("a", "b"), None),
    (None, ("a",), None),
    ([], ("a",), None),
    ("string", ("a",), None),
    ({}, (), {}),                              # no keys: the object itself
])
def test_dig(obj, keys, expected):
    assert _dig(obj, *keys) == expected


# ---------------------------------- _survive -----------------------------------

def test_survive_passes_a_real_result_through_untouched():
    """Identity, not equality -- nothing is copied or rebuilt on the way."""
    r = CollectorResult(ok=True, data={"x": 1})
    assert _survive(r) is r


def test_survive_turns_an_exception_into_a_named_failure():
    r = _survive(RuntimeError("boom"))
    assert r.ok is False
    assert r.skipped is False          # a bug is degradation, never a skip
    assert "RuntimeError" in r.error and "boom" in r.error


@pytest.mark.parametrize("exc", [
    KeyboardInterrupt(),
    SystemExit(1),
    RealNetworkAttempted("guard"),
])
def test_survive_reraises_anything_that_is_not_an_exception(exc):
    """NOTES-M1-inheritance.md D.1.

    A user's Ctrl-C must not become a degraded source line, and the test
    suite's network guard must not either -- if it did, every test that goes
    through collect() would be unable to see a real network call.
    """
    with pytest.raises(type(exc)):
        _survive(exc)


# ------------------------------ CollectorResult --------------------------------

def test_ok_with_an_error_is_a_legitimate_state():
    """'I got an answer and it was incomplete' -- pagination truncation. The
    two fields are separate facts, and this combination must be constructible."""
    r = CollectorResult(ok=True, data={"vulns": []}, error="results truncated after 5 pages")
    assert r.ok and r.error


def test_skipped_defaults_to_false():
    """A collector that forgets to set it must read as ATTEMPTED. Defaulting to
    True would silently file every failure as a quiet skip (A.3 inverted)."""
    assert CollectorResult(ok=False, error="x").skipped is False


def test_data_defaults_are_not_shared_between_instances():
    """field(default_factory=dict), not `= {}`. A shared default dict would let
    one collector's payload leak into another's result."""
    a, b = CollectorResult(ok=True), CollectorResult(ok=True)
    assert a.data is not b.data