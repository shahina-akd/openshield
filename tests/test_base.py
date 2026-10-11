"""Tests for collect/base.py, the helpers shared by all collectors."""
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
    ("abc", []),
    (7, []),
    ((1, 2), []),       # JSON never produces tuples
])
def test_as_list(value, expected):
    assert _as_list(value) == expected


def test_as_list_never_returns_none():
    assert _as_list(None) is not None


# ------------------------------------ _dig -------------------------------------

@pytest.mark.parametrize("obj,keys,expected", [
    ({"a": {"b": 1}}, ("a", "b"), 1),
    ({"a": {"b": 1}}, ("a",), {"b": 1}),
    ({"a": {"b": 1}}, ("a", "c"), None),
    ({"a": {"b": 1}}, ("x", "b"), None),
    ({"a": "not-a-dict"}, ("a", "b"), None),
    ({"a": ["list"]}, ("a", "b"), None),
    ({"a": None}, ("a", "b"), None),
    (None, ("a",), None),
    ([], ("a",), None),
    ("string", ("a",), None),
    ({}, (), {}),                              # no keys returns the object
])
def test_dig(obj, keys, expected):
    assert _dig(obj, *keys) == expected


# ---------------------------------- _survive -----------------------------------

def test_survive_passes_a_real_result_through_untouched():
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
    """Ctrl-C and the test network guard must propagate, not become a
    degraded source."""
    with pytest.raises(type(exc)):
        _survive(exc)


# ------------------------------ CollectorResult --------------------------------

def test_ok_with_an_error_is_a_legitimate_state():
    """Represents an incomplete answer, e.g. truncated pagination."""
    r = CollectorResult(ok=True, data={"vulns": []}, error="results truncated after 5 pages")
    assert r.ok and r.error


def test_skipped_defaults_to_false():
    """Otherwise a collector that forgets to set it would hide failures as skips."""
    assert CollectorResult(ok=False, error="x").skipped is False


def test_data_defaults_are_not_shared_between_instances():
    a, b = CollectorResult(ok=True), CollectorResult(ok=True)
    assert a.data is not b.data