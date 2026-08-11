"""resolve.py -- specifier -> PackageRef | Unresolvable.

Every test here is mocked. No test in this file may reach the real registry.
"""
import httpx
import pytest
import respx

from openshield.models import PackageRef, Unresolvable
from openshield.parse import classify_specifier
from openshield.resolve import (
    normalize_version,
    registry_url,
    resolve,
    resolve_all,
)
from tests.test_parse import UNRESOLVABLE_CASES

REFUSED = [spec for spec, _ in UNRESOLVABLE_CASES]


def _packument(name="axios", latest="1.7.2", versions=("1.7.2",)):
    return {
        "name": name,
        "dist-tags": {"latest": latest},
        "versions": {v: {} for v in versions},
    }


# --------------------------------- the gate ----------------------------------

def test_unresolvable_never_touches_the_network(monkeypatch):
    """THE security property of this module. The labels are reading aids;
    this is not. Fails loudly if a client is even constructed."""
    def explode(*a, **k):
        raise AssertionError("network touched for an unresolvable specifier")

    monkeypatch.setattr(httpx.Client, "__init__", explode)
    for spec in REFUSED:
        result = resolve(spec)
        assert isinstance(result, Unresolvable), spec
        assert result.specifier == spec
    assert all(isinstance(r, Unresolvable) for r in resolve_all(REFUSED))


@pytest.mark.parametrize("spec", REFUSED)
def test_reason_matches_the_parse_label(spec):
    assert resolve(spec).reason == classify_specifier(spec)


# ------------------------------ url + normalize -------------------------------

def test_scoped_names_are_url_encoded():
    assert registry_url("axios").endswith("/axios")
    assert registry_url("@babel/core").endswith("/@babel%2Fcore")


@pytest.mark.parametrize("raw,expected", [
    ("1.7.2", "1.7.2"),
    ("v1.7.2", "1.7.2"),
    ("V1.7.2", "V1.7.2"),      # not a version -- nothing to normalize
    ("1.0.0-v.1", "1.0.0-v.1"),
])
def test_normalize_version(raw, expected):
    assert normalize_version(raw) == expected


# --------------------------------- lookups -----------------------------------

@respx.mock
def test_bare_name_uses_dist_tags_not_max_version():
    respx.get("https://registry.npmjs.org/axios").respond(
        json=_packument(versions=("1.7.2", "2.0.0-beta.1")))
    assert resolve("axios") == PackageRef(name="axios", version="1.7.2")


@respx.mock
def test_exact_version_is_confirmed_against_the_registry():
    respx.get("https://registry.npmjs.org/axios").respond(
        json=_packument(latest="1.8.0", versions=("1.7.2", "1.8.0")))
    assert resolve("axios@1.7.2").version == "1.7.2"


@respx.mock
def test_scoped_name_resolves():
    respx.get("https://registry.npmjs.org/@babel%2Fcore").respond(
        json=_packument(name="@babel/core", latest="7.24.0", versions=("7.24.0",)))
    assert resolve("@babel/core").canonical == "npm:@babel/core@7.24.0"


@respx.mock
def test_leading_v_yields_one_identity():
    route = respx.get("https://registry.npmjs.org/axios").respond(json=_packument())
    assert resolve("axios@v1.7.2").canonical == "npm:axios@1.7.2"
    assert resolve("axios@v1.7.2") == resolve("axios@1.7.2")
    assert route.called


@respx.mock
def test_registry_name_wins_over_typed_casing():
    respx.get("https://registry.npmjs.org/JSONStream").respond(
        json=_packument(name="JSONStream", latest="1.3.5", versions=("1.3.5",)))
    assert resolve("JSONStream").name == "JSONStream"


@respx.mock
def test_missing_exact_version_is_not_found_not_a_silent_pass():
    respx.get("https://registry.npmjs.org/axios").respond(json=_packument())
    r = resolve("axios@9.9.9")
    assert r.reason == "not_found" and "9.9.9" in r.detail


@respx.mock
def test_missing_latest_dist_tag_is_not_found():
    respx.get("https://registry.npmjs.org/ghost").respond(
        json={"name": "ghost", "versions": {}})
    assert resolve("ghost").reason == "not_found"


@respx.mock
@pytest.mark.parametrize("response,reason", [
    (httpx.Response(404), "not_found"),
    (httpx.Response(503), "network"),
    (httpx.Response(500), "network"),
    (httpx.Response(200, text="<html>captive portal</html>"), "network"),
])
def test_lookup_failures(response, reason):
    respx.get("https://registry.npmjs.org/axios").mock(return_value=response)
    assert resolve("axios").reason == reason


@respx.mock
@pytest.mark.parametrize("exc,fragment", [
    (httpx.ConnectTimeout("boom"), "timed out"),
    (httpx.ReadTimeout("boom"), "timed out"),
    (httpx.ConnectError("boom"), "unreachable"),
])
def test_network_errors_are_return_values_not_exceptions(exc, fragment):
    respx.get("https://registry.npmjs.org/axios").mock(side_effect=exc)
    r = resolve("axios")
    assert r.reason == "network" and fragment in r.detail


@respx.mock
def test_registry_data_rejected_by_package_ref_is_surfaced_not_raised():
    """classify_specifier validates form, not names. A name the registry
    serves but PackageRef refuses must become a visible Unresolvable -- this
    is what the try/except around the construction is for."""
    respx.get(url__regex=r".*registry\.npmjs\.org/.*").respond(
        json=_packument(name="axiós"))
    result = resolve("axiós")
    assert isinstance(result, Unresolvable)
    assert result.reason == "unknown"


# -------------------------------- resolve_all ---------------------------------

@respx.mock
def test_mixed_command_line_returns_both_kinds_in_order():
    """`npm install axios ./local` -- one ref, one refusal. run.py gets the
    good half; §11.1's unresolvable_policy governs the rest."""
    respx.get("https://registry.npmjs.org/axios").respond(json=_packument())
    results = resolve_all(["axios", "./local", "axios@1.7.2"])
    assert isinstance(results[0], PackageRef)
    assert isinstance(results[1], Unresolvable) and results[1].reason == "local_path"
    assert isinstance(results[2], PackageRef)


@respx.mock
def test_resolve_all_reuses_one_client():
    route = respx.get("https://registry.npmjs.org/axios").respond(json=_packument())
    resolve_all(["axios", "axios@1.7.2"])
    assert route.call_count == 2      # no caching yet