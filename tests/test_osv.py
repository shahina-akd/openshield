"""collect/osv.py -- extraction (pure) and transport (async, via a sync wrapper).

M1 Step 1.1 changed only the transport half: query()/collect_osv() became
`async def fetch(ref, client) -> CollectorResult`. Everything in sections 1-3
is unchanged from M0 apart from imports -- that is the payoff of the
transport/parse split (NOTES-M1 B.1).

The M0 tests of _evidence() and SourceResult moved to test_collect.py, where
assembly now lives. The _as_list/_dig tests moved to test_base.py.

No test here is async. Transport tests drive fetch() through _fetch(), a small
sync wrapper around asyncio.run -- the same boundary collect() uses.
"""
import asyncio
import json
from datetime import datetime, timezone

import httpx
import pytest
import respx

from openshield.collect import osv
from openshield.collect.base import CollectorResult
from openshield.collect.osv import (
    MAX_PAGES,
    OSV_QUERY_URL,
    _word,
    fixed_versions,
    parse_vulns,
    severity_of,
)
from openshield.models import PackageRef, SourceRef

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")


def _vuln(**fields) -> dict:
    """A minimal OSV record. Hand-written, not a saved API response -- an
    eight-line fixture isolating one extraction path localises a failure."""
    return {"id": "GHSA-test", **fields}


def _fetch(ref: PackageRef = REF) -> CollectorResult:
    """Drive the async transport synchronously, as collect() does."""
    async def go():
        async with httpx.AsyncClient() as client:
            return await osv.fetch(ref, client)
    return asyncio.run(go())


# ------------------------------------------------------------------------------
# 1. Severity
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("HIGH", "high"), ("high", "high"), ("  Moderate  ", "moderate"),
    ("MEDIUM", "moderate"),          # CVSS's word for GHSA's "moderate"
    ("SEVERE", None), ("", None), (None, None), (7, None), ({"s": "high"}, None),
])
def test_word(value, expected):
    assert _word(value) == expected


@pytest.mark.parametrize("vuln,expected", [
    # tier 1 -- the publisher's word, and the casefold
    (_vuln(database_specific={"severity": "HIGH"}), "high"),
    (_vuln(database_specific={"severity": "MODERATE"}), "moderate"),
    # tier 2 -- same word, per affected package
    (_vuln(affected=[{"database_specific": {"severity": "LOW"}}]), "low"),
    # tier 3 -- a CVSS vector
    (_vuln(severity=[{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]),
     "critical"),
    # CVSS says MEDIUM, we say moderate
    (_vuln(severity=[{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}]),
     "moderate"),
    # misses
    (_vuln(), "unknown"),
    (_vuln(database_specific={"severity": "SEVERE"}), "unknown"),
    (_vuln(severity=[]), "unknown"),
    # wrong shapes -- the tests that actually matter
    (_vuln(database_specific="HIGH"), "unknown"),
    (_vuln(severity={"score": "CVSS:3.1/…"}), "unknown"),
    (_vuln(affected="not-a-list"), "unknown"),
])
def test_severity_of(vuln, expected):
    assert severity_of(vuln) == expected


def test_the_top_level_word_wins_over_the_affected_one():
    vuln = _vuln(database_specific={"severity": "CRITICAL"},
                 affected=[{"database_specific": {"severity": "LOW"}}])
    assert severity_of(vuln) == "critical"


V4_ONLY = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"
V31_MODERATE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"


@pytest.mark.parametrize("vuln,expected", [
    # GHSA-8hc4-vh64-cxmj: a word and NO vector at all.
    (_vuln(database_specific={"severity": "HIGH"}, severity=[]), "high"),
    # GHSA-42h9-826w-cgv3: a word, and only a v4 vector base_score declines.
    (_vuln(database_specific={"severity": "MODERATE"},
           severity=[{"type": "CVSS_V4", "score": V4_ONLY}]), "moderate"),
])
def test_severity_of_real_shapes(vuln, expected):
    assert severity_of(vuln) == expected


@pytest.mark.parametrize("vectors", [
    [{"type": "CVSS_V3", "score": V31_MODERATE}, {"type": "CVSS_V4", "score": V4_ONLY}],
    # THE ordering case: v4 first (GHSA-xxjr-mmjv-4gpg carries both).
    [{"type": "CVSS_V4", "score": V4_ONLY}, {"type": "CVSS_V3", "score": V31_MODERATE}],
])
def test_tier_three_continues_past_a_vector_it_cannot_parse(vectors):
    assert severity_of(_vuln(severity=vectors)) == "moderate"


def test_a_v4_only_record_with_no_word_is_unknown_not_a_crash():
    """The recorded gap in NOTES-0_4 §8.1, pinned. If v4 support ever lands,
    this is the test that should fail."""
    assert severity_of(_vuln(severity=[{"type": "CVSS_V4", "score": V4_ONLY}])) == "unknown"


# ------------------------------------------------------------------------------
# 2. Fixed versions
# ------------------------------------------------------------------------------

def _affected(ecosystem="npm", name="axios", fixed=("1.7.3",)):
    return {"package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, *({"fixed": f} for f in fixed)]}]}


@pytest.mark.parametrize("vuln,expected", [
    (_vuln(affected=[_affected()]), ["1.7.3"]),
    (_vuln(affected=[_affected(fixed=("1.9.1",)), _affected(fixed=("2.0.3",))]),
     ["1.9.1", "2.0.3"]),
    (_vuln(affected=[_affected(name="lodash")]), []),
    # THE ecosystem bug: same name, different ecosystem
    (_vuln(affected=[_affected(ecosystem="PyPI")]), []),
    (_vuln(affected=[{"package": {"ecosystem": "npm", "name": "axios"},
                      "ranges": [{"events": [{"introduced": "0"}]}]}]), []),
    (_vuln(affected=[_affected(fixed=("1.7.3",)), _affected(fixed=("1.7.3",))]),
     ["1.7.3"]),
    (_vuln(affected=[{"package": "axios"}]), []),
    (_vuln(affected=[_affected() | {"ranges": "nope"}]), []),
    (_vuln(), []),
])
def test_fixed_versions(vuln, expected):
    assert fixed_versions(vuln, REF) == expected


# ------------------------------------------------------------------------------
# 3. parse_vulns
# ------------------------------------------------------------------------------

JUNK = [
    {}, {"vulns": None}, {"vulns": "nope"}, {"vulns": [None, 3, "x"]},
    {"vulns": [{}]}, {"vulns": [{"id": 7}]}, {"vulns": [{"id": ""}]},
    {"vulns": [{"id": "X", "affected": "not-a-list"}]},
    {"vulns": [{"id": "X", "aliases": "CVE-1"}]},
    {"vulns": [{"id": "X", "summary": {"text": "no"}}]},
    {"vulns": [{"id": "X", "affected": [{"ranges": [{"events": {}}]}]}]},
    {"vulns": [{"id": "X", "database_specific": None, "severity": None}]},
    [], "string", None,                        # not even a dict at the top
]


@pytest.mark.parametrize("payload", JUNK)
def test_parse_never_raises(payload):
    assert isinstance(parse_vulns(payload, REF, SOURCE), list)


def test_withdrawn_advisories_are_dropped():
    payload = {"vulns": [_vuln(withdrawn="2023-01-01T00:00:00Z"), _vuln(id="GHSA-live")]}
    assert [v.id for v in parse_vulns(payload, REF, SOURCE)] == ["GHSA-live"]


def test_every_vulnerability_carries_the_source_that_found_it():
    assert parse_vulns({"vulns": [_vuln()]}, REF, SOURCE)[0].source == SOURCE


# ------------------------------------------------------------------------------
# 4. Transport -- async fetch(), driven synchronously
# ------------------------------------------------------------------------------

@respx.mock
def test_fetch_sends_the_resolved_version():
    """Appendix B: are you querying the version you resolved, or the version
    the user typed? Asserted mechanically."""
    route = respx.post(OSV_QUERY_URL).respond(200, json={})
    _fetch()
    assert json.loads(route.calls.last.request.content) == {
        "version": "1.7.2", "package": {"name": "axios", "ecosystem": "npm"},
    }


@respx.mock
@pytest.mark.parametrize("payload", [{}, {"vulns": []}])
def test_an_empty_result_is_a_successful_clean_answer(payload):
    """{} and {"vulns": []} both mean 'nothing known against this'."""
    respx.post(OSV_QUERY_URL).respond(200, json=payload)
    r = _fetch()
    assert r.ok is True and r.error is None and r.skipped is False
    assert r.data == {"vulns": []}
    assert r.source is not None and r.source.name == "osv"


@respx.mock
def test_fetch_returns_the_raw_payload_not_parsed_models():
    """Step 1.4 caches exactly what fetch returns, so it must be raw."""
    respx.post(OSV_QUERY_URL).respond(200, json={"vulns": [_vuln()]})
    assert _fetch().data == {"vulns": [_vuln()]}


@respx.mock
@pytest.mark.parametrize("response,fragment", [
    (httpx.Response(503), "503"),
    (httpx.Response(500), "500"),
    (httpx.Response(429), "429"),
    (httpx.Response(200, text="<html>captive portal</html>"), "non-JSON"),
    (httpx.Response(200, json=[]), "not a JSON object"),
])
def test_a_failure_is_not_a_clean_answer(response, fragment):
    """Same empty data as the clean case; only `ok` tells them apart. §9.1."""
    respx.post(OSV_QUERY_URL).mock(return_value=response)
    r = _fetch()
    assert r.ok is False and r.skipped is False
    assert r.data == {}
    assert fragment in r.error


@respx.mock
@pytest.mark.parametrize("exc,fragment", [
    (httpx.ConnectTimeout("boom"), "timeout"),
    (httpx.ReadTimeout("boom"), "timeout"),
    (httpx.ConnectError("boom"), "network error: ConnectError"),
])
def test_transport_errors_are_return_values(exc, fragment):
    respx.post(OSV_QUERY_URL).mock(side_effect=exc)
    r = _fetch()
    assert r.ok is False and fragment in r.error


@respx.mock
def test_pagination_is_followed():
    route = respx.post(OSV_QUERY_URL).mock(side_effect=[
        httpx.Response(200, json={"vulns": [_vuln(id="A")], "next_page_token": "t"}),
        httpx.Response(200, json={"vulns": [_vuln(id="B")]}),
    ])
    r = _fetch()
    assert [v["id"] for v in r.data["vulns"]] == ["A", "B"]
    assert r.ok is True and r.error is None
    assert json.loads(route.calls[1].request.content)["page_token"] == "t"


@respx.mock
def test_truncation_is_reported_rather_than_hidden():
    respx.post(OSV_QUERY_URL).respond(
        200, json={"vulns": [_vuln()], "next_page_token": "forever"})
    r = _fetch()
    assert r.ok is True
    assert f"truncated after {MAX_PAGES} pages" in r.error