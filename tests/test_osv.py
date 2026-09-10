from datetime import datetime, timezone

import httpx
import pytest
import respx
from openshield.collect import _evidence, collect
from openshield.collect.osv import (
    MAX_PAGES,
    OSV_QUERY_URL,
    SourceResult,
    collect_osv,
    fixed_versions,
    parse_vulns,
    severity_of,
)
from openshield.models import PackageRef, SourceRef

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")


def _vuln(**fields) -> dict:
    """A minimal OSV record. Hand-written literal dicts, not saved API
    responses -- M1 Step 1.4 caches raw responses precisely because parsers
    change weekly, and an eight-line fixture that isolates one extraction path
    localises a failure in a way a 400-line real advisory does not."""
    return {"id": "GHSA-test", **fields}

from openshield.collect.osv import _word

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


# Shapes taken from the 2026-09-10 survey rather than invented. Each one is a
# real advisory whose structure would have broken a plausible implementation.
V4_ONLY = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"
V31_MODERATE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"


@pytest.mark.parametrize("vuln,expected", [
    # GHSA-8hc4-vh64-cxmj: a word and NO vector at all. Proves tier 3 cannot
    # substitute for tier 1 -- dropping tier 1 as "redundant with the vector"
    # would score this finding unknown and weight it zero.
    (_vuln(database_specific={"severity": "HIGH"}, severity=[]), "high"),
    # GHSA-42h9-826w-cgv3: a word, and only a v4 vector base_score declines.
    (_vuln(database_specific={"severity": "MODERATE"},
           severity=[{"type": "CVSS_V4", "score": V4_ONLY}]), "moderate"),
])
def test_severity_of_real_shapes(vuln, expected):
    assert severity_of(vuln) == expected


@pytest.mark.parametrize("vectors", [
    [{"type": "CVSS_V3", "score": V31_MODERATE}, {"type": "CVSS_V4", "score": V4_ONLY}],
    # THE ordering case: v4 first. GHSA-xxjr-mmjv-4gpg carries both, and the
    # order in the list is not guaranteed. A loop that stopped at the first
    # entry base_score() declined would return "unknown" for this record.
    [{"type": "CVSS_V4", "score": V4_ONLY}, {"type": "CVSS_V3", "score": V31_MODERATE}],
])
def test_tier_three_continues_past_a_vector_it_cannot_parse(vectors):
    assert severity_of(_vuln(severity=vectors)) == "moderate"


def test_a_v4_only_record_with_no_word_is_unknown_not_a_crash():
    """The recorded gap in NOTES-0_4 §8.1, pinned as a test so it stays a
    deliberate limitation rather than becoming a surprise. If v4 support ever
    lands, this test is the one that should fail."""
    assert severity_of(_vuln(severity=[{"type": "CVSS_V4", "score": V4_ONLY}])) == "unknown"


def test_the_top_level_word_wins_over_the_affected_one():
    """Pins the ordering, so a refactor that reorders the tiers is visible."""
    vuln = _vuln(
        database_specific={"severity": "CRITICAL"},
        affected=[{"database_specific": {"severity": "LOW"}}],
    )
    assert severity_of(vuln) == "critical"


def _affected(ecosystem="npm", name="axios", fixed=("1.7.3",)):
    return {"package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, *({"fixed": f} for f in fixed)]}]}


@pytest.mark.parametrize("vuln,expected", [
    (_vuln(affected=[_affected()]), ["1.7.3"]),
    # two maintained branches -- genuinely two fixed versions
    (_vuln(affected=[_affected(fixed=("1.9.1",)), _affected(fixed=("2.0.3",))]),
     ["1.9.1", "2.0.3"]),
    # a different package in the same advisory
    (_vuln(affected=[_affected(name="lodash")]), []),
    # THE ecosystem bug: same name, different ecosystem
    (_vuln(affected=[_affected(ecosystem="PyPI")]), []),
    # no fix published -- an empty list is a fact, not a failure
    (_vuln(affected=[{"package": {"ecosystem": "npm", "name": "axios"},
                      "ranges": [{"events": [{"introduced": "0"}]}]}]), []),
    # deduped
    (_vuln(affected=[_affected(fixed=("1.7.3",)), _affected(fixed=("1.7.3",))]),
     ["1.7.3"]),
    # wrong shapes
    (_vuln(affected=[{"package": "axios"}]), []),
    (_vuln(affected=[_affected() | {"ranges": "nope"}]), []),
    (_vuln(), []),
])
def test_fixed_versions(vuln, expected):
    assert fixed_versions(vuln, REF) == expected

JUNK = [
    {}, {"vulns": None}, {"vulns": "nope"}, {"vulns": [None, 3, "x"]},
    {"vulns": [{}]}, {"vulns": [{"id": 7}]}, {"vulns": [{"id": ""}]},
    {"vulns": [{"id": "X", "affected": "not-a-list"}]},
    {"vulns": [{"id": "X", "aliases": "CVE-1"}]},
    {"vulns": [{"id": "X", "summary": {"text": "no"}}]},
    {"vulns": [{"id": "X", "affected": [{"ranges": [{"events": {}}]}]}]},
    {"vulns": [{"id": "X", "database_specific": None, "severity": None}]},
]


@pytest.mark.parametrize("payload", JUNK)
def test_parse_never_raises(payload):
    """Worth more than any individual severity row. This is the property that
    survives OSV changing its schema -- and the direct analogue of the
    wrongly-shaped-JSON bug resolve() had."""
    assert isinstance(parse_vulns(payload, REF, SOURCE), list)


def test_withdrawn_advisories_are_dropped():
    payload = {"vulns": [_vuln(withdrawn="2023-01-01T00:00:00Z"), _vuln(id="GHSA-live")]}
    assert [v.id for v in parse_vulns(payload, REF, SOURCE)] == ["GHSA-live"]


def test_every_vulnerability_carries_the_source_that_found_it():
    payload = {"vulns": [_vuln()]}
    assert parse_vulns(payload, REF, SOURCE)[0].source == SOURCE

@respx.mock
def test_query_sends_the_resolved_version():
    """Appendix B's 'are you scoring the version you resolved, or the version
    the user typed?' -- asserted mechanically rather than trusted."""
    import json
    route = respx.post(OSV_QUERY_URL).respond(200, json={})
    collect_osv(REF)
    assert json.loads(route.calls.last.request.content) == {
        "version": "1.7.2",
        "package": {"name": "axios", "ecosystem": "npm"},
    }


@respx.mock
@pytest.mark.parametrize("payload", [{}, {"vulns": []}])
def test_an_empty_result_is_a_successful_clean_answer(payload):
    """OSV returns {} or {"vulns": []} depending on the service version. Both
    mean 'nothing known against this' -- which is what §3.3.2 says a clean
    result means, not a failure."""
    respx.post(OSV_QUERY_URL).respond(200, json=payload)
    result = collect_osv(REF)
    assert result.ok is True
    assert result.vulnerabilities == []
    assert result.error is None


@respx.mock
@pytest.mark.parametrize("response,fragment", [
    (httpx.Response(503), "503"),
    (httpx.Response(500), "500"),
    (httpx.Response(429), "429"),
    (httpx.Response(200, text="<html>captive portal</html>"), "non-JSON"),
    (httpx.Response(200, json=[]), "not a JSON object"),
])
def test_a_failure_is_not_a_clean_answer(response, fragment):
    """The pair that IS the §9.1 invariant. Same empty vulnerabilities list as
    the test above; only `ok` tells them apart."""
    respx.post(OSV_QUERY_URL).mock(return_value=response)
    result = collect_osv(REF)
    assert result.ok is False
    assert result.vulnerabilities == []
    assert fragment in result.error


@respx.mock
@pytest.mark.parametrize("exc,fragment", [
    (httpx.ConnectTimeout("boom"), "timeout"),
    (httpx.ReadTimeout("boom"), "timeout"),
    (httpx.ConnectError("boom"), "network error"),
])
def test_transport_errors_are_return_values(exc, fragment):
    respx.post(OSV_QUERY_URL).mock(side_effect=exc)
    result = collect_osv(REF)
    assert result.ok is False and fragment in result.error


@respx.mock
def test_pagination_is_followed():
    respx.post(OSV_QUERY_URL).mock(side_effect=[
        httpx.Response(200, json={"vulns": [_vuln(id="A")], "next_page_token": "t"}),
        httpx.Response(200, json={"vulns": [_vuln(id="B")]}),
    ])
    result = collect_osv(REF)
    assert [v.id for v in result.vulnerabilities] == ["A", "B"]
    assert result.ok is True and result.error is None


@respx.mock
def test_truncation_is_reported_rather_than_hidden():
    respx.post(OSV_QUERY_URL).respond(
        200, json={"vulns": [_vuln()], "next_page_token": "forever"})
    result = collect_osv(REF)
    assert result.ok is True          
    assert "truncated" in result.error   

def test_all_sources_failed_is_not_a_clean_result():
    """§15: 'All sources failed -> exit 12, not "no vulnerabilities"'. The
    failure mode that makes the tool actively harmful. run.py applies
    offline_policy to this; the collector's job is to make it distinguishable."""
    from openshield.collect import _evidence
    ev = _evidence(REF, SourceResult(False, source=SOURCE, error="503 from api.osv.dev"))
    assert ev.sources == []
    assert ev.partial is True
    assert ev.degraded_sources == ["osv: 503 from api.osv.dev"]
    assert ev.vulnerabilities == []


def test_a_clean_result_is_not_partial():
    from openshield.collect import _evidence
    ev = _evidence(REF, SourceResult(True, [], SOURCE))
    assert ev.sources == [SOURCE] and ev.partial is False


@respx.mock
def test_collect_opens_one_client_for_the_batch(client_spy):
    respx.post(OSV_QUERY_URL).respond(200, json={})
    collect([REF, PackageRef(name="lodash", version="4.17.21")])
    assert len(client_spy) == 1