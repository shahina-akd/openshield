"""Tests for collect/npm.py.

Transport tests drive fetch() through a sync wrapper; parsing tests call
parse() directly with literal dicts.

Fixtures use the registry's timestamp format (`...T12:00:00.000Z`), not
datetime.isoformat() (`...+00:00`), so the parser is tested against what the
registry actually sends.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from openshield.collect import npm
from openshield.collect.npm import (
    _parse_iso,
    downloads_url,
    fetch,
    parse,
    parse_github_repo,
)
from openshield.models import PackageRef, RegistryInfo

REF = PackageRef(name="axios", version="1.7.2")
SCOPED = PackageRef(name="@babel/core", version="7.24.0")

REGISTRY_URL = "https://registry.npmjs.org/axios"
DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week/axios"


def registry_time(days_ago: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def packument(**overrides) -> dict:
    base = {
        "name": "axios",
        "dist-tags": {"latest": "1.7.2"},
        "maintainers": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
        "repository": {"type": "git", "url": "git+https://github.com/axios/axios.git"},
        "versions": {"1.7.2": {"license": "MIT"}},
        "time": {"1.7.2": registry_time(30)},
    }
    base.update(overrides)
    return base


def payload(pack=None, downloads=51_000_000) -> dict:
    return {
        "packument": packument() if pack is None else pack,
        "downloads": {} if downloads is None else {"downloads": downloads},
    }


def _fetch(ref: PackageRef = REF):
    async def go():
        async with httpx.AsyncClient() as client:
            return await fetch(ref, client)
    return asyncio.run(go())


# ------------------------------------------------------------------------------
# 1. parse
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {},                                   # no packument key
    {"packument": {}},                    # no versions key
    {"packument": {"unexpected": ["shape"]}},
    {"packument": []},
    {"packument": "a string"},
    {"packument": None},
    [],
    "not a dict",
    None,
])
def test_parse_returns_None_for_an_unreadable_packument(bad):
    """A default RegistryInfo() would read as "no repository declared",
    turning an unreadable response into a known absence."""
    assert parse(bad, REF) is None


def test_parse_returns_a_model_when_the_packument_declares_no_repository():
    """Counterpart to the test above: a readable packument without a
    repository is a known absence."""
    pack = packument()
    del pack["repository"]
    pack["versions"] = {"1.7.2": {"license": "MIT"}}
    info = parse(payload(pack), REF)
    assert info is not None
    assert info.repository_owner is None
    assert info.license == "MIT"


def test_parse_extracts_every_field():
    info = parse(payload(), REF)
    assert info == RegistryInfo(
        maintainer_count=3,
        license="MIT",
        weekly_downloads=51_000_000,
        days_since_last_publish=30,
        repository_owner="axios",
        repository_name="axios",
    )


@pytest.mark.parametrize("junk", [
    {"packument": {"versions": {}, "maintainers": "three"}},
    {"packument": {"versions": {}, "maintainers": {"a": 1}}},
    {"packument": {"versions": "nope", "time": "nope"}},
    {"packument": {"versions": {}, "time": {"1.7.2": 12345}}},
    {"packument": {"versions": {}, "repository": ["list"]}},
    {"packument": {"versions": {"1.7.2": "a string"}}},
    {"packument": {"versions": {}}, "downloads": "nope"},
    {"packument": {"versions": {}}, "downloads": {"downloads": "many"}},
])
def test_parse_never_raises(junk):
    result = parse(junk, REF)
    assert result is None or isinstance(result, RegistryInfo)


def test_missing_fields_are_None_not_zero():
    """Zero is a measurement; a missing field is an absence."""
    info = parse({"packument": {"versions": {}}}, REF)
    assert info is not None
    assert info.maintainer_count is None
    assert info.weekly_downloads is None
    assert info.days_since_last_publish is None
    assert info.license is None


def test_a_version_level_license_beats_the_top_level_one():
    """A package can relicense between releases."""
    pack = packument(license="Apache-2.0")
    pack["versions"] = {"1.7.2": {"license": "MIT"}}
    assert parse(payload(pack), REF).license == "MIT"


def test_the_legacy_license_object_is_read():
    """The legacy {"type": ..., "url": ...} form still appears in published
    packuments."""
    pack = packument()
    pack["versions"] = {"1.7.2": {"license": {"type": "MIT", "url": "http://x"}}}
    assert parse(payload(pack), REF).license == "MIT"


def test_the_age_is_for_the_resolved_version_not_the_latest():
    pack = packument()
    pack["versions"] = {"1.0.0": {}, "1.7.2": {}}
    pack["time"] = {"1.0.0": registry_time(900), "1.7.2": registry_time(10)}
    assert parse(payload(pack), REF).days_since_last_publish == 10


# ------------------------------------------------------------------------------
# 2. _parse_iso
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    "2024-05-01T12:00:00.000Z",      # npm registry
    "2024-05-01T12:00:00Z",          # GitHub
    "2024-05-01T12:00:00+00:00",     # Python isoformat()
])
def test_parse_iso_accepts_what_the_hosts_actually_send(raw):
    assert _parse_iso(raw) == datetime(2024, 5, 1, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("raw", [
    "2024-05-01T12:00:00",           # naive
    "yesterday", "", None, 7, {}, ["2024-05-01"],
])
def test_parse_iso_refuses_junk_and_naive_times(raw):
    assert _parse_iso(raw) is None


# ------------------------------------------------------------------------------
# 3. parse_github_repo
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("git+https://github.com/axios/axios.git", ("axios", "axios")),
    ("git://github.com/axios/axios.git", ("axios", "axios")),
    ("https://github.com/axios/axios", ("axios", "axios")),
    ("https://github.com/axios/axios#main", ("axios", "axios")),
    ("https://github.com/axios/axios.git#v1", ("axios", "axios")),
    ("git+ssh://git@github.com/axios/axios.git", ("axios", "axios")),
    ("git@github.com:axios/axios.git", ("axios", "axios")),
    ("github:axios/axios", ("axios", "axios")),
    ("axios/axios", ("axios", "axios")),
    ("https://github.com/axios/axios/", ("axios", "axios")),
])
def test_parse_github_repo_accepts_every_published_shape(url, expected):
    assert parse_github_repo(url) == expected
    assert parse_github_repo({"type": "git", "url": url}) == expected


@pytest.mark.parametrize("url", [
    "https://gitlab.com/owner/repo.git",
    "gitlab:owner/repo",
    "https://bitbucket.org/owner/repo",
    "bitbucket:owner/repo",
    "https://example.com/owner/repo",
    "https://github.com/axios",                       # no repo segment
    "https://github.com/axios/axios/tree/main/pkg",   # monorepo subpath
    "", "   ", "not a url", None, 7, [], {}, {"url": None}, {"url": 7},
])
def test_parse_github_repo_returns_None_rather_than_guessing(url):
    """A wrong owner/repo would attribute another project's GitHub data to
    this package."""
    assert parse_github_repo(url) is None


# ------------------------------------------------------------------------------
# 4. Transport
# ------------------------------------------------------------------------------

@respx.mock
def test_both_hosts_are_queried_and_merged():
    reg = respx.get(REGISTRY_URL).respond(200, json=packument())
    dl = respx.get(DOWNLOADS).respond(200, json={"downloads": 51_000_000})

    result = _fetch()

    assert reg.called and dl.called
    assert result.ok is True and result.error is None
    assert result.data["packument"]["name"] == "axios"
    assert result.data["downloads"]["downloads"] == 51_000_000
    assert result.source is not None and result.source.name == "npm-registry"


@respx.mock
def test_fetch_returns_raw_payloads_not_parsed_models():
    """The cache stores fetch() output, so derived values such as age must be
    computed later, in parse()."""
    respx.get(REGISTRY_URL).respond(200, json=packument())
    respx.get(DOWNLOADS).respond(200, json={"downloads": 1})
    assert isinstance(_fetch().data["packument"], dict)


@respx.mock
@pytest.mark.parametrize("response,fragment", [
    (httpx.Response(404), "404"),
    (httpx.Response(503), "503"),
    (httpx.Response(200, text="<html>portal</html>"), "non-JSON"),
    (httpx.Response(200, json=[]), "not a JSON object"),
])
def test_a_failed_packument_fails_the_collector(response, fragment):
    respx.get(REGISTRY_URL).mock(return_value=response)
    respx.get(DOWNLOADS).respond(200, json={"downloads": 1})

    result = _fetch()

    assert result.ok is False and result.skipped is False
    assert fragment in result.error


@respx.mock
@pytest.mark.parametrize("response", [
    httpx.Response(404),
    httpx.Response(503),
])
def test_a_failed_downloads_lookup_is_an_incomplete_answer_not_a_failure(response):
    """ok=True with an error: the source answered, but incompletely."""
    respx.get(REGISTRY_URL).respond(200, json=packument())
    respx.get(DOWNLOADS).mock(return_value=response)

    result = _fetch()

    assert result.ok is True
    assert result.source is not None
    assert "downloads unavailable" in result.error
    assert parse(result.data, REF).weekly_downloads is None


@respx.mock
@pytest.mark.parametrize("exc,fragment", [
    (httpx.ConnectTimeout("boom"), "timeout"),
    (httpx.ReadTimeout("boom"), "timeout"),
    (httpx.ConnectError("boom"), "network error: ConnectError"),
])
def test_transport_errors_are_return_values(exc, fragment):
    respx.get(REGISTRY_URL).mock(side_effect=exc)
    respx.get(DOWNLOADS).respond(200, json={"downloads": 1})
    result = _fetch()
    assert result.ok is False and fragment in result.error


@respx.mock
def test_scoped_names_are_encoded_for_the_registry_but_not_the_downloads_host():
    """The registry requires %2F in the path; the downloads API takes the
    scope literally."""
    reg = respx.get("https://registry.npmjs.org/@babel%2Fcore").respond(
        200, json={"name": "@babel/core", "versions": {"7.24.0": {}}, "time": {}})
    dl = respx.get(
        "https://api.npmjs.org/downloads/point/last-week/@babel/core"
    ).respond(200, json={"downloads": 10})

    result = _fetch(SCOPED)

    assert reg.called and dl.called
    assert result.ok is True and result.error is None


def test_downloads_url_keeps_the_scope_literal():
    assert downloads_url("axios").endswith("/axios")
    assert downloads_url("@babel/core").endswith("/@babel/core")


@respx.mock
def test_the_two_requests_overlap(monkeypatch):
    """Each response waits for the other request to arrive, so sequential
    requests time out. The timeout is caught by the collector, hence the
    assertion on the result."""
    arrived: dict[str, asyncio.Event] = {}

    def gate(me: str, other: str, body: dict):
        async def responder(request):
            arrived.setdefault(me, asyncio.Event()).set()
            await asyncio.wait_for(
                arrived.setdefault(other, asyncio.Event()).wait(), 0.5)
            return httpx.Response(200, json=body)
        return responder

    respx.get(REGISTRY_URL).mock(side_effect=gate("reg", "dl", packument()))
    respx.get(DOWNLOADS).mock(side_effect=gate("dl", "reg", {"downloads": 7}))

    result = _fetch()

    assert result.ok is True, "the two requests are sequential, not concurrent"
    assert result.error is None