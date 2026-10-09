"""collect/github.py -- wave 2.

Four sections: the gate (which branch fires when), status handling (404 vs 403
vs rate limit), the contributor count (the Link-header trick and its fallback),
and parsing.

FIXTURES USE GITHUB'S TIMESTAMP FORMAT (`...T12:00:00Z`, no milliseconds), not
datetime.isoformat(). The registry sends milliseconds, GitHub does not, and
both end in Z -- a fixture built from isoformat() produces `+00:00`, which
neither host ever sends (NOTES-M1 D.4).
"""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from openshield.collect import github
from openshield.collect.github import contributor_count, fetch_for, parse
from openshield.models import PackageRef, RegistryInfo, RepositoryInfo, SourceRef

REF = PackageRef(name="axios", version="1.7.2")
TOKEN = "ghp_" + "x" * 36

REPO_URL = "https://api.github.com/repos/axios/axios"
CONTRIB_URL = "https://api.github.com/repos/axios/axios/contributors"

REGISTRY = RegistryInfo(repository_owner="axios", repository_name="axios",
                        maintainer_count=3, license="MIT")
NO_REPO = RegistryInfo(maintainer_count=1, license="MIT")

SOURCE = SourceRef(name="github",
                   fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc))


def github_time(days_ago: int) -> str:
    """GitHub's own shape: no milliseconds, trailing Z."""
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def repo_body(**overrides) -> dict:
    body = {
        "full_name": "axios/axios",
        "archived": False,
        "pushed_at": github_time(5),
        "stargazers_count": 106_000,
        "open_issues_count": 12,
    }
    body.update(overrides)
    return body


def link_header(last: int) -> str:
    base = f'<{CONTRIB_URL}?per_page=1&anon=1&page=2>; rel="next", '
    return base + f'<{CONTRIB_URL}?per_page=1&anon=1&page={last}>; rel="last"'


def _call(registry=REGISTRY, registry_ok=True, ref=REF):
    async def go():
        async with httpx.AsyncClient() as client:
            return await fetch_for(registry, registry_ok, ref, client)
    return asyncio.run(go())


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv("OPENSHIELD_GITHUB_TOKEN", TOKEN)


@pytest.fixture
def no_token(monkeypatch):
    monkeypatch.delenv("OPENSHIELD_GITHUB_TOKEN", raising=False)


# ------------------------------------------------------------------------------
# 1. The gate -- which branch fires, and whether it is degradation
# ------------------------------------------------------------------------------

def test_no_token_is_a_skip_not_a_failure(no_token):
    """A.3. This fires on EVERY run for an unconfigured user. A warning that
    always fires is furniture, and it would train the reader past the OSV
    failures that matter."""
    result = _call()
    assert result.ok is False
    assert result.skipped is True            # -> never sets partial
    assert "no token" in result.error


def test_the_token_is_never_echoed_in_an_error(token):
    """§13: secrets are environment-only and never rendered. Cheap, and the
    kind of test usually added only after a leak."""
    with respx.mock:
        respx.get(url__regex=r".*api\.github\.com/.*").respond(403)
        result = _call()
    assert TOKEN not in (result.error or "")


def test_a_package_with_no_repository_is_a_skip(token):
    """B.5. Nothing to fetch is a complete answer -- including GitLab,
    Bitbucket and monorepo subpaths, which npm.py refuses to guess at."""
    result = _call(registry=NO_REPO)
    assert result.ok is False and result.skipped is True
    assert "no GitHub repository" in result.error


def test_a_failed_registry_lookup_is_degradation_naming_the_lookup(token):
    """A.1: an unknown repository is different from knowing there is none."""
    result = _call(registry=None, registry_ok=False)
    assert result.ok is False and result.skipped is False
    assert "repository unknown (registry lookup failed)" in result.error


def test_an_unreadable_packument_says_so_rather_than_blaming_the_lookup(token):
    """D.3. The registry ANSWERED. Saying the lookup failed would put a false
    claim in degraded_sources."""
    result = _call(registry=None, registry_ok=True)
    assert result.ok is False and result.skipped is False
    assert "could not be read" in result.error
    assert "lookup failed" not in result.error


def test_the_gate_makes_no_request_when_it_skips(no_token):
    """The skip branches must short-circuit BEFORE the network. conftest's
    socket guard raises a BaseException on any real connection, so a leak here
    errors rather than degrading."""
    assert _call().skipped is True          # no respx mock, no guard trip


# ------------------------------------------------------------------------------
# 2. Status handling -- 404 vs 403 vs rate limit
# ------------------------------------------------------------------------------

@respx.mock
def test_a_404_is_a_failure_not_an_absence(token):
    """Moved, renamed, private or deleted -- we do not know which, and we know
    nothing about the repository. The OPPOSITE of a 404 from the npm downloads
    host, which is a real answer of zero (B.5)."""
    respx.get(REPO_URL).respond(404)
    respx.get(url__startswith=CONTRIB_URL).respond(404)
    result = _call()
    assert result.ok is False and result.skipped is False
    assert "404" in result.error and "private or deleted" in result.error


@respx.mock
def test_a_rate_limit_says_when_it_resets(token):
    """A message you can act on beats one you can only read."""
    reset = int(datetime(2026, 10, 9, 18, 42, tzinfo=timezone.utc).timestamp())
    respx.get(url__regex=r".*api\.github\.com/.*").respond(
        403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset)})
    result = _call()
    assert result.ok is False
    assert "rate limited" in result.error and "18:42Z" in result.error


@respx.mock
def test_a_403_that_is_not_a_rate_limit_reads_differently(token):
    """A token without the right scope, or a repository you cannot see. Same
    status code, a different thing to go and fix."""
    respx.get(url__regex=r".*api\.github\.com/.*").respond(
        403, headers={"X-RateLimit-Remaining": "4998"})
    result = _call()
    assert "forbidden" in result.error
    assert "rate limited" not in result.error


@respx.mock
@pytest.mark.parametrize("response,fragment", [
    (httpx.Response(500), "500"),
    (httpx.Response(200, text="<html>portal</html>"), "non-JSON"),
    (httpx.Response(200, json=[]), "not a JSON object"),
])
def test_other_failures_are_named_return_values(token, response, fragment):
    respx.get(REPO_URL).mock(return_value=response)
    respx.get(url__startswith=CONTRIB_URL).respond(200, json=[])
    result = _call()
    assert result.ok is False and fragment in result.error


@respx.mock
@pytest.mark.parametrize("exc,fragment", [
    (httpx.ConnectTimeout("boom"), "timeout"),
    (httpx.ConnectError("boom"), "network error: ConnectError"),
])
def test_transport_errors_are_return_values(token, exc, fragment):
    respx.get(url__regex=r".*api\.github\.com/.*").mock(side_effect=exc)
    result = _call()
    assert result.ok is False and fragment in result.error


# ------------------------------------------------------------------------------
# 3. The contributor count -- the Link-header trick
# ------------------------------------------------------------------------------

def _response(body, headers=None) -> httpx.Response:
    return httpx.Response(200, json=body, headers=headers or {})


def test_the_count_comes_from_the_link_headers_last_page():
    """per_page=1 makes the last page number the contributor count. GitHub
    exposes it no other way."""
    assert contributor_count(_response([{}], {"Link": link_header(431)})) == 431


def test_no_link_header_means_one_page_so_the_fallback_is_the_body_length():
    """NEVER 0 by default. Zero would read as 'no contributors' and cost -8
    under §9.4, for a repository that simply has one."""
    assert contributor_count(_response([{"login": "a"}])) == 1


def test_an_empty_list_with_no_link_header_is_a_real_zero():
    """GitHub returns [] for a repository with no commits. That IS zero
    contributors -- a measurement, not an absence."""
    assert contributor_count(_response([])) == 0


@pytest.mark.parametrize("body", [{"message": "Not Found"}, "a string", 7, None])
def test_a_body_that_is_not_a_list_is_unknown_not_zero(body):
    """None means 'we genuinely do not know', which §9.4 scores as no signal
    rather than as a bad one."""
    assert contributor_count(_response(body)) is None


def test_a_malformed_link_header_falls_back_to_the_body():
    """Over-trusting the header is how you get 0 or a crash. The body is still
    there to count."""
    assert contributor_count(_response([{}], {"Link": "garbage"})) == 1


def test_the_header_is_matched_case_insensitively():
    """httpx normalises header names, but a cached or proxied response may not
    arrive through httpx in M1 Step 1.4."""
    assert contributor_count(_response([{}], {"link": link_header(9)})) == 9


@respx.mock
def test_a_failed_contributor_lookup_is_an_incomplete_answer(token):
    """ok=True WITH an error -- the same relationship the downloads host has
    to the packument in npm.py. The repository answered; one field is missing.
    """
    respx.get(REPO_URL).respond(200, json=repo_body())
    respx.get(url__startswith=CONTRIB_URL).respond(500)

    result = _call()

    assert result.ok is True
    assert "contributor count unavailable" in result.error
    assert parse(result.data, SOURCE).contributors is None


@respx.mock
def test_a_failed_repository_lookup_fails_the_collector(token):
    """The repository is this collector's reason to exist. Without it there is
    nothing to have an incomplete version of."""
    respx.get(REPO_URL).respond(404)
    respx.get(url__startswith=CONTRIB_URL).respond(200, json=[{}],
                                                   headers={"Link": link_header(400)})
    assert _call().ok is False


# ------------------------------------------------------------------------------
# 4. Transport, merged, and parsing
# ------------------------------------------------------------------------------

@respx.mock
def test_both_requests_are_made_and_merged(token):
    repo = respx.get(REPO_URL).respond(200, json=repo_body())
    contrib = respx.get(url__startswith=CONTRIB_URL).respond(
        200, json=[{}], headers={"Link": link_header(431)})

    result = _call()

    assert repo.called and contrib.called
    assert result.ok is True and result.error is None
    assert result.source is not None and result.source.name == "github"

    info = parse(result.data, result.source)
    assert info == RepositoryInfo(archived=False, days_since_last_push=5,
                                  contributors=431, stars=106_000)


@respx.mock
def test_the_token_is_sent_as_a_bearer_header(token):
    repo = respx.get(REPO_URL).respond(200, json=repo_body())
    respx.get(url__startswith=CONTRIB_URL).respond(200, json=[{}])
    _call()
    assert repo.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"


@respx.mock
def test_an_archived_repository_reports_archived_true(token):
    """The signal §9.4 charges -20 for, and the reason archived=None must be
    distinguishable from archived=False (A.2)."""
    respx.get(REPO_URL).respond(200, json=repo_body(archived=True))
    respx.get(url__startswith=CONTRIB_URL).respond(200, json=[{}])
    assert parse(_call().data, SOURCE).archived is True


@pytest.mark.parametrize("bad", [
    {}, {"full_name": "x"}, {"full_name": "x", "stargazers_count": 1}, [], "str", None, 7,
])
def test_parse_returns_None_for_an_unreadable_body(bad):
    """Same None-versus-default rule as npm.parse. A defaulted
    RepositoryInfo() would be a measurement that never happened."""
    assert parse(bad, SOURCE) is None


@pytest.mark.parametrize("body", [
    {"archived": "yes", "pushed_at": "nope", "stargazers_count": "lots"},
    {"archived": False, "pushed_at": None, "stargazers_count": None},
    {"archived": False, "pushed_at": "2024-05-01T12:00:00"},     # naive
    {"archived": False, "_contributor_count": "many"},
])
def test_parse_never_raises_and_wrong_shapes_become_None(body):
    """B.4, extended to this collector."""
    info = parse(body, SOURCE)
    assert info is None or isinstance(info, RepositoryInfo)


def test_a_wrong_shaped_field_is_None_not_a_default():
    info = parse({"archived": "yes", "stargazers_count": "lots",
                  "pushed_at": "nonsense"}, SOURCE)
    assert info is not None
    assert info.archived is None          # "yes" is not a bool
    assert info.stars is None
    assert info.days_since_last_push is None


def test_the_age_uses_githubs_timestamp_format():
    """No milliseconds, trailing Z -- and _parse_iso is imported from npm.py
    rather than reimplemented, so there is one place for this trap to live."""
    info = parse({"archived": False, "pushed_at": github_time(45)}, SOURCE)
    assert info.days_since_last_push == 45