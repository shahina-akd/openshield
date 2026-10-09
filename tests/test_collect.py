"""Step 1.1 -- the two-wave fan-out, batch isolation, degradation, assembly.

RULES FOR THIS FILE (and for any M1 test that goes through collect()):

1. EVERY TEST IS SYNCHRONOUS AND DRIVES collect(). collect() owns the only
   asyncio.run, so going through it exercises _survive, the wave-2 guard,
   _assemble, the batch guard, and the client lifecycle. pyproject.toml turns
   PytestUnhandledCoroutineWarning into an error, so an `async def test_` here
   fails loudly instead of being skipped.

2. EVERY "HAPPY PATH" TEST ASSERTS `ev.partial is False`. collect() is designed
   never to raise, so a test that only checks "no exception" verifies almost
   nothing: a collector that timed out, deadlocked, or reached the network would
   still return normally -- just degraded. NOTES-M1-inheritance.md D.1.

3. THIS FILE TESTS FAN-OUT AND ASSEMBLY, NOT PARSING. The `healthy` fixture
   stubs npm.parse and github.parse along with the fetchers, so the file runs at
   the end of Step 1.1 -- before either parser exists -- and a parser bug fails
   test_npm.py / test_github.py rather than here.

4. PATCH TARGETS ARE PART OF THE CONTRACT. Collectors are patched on the MODULE
   OBJECT, which works only because collect/__init__.py calls them as
   `github.fetch_for(...)`. test_collectors_are_called_through_their_modules
   pins it.

5. fetch_for stubs take `(registry, *rest)`, so they survive signature changes
   without edits. Tests that need a specific argument name it explicitly.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
from datetime import datetime, timezone

import pytest

from openshield.collect import base, collect, github, npm, osv
from openshield.collect.base import CollectorResult
from openshield.models import PackageRef, RegistryInfo, RepositoryInfo, SourceRef

REF = PackageRef(name="axios", version="1.7.2")
REF2 = PackageRef(name="lodash", version="4.17.11")
REF3 = PackageRef(name="@babel/core", version="7.24.0")
ALL_REFS = [REF, REF2, REF3]

TOKEN = "x" * 40


def src(name: str) -> SourceRef:
    return SourceRef(name=name, fetched_at=datetime(2026, 9, 10, 12, tzinfo=timezone.utc))


def ok(name: str, data: dict | None = None) -> CollectorResult:
    return CollectorResult(ok=True, data=data or {}, source=src(name))


# A real OSV shape -- osv.parse_vulns is M0 code and runs for real here.
OSV_PAYLOAD = {
    "vulns": [{
        "id": "GHSA-test-0001",
        "summary": "a finding",
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"name": "axios", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.7.3"}]}],
        }],
    }]
}

# Opaque to this file -- npm.parse and github.parse are stubbed. Kept in the
# hosts' own shapes anyway (D.4): `...000Z` for the registry, `...Z` for GitHub.
NPM_PAYLOAD = {"name": "axios", "time": {"1.7.2": "2026-08-11T12:00:00.000Z"}}
GITHUB_PAYLOAD = {"archived": False, "pushed_at": "2026-09-05T12:00:00Z"}

REGISTRY = RegistryInfo(
    maintainer_count=3, license="MIT", weekly_downloads=50_000_000,
    days_since_last_publish=30, repository_owner="axios", repository_name="axios",
)
REGISTRY_NO_REPO = RegistryInfo(maintainer_count=1, license="MIT")
REPOSITORY = RepositoryInfo(archived=False, days_since_last_push=5,
                            contributors=400, stars=100_000)


# --------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------

@pytest.fixture
def healthy(monkeypatch):
    """All three collectors succeed; both parsers return fixed models.

    Explicit, not autouse: a test that needs the REAL github.fetch_for simply
    does not request this, and nothing has to be undone. monkeypatch.undo()
    reverses every patch on the instance and works only by accident of order.
    """
    async def osv_fetch(ref, client):
        return ok(base.NAME_OSV, OSV_PAYLOAD)

    async def npm_fetch(ref, client):
        return ok(base.NAME_NPM, NPM_PAYLOAD)

    async def github_fetch_for(registry, *rest):
        return ok(base.NAME_GITHUB, GITHUB_PAYLOAD)

    monkeypatch.setattr(osv, "fetch", osv_fetch)
    monkeypatch.setattr(npm, "fetch", npm_fetch)
    monkeypatch.setattr(npm, "parse", lambda payload, ref: REGISTRY)
    monkeypatch.setattr(github, "fetch_for", github_fetch_for)
    monkeypatch.setattr(github, "parse", lambda payload, source: REPOSITORY)


def _attr(module) -> str:
    return "fetch_for" if module is github else "fetch"


_NAMES = {osv: base.NAME_OSV, npm: base.NAME_NPM, github: base.NAME_GITHUB}


def _fail(monkeypatch, module, error: str) -> None:
    """ok=False, skipped=False -- genuine degradation.

    Carries a SOURCE, deliberately. A failure with source=None is filtered out
    of Evidence.sources by the `r.source` check alone, so a test built on it
    cannot notice if _assemble stops checking `r.ok` -- the bug that would let
    a 503 appear in `check`'s list of sources that answered. Mutation-tested:
    with source=None here, dropping `r.ok` from _assemble passed the suite."""
    async def failed(*args, **kwargs):
        return CollectorResult(ok=False, error=error, source=src(_NAMES[module]))
    monkeypatch.setattr(module, _attr(module), failed)


def _skip(monkeypatch, module, error: str) -> None:
    """ok=False, skipped=True -- NOT degradation (A.3)."""
    async def skipped(*args, **kwargs):
        return CollectorResult(ok=False, skipped=True, error=error)
    monkeypatch.setattr(module, _attr(module), skipped)


def _raise(monkeypatch, module, exc: Exception) -> None:
    async def boom(*args, **kwargs):
        raise exc
    monkeypatch.setattr(module, _attr(module), boom)


@pytest.fixture
def real_fetch_for(monkeypatch):
    """OSV and npm stubbed, github.fetch_for REAL -- for its branch logic.

    Returns a setter: call it with the npm result and what npm.parse should
    return. The token is set, so the no-token branch does not short-circuit
    every case; test_no_token_is_a_quiet_skip unsets it deliberately.
    """
    monkeypatch.setenv("OPENSHIELD_GITHUB_TOKEN", TOKEN)

    async def osv_fetch(ref, client):
        return ok(base.NAME_OSV, OSV_PAYLOAD)
    monkeypatch.setattr(osv, "fetch", osv_fetch)

    def configure(npm_result: CollectorResult, parsed: RegistryInfo | None):
        async def npm_fetch(ref, client):
            return npm_result
        monkeypatch.setattr(npm, "fetch", npm_fetch)
        monkeypatch.setattr(npm, "parse", lambda payload, ref: parsed)

    return configure


def _happy(ev) -> None:
    """Rule 2, as a helper. Use on every test that means 'nothing degraded'."""
    assert ev.partial is False, f"silently degraded: {ev.degraded_sources}"
    assert ev.degraded_sources == []


# --------------------------------------------------------------------------
# 0. Guards on this file's own assumptions
# --------------------------------------------------------------------------

def test_collectors_are_called_through_their_modules():
    """Every patch here targets a module attribute. `from .github import
    fetch_for` would bind a local name the patch cannot reach, and every
    degradation test would go green against unpatched production code.

    Checked on the AST, not the source text: a substring search matches the
    comment in collect/__init__.py that WARNS against the forbidden import, and
    a guard that cannot tell a warning from a violation is not a guard.
    """
    import ast

    tree = ast.parse(inspect.getsource(importlib.import_module("openshield.collect")))

    # No `from .osv/.npm/.github import <name>` -- those bind local names.
    banned = {"osv", "npm", "github"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            assert node.module not in banned, (
                f"`from .{node.module} import ...` makes this file's patches dead"
            )

    # And the calls really are module-qualified.
    called = {
        f"{node.func.value.id}.{node.func.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
    }
    for expected in ("osv.fetch", "npm.fetch", "npm.parse", "github.fetch_for"):
        assert expected in called, f"expected a module-qualified call: {expected}"


def _flatten(exc: BaseException):
    """Yield exc and, recursively, everything inside an exception group.

    httpx/anyio open connections inside a TaskGroup, and a TaskGroup wraps
    whatever escapes it in a BaseExceptionGroup. Whether our guard arrives bare
    or wrapped depends on whether DNS or the TCP connect tripped first, which
    varies by machine (a proxy, an IP-literal host, a warm resolver cache all
    change it). Flattening makes the assertion true of both shapes.
    """
    yield exc
    for sub in getattr(exc, "exceptions", ()):
        yield from _flatten(sub)


def test_a_real_network_call_is_an_error_not_a_degraded_source():
    """D.1, pinned permanently. The REAL osv.fetch runs here, with no stub and
    no respx, so it reaches for the network.

    The guard in conftest raises RealNetworkAttempted -- a BaseException -- and
    it must escape collect() as an error. If this test instead sees a normal
    return, the degradation machinery has swallowed the guard again and every
    test in this file has lost its ability to notice a real network call.
    """
    from tests.conftest import RealNetworkAttempted

    with pytest.raises(BaseException) as caught:
        collect([REF])

    assert any(isinstance(e, RealNetworkAttempted) for e in _flatten(caught.value)), (
        f"the guard was swallowed; collect() raised {caught.value!r} instead"
    )


# --------------------------------------------------------------------------
# 1. Degradation -- the three states (A.3)
# --------------------------------------------------------------------------

def test_the_happy_path_is_fully_populated(healthy):
    """Asserted once, so every failure test below means something."""
    ev = collect([REF])[0]
    _happy(ev)
    assert ev.package == REF
    assert {s.name for s in ev.sources} == {base.NAME_OSV, base.NAME_NPM, base.NAME_GITHUB}
    assert ev.unavailable == []
    assert ev.registry == REGISTRY
    assert ev.repository == REPOSITORY
    assert [v.id for v in ev.vulnerabilities] == ["GHSA-test-0001"]


@pytest.mark.parametrize("module", [osv, npm, github], ids=["osv", "npm", "github"])
def test_one_collector_raising_does_not_deny_the_others(healthy, monkeypatch, module):
    """§15. The rule that makes degradation work -- for EVERY collector, wave 1
    and wave 2. The first draft of BUILD-M1 left wave 2 unguarded, and a raise
    in github.fetch_for escaped _collect_one entirely."""
    _raise(monkeypatch, module, RuntimeError("collector bug"))

    ev = collect([REF])[0]

    assert ev.partial is True
    assert len(ev.sources) == 2                 # the other two still answered
    (degraded,) = ev.degraded_sources
    assert "RuntimeError" in degraded and "collector bug" in degraded


def test_a_skipped_collector_is_not_degradation(healthy, monkeypatch):
    """A.3. partial stays False..."""
    _skip(monkeypatch, github, "no token configured")
    _happy(collect([REF])[0])


def test_a_skipped_collector_is_still_recorded(healthy, monkeypatch):
    """...but the skip must SURVIVE assembly. One that vanished entirely would
    also satisfy partial=False, and A.3's quiet line would have nothing to
    render."""
    _skip(monkeypatch, github, "no token configured")
    assert collect([REF])[0].unavailable == ["github: no token configured"]


def test_a_failed_collector_is_degradation(healthy, monkeypatch):
    _fail(monkeypatch, github, "403 rate limited")
    ev = collect([REF])[0]
    assert ev.partial is True
    assert ev.degraded_sources == ["github: 403 rate limited"]
    assert ev.unavailable == []


# --------------------------------------------------------------------------
# 2. github.fetch_for's branches -- REAL function, D.3's four states
# --------------------------------------------------------------------------

def test_no_token_is_a_quiet_skip(real_fetch_for, monkeypatch):
    """A.3. Fires on every run for an unconfigured user, so it must not be
    furniture in the degraded banner."""
    monkeypatch.delenv("OPENSHIELD_GITHUB_TOKEN")
    real_fetch_for(ok(base.NAME_NPM, NPM_PAYLOAD), REGISTRY)

    ev = collect([REF])[0]

    assert ev.partial is False
    assert any("no token" in u for u in ev.unavailable)


def test_a_skipped_registry_means_github_is_not_attempted(healthy, monkeypatch):
    """npm SKIPPED is not npm FAILED. Nothing was looked up, so nothing failed:
    GitHub is simply not attempted either. Without the skip branch in
    _collect_one, fetch_for would read registry=None as a failed lookup and put
    a false line in degraded_sources -- which is exactly what the Step 1.1
    skeleton npm collector would do on every run with a token set."""
    _skip(monkeypatch, npm, "not implemented until Step 1.2")

    ev = collect([REF])[0]

    _happy(ev)
    assert "github: not attempted (registry not consulted)" in ev.unavailable


def test_a_package_with_no_repository_is_a_skip_not_a_failure(real_fetch_for):
    """B.5, and the fetch_for branch the first test list left out. Nothing to
    fetch is a complete answer."""
    real_fetch_for(ok(base.NAME_NPM, NPM_PAYLOAD), REGISTRY_NO_REPO)

    ev = collect([REF])[0]

    _happy(ev)
    assert ev.repository is None
    assert any("no GitHub repository" in u for u in ev.unavailable)


def test_a_failed_registry_lookup_makes_github_degraded(real_fetch_for):
    """A.1: the repository is UNKNOWN, which is different from knowing there is
    none -- so this skip IS degradation, and is named as such."""
    real_fetch_for(CollectorResult(ok=False, error="503 from registry"), None)

    ev = collect([REF])[0]

    assert ev.partial is True
    assert "npm-registry: 503 from registry" in ev.degraded_sources
    assert "github: repository unknown (registry lookup failed)" in ev.degraded_sources
    assert not any(u.startswith("github") for u in ev.unavailable)


def test_an_unreadable_packument_is_not_reported_as_a_failed_lookup(real_fetch_for):
    """D.3. The registry ANSWERED. Saying the lookup failed would put a false
    claim in degraded_sources -- the one block §9.1 requires to be trustworthy.

    Still degradation (the repository is genuinely unknown), with a message that
    says which thing broke: the parser, not the network."""
    real_fetch_for(ok(base.NAME_NPM, {"unexpected": ["shape"]}), None)

    ev = collect([REF])[0]

    assert ev.partial is True
    assert "github: repository unknown (registry answered but could not be read)" \
        in ev.degraded_sources
    assert not any("lookup failed" in d for d in ev.degraded_sources)


# --------------------------------------------------------------------------
# 3. Assembly invariants -- where missing evidence becomes good-looking evidence
# --------------------------------------------------------------------------

@pytest.mark.parametrize("module,name", [
    (osv, base.NAME_OSV), (npm, base.NAME_NPM), (github, base.NAME_GITHUB),
], ids=["osv", "npm", "github"])
def test_each_collector_is_named_correctly_when_it_alone_fails(healthy, monkeypatch,
                                                               module, name):
    """D.5. _assemble once paired names with results POSITIONALLY; a reorder
    made a GitHub 403 read as `osv: 403`. Fail each in turn, expect its own
    name back."""
    _fail(monkeypatch, module, "the marker error")
    assert collect([REF])[0].degraded_sources == [f"{name}: the marker error"]


@pytest.mark.parametrize("module,name", [
    (osv, base.NAME_OSV), (npm, base.NAME_NPM), (github, base.NAME_GITHUB),
], ids=["osv", "npm", "github"])
def test_a_failed_or_skipped_collector_is_never_listed_as_a_source(healthy, monkeypatch,
                                                                   module, name):
    """`sources` is what `check` prints as having answered. A 503 there is the
    tool claiming an answer it does not have."""
    _fail(monkeypatch, module, "down")
    assert name not in [s.name for s in collect([REF])[0].sources]
    _skip(monkeypatch, module, "not configured")
    assert name not in [s.name for s in collect([REF])[0].sources]


def test_a_failed_github_fetch_leaves_repository_None(healthy, monkeypatch):
    """A.2 one step upstream of score(). None means 'not collected'; a
    defaulted RepositoryInfo() would be a measurement that never happened."""
    _fail(monkeypatch, github, "404 not found")
    assert collect([REF])[0].repository is None


def test_a_failed_npm_fetch_leaves_registry_None(healthy, monkeypatch):
    _fail(monkeypatch, npm, "503 from registry")
    assert collect([REF])[0].registry is None


def test_a_failed_osv_fetch_is_not_a_clean_result(healthy, monkeypatch):
    """§9.1 in its most dangerous form: an empty vulns list is
    indistinguishable from a clean package UNLESS partial carries the truth."""
    _fail(monkeypatch, osv, "timeout after 8s")
    ev = collect([REF])[0]
    assert ev.vulnerabilities == []
    assert ev.partial is True
    assert "osv: timeout after 8s" in ev.degraded_sources


@pytest.mark.parametrize("setup", ["ok", "skip", "fail", "raise"])
def test_partial_always_equals_bool_degraded_sources(healthy, monkeypatch, setup):
    """The Evidence validator says the invariant broke; this says which state
    broke it."""
    {"ok": lambda: None,
     "skip": lambda: _skip(monkeypatch, github, "no token configured"),
     "fail": lambda: _fail(monkeypatch, github, "403"),
     "raise": lambda: _raise(monkeypatch, github, RuntimeError("x"))}[setup]()
    ev = collect([REF])[0]
    assert ev.partial is bool(ev.degraded_sources)
    assert ev.partial is (setup in ("fail", "raise"))


# --------------------------------------------------------------------------
# 4. Wave structure (A.1)
# --------------------------------------------------------------------------

def test_osv_and_npm_run_concurrently(healthy, monkeypatch):
    """A.1, wave 1. Each fetch announces itself, then waits for the other.

    The assertion is on the RESULT. A sequential implementation deadlocks, the
    wait times out -- and that TimeoutError is caught and becomes a degraded
    source, so collect() returns normally. Without `_happy(ev)` this test
    passes against the very implementation it exists to reject (D.1)."""
    arrived: dict[str, asyncio.Event] = {}

    def gate(me: str, other: str, payload: dict):
        async def fetch(ref, client):
            arrived.setdefault(me, asyncio.Event()).set()
            await asyncio.wait_for(arrived.setdefault(other, asyncio.Event()).wait(), 0.5)
            return ok(me, payload)
        return fetch

    monkeypatch.setattr(osv, "fetch", gate(base.NAME_OSV, base.NAME_NPM, OSV_PAYLOAD))
    monkeypatch.setattr(npm, "fetch", gate(base.NAME_NPM, base.NAME_OSV, NPM_PAYLOAD))

    _happy(collect([REF])[0])


def test_github_receives_the_parsed_registry_and_its_status(healthy, monkeypatch):
    """Wave 2's input. Parsed RegistryInfo, not a raw dict or URL -- that is
    what keeps every skip case inside fetch_for -- plus the lookup status D.3
    needs to tell an unreadable 200 from a failed lookup.

    Receiving npm's PARSED output also proves ordering: it cannot exist before
    npm finished. That replaces a sleep-based ordering test, which was timing-
    dependent and proved less."""
    seen: list[tuple] = []

    async def github_fetch_for(registry, registry_ok, ref, client):
        seen.append((registry, registry_ok))
        return ok(base.NAME_GITHUB, GITHUB_PAYLOAD)

    monkeypatch.setattr(github, "fetch_for", github_fetch_for)
    collect([REF])

    assert seen == [(REGISTRY, True)]


def test_github_receives_None_and_False_when_the_registry_failed(healthy, monkeypatch):
    seen: list[tuple] = []

    async def github_fetch_for(registry, registry_ok, ref, client):
        seen.append((registry, registry_ok))
        return CollectorResult(ok=False, error="repository unknown")

    _fail(monkeypatch, npm, "503 from registry")
    monkeypatch.setattr(github, "fetch_for", github_fetch_for)
    collect([REF])

    assert seen == [(None, False)]


# --------------------------------------------------------------------------
# 5. The batch path
# --------------------------------------------------------------------------

def test_collect_of_nothing_opens_no_client(async_client_spy):
    """Same discipline as resolve_all: no refs, no network."""
    assert collect([]) == []
    assert async_client_spy == []


def test_evidence_comes_back_in_input_order_paired_with_its_ref(healthy):
    """gather preserves order. This stops an as_completed refactor quietly
    showing axios's advisories under lodash's name."""
    evidence = collect(ALL_REFS)
    assert [e.package for e in evidence] == ALL_REFS


def test_one_refs_pipeline_failing_does_not_deny_the_other_refs(healthy, monkeypatch):
    """D.2 -- Step 0.3's rule at the batch level. _survive covers a COLLECTOR
    raising; this covers npm.parse / _assemble / the Evidence validator raising
    inside _collect_one, which a bare outer gather would let abort the batch."""
    def selective_parse(payload, ref):
        if ref == REF2:
            raise KeyError("unexpected packument shape")
        return REGISTRY
    monkeypatch.setattr(npm, "parse", selective_parse)

    good, bad = collect([REF, REF2])

    _happy(good)
    assert good.package == REF and good.vulnerabilities

    assert bad.package == REF2
    assert bad.partial is True
    assert bad.sources == []
    (reason,) = bad.degraded_sources
    assert reason.startswith("pipeline:") and "KeyError" in reason


def test_collect_opens_exactly_one_async_client(healthy, async_client_spy):
    """B.13. Three hosts, N packages, one pool."""
    collect(ALL_REFS)
    assert len(async_client_spy) == 1


def test_every_collector_receives_the_same_client(healthy, async_client_spy, monkeypatch):
    """B.13, the half a count cannot prove. A collector that takes `client` and
    then calls httpx.get() internally builds a pool the spy never sees."""
    seen: list[object] = []

    async def osv_fetch(ref, client):
        seen.append(client)
        return ok(base.NAME_OSV, OSV_PAYLOAD)

    async def npm_fetch(ref, client):
        seen.append(client)
        return ok(base.NAME_NPM, NPM_PAYLOAD)

    async def github_fetch_for(registry, registry_ok, ref, client):
        seen.append(client)
        return ok(base.NAME_GITHUB, GITHUB_PAYLOAD)

    monkeypatch.setattr(osv, "fetch", osv_fetch)
    monkeypatch.setattr(npm, "fetch", npm_fetch)
    monkeypatch.setattr(github, "fetch_for", github_fetch_for)

    collect(ALL_REFS)

    constructed = async_client_spy[0]["self"]
    assert len(seen) == 3 * len(ALL_REFS)
    assert all(c is constructed for c in seen)


def test_the_client_carries_the_documented_timeout_and_headers(healthy, async_client_spy):
    """§17: every network call carries an explicit timeout. A KeyError here is
    the failure you want -- it names the missing keyword."""
    collect([REF])
    (call,) = async_client_spy
    assert call["kwargs"]["timeout"] is base.TIMEOUT
    assert "openshield" in call["kwargs"]["headers"]["User-Agent"]


def test_the_pool_is_closed_when_collect_returns(healthy, async_client_spy):
    """A leaked pool under M2's ambient interception is a file descriptor per
    npm install."""
    collect([REF])
    assert async_client_spy[0]["self"].is_closed