"""Fan-out, degradation, and assembly. collect(refs) -> list[Evidence].

Two waves, not one gather (NOTES-M1 A.1): GitHub needs repository.url, which
only the npm registry collector can supply.

    wave 1:   osv   npm-registry      concurrent, independent
                          |
    wave 2:            github         only after npm has answered

COLLECTORS ARE CALLED THROUGH THEIR MODULES -- osv.fetch, npm.fetch, npm.parse,
github.fetch_for -- never `from .github import fetch_for`. The tests patch the
module attribute; a local import binds a name the patch cannot reach, and every
degradation test would go green against unpatched production code.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from .. import cache
from ..models import Evidence, PackageRef, SourceRef
from . import base, github, npm, osv
from .base import CollectorResult


def collect(refs: list[PackageRef]) -> list[Evidence]:
    """The ONE asyncio.run in the codebase. run.py stays synchronous.

    This boundary is also what keeps the test suite synchronous: everything
    above it -- run.py, cli.py, and every test that goes through collect() --
    is ordinary sync code, so no async test runner is needed anywhere.
    """
    if not refs:
        return []            # no refs, no client -- same as resolve_all
    return asyncio.run(_collect_all(refs))


async def _collect_all(refs: list[PackageRef]) -> list[Evidence]:
    # One pool for every collector and every ref (NOTES-M1 B.13).
    async with httpx.AsyncClient(timeout=base.TIMEOUT, headers=base.HEADERS) as client:
        # return_exceptions=True: Step 0.3's rule at the batch level (D.2).
        # One command line carries several specifiers, and an exception in one
        # ref's pipeline must not lose the others' evidence.
        results = await asyncio.gather(
            *(_collect_one(r, client) for r in refs), return_exceptions=True
        )
    return [
        r if isinstance(r, Evidence) else _failed_evidence(ref, r)
        for ref, r in zip(refs, results)
    ]


async def _cached(source: str, ref: PackageRef, make_request) -> CollectorResult:
    """Read-through: hit the cache, else fetch and store on success.

    `make_request` is a CALLABLE, not a coroutine. Calling an async function
    creates a coroutine immediately -- it does not run it -- so passing
    `osv.fetch(ref, client)` would build one on every cache HIT and then
    discard it unawaited, which Python reports as
    `RuntimeWarning: coroutine 'fetch' was never awaited`. Harmless here, but
    it means the cache saved nothing: the request object was still constructed.
    A zero-argument lambda defers creation until there is actually a miss.

    The cache wraps the TRANSPORT half only, which is the whole reason Step 1.1
    kept transport and parsing separate (NOTES-M1 B.1). Parsing still runs on
    every request, hit or miss -- which is what keeps the age integers correct
    (B.2).

    SUCCESSES ONLY are stored (B.3). A cached 503 is a source that stays broken
    for a day after it recovered, and `from_cache=True` on a failure would
    render as 'as of nine hours ago' about something that never succeeded.
    """
    hit = cache.get(source, ref.canonical)
    if hit is not None:
        return CollectorResult(
            ok=True, data=hit,
            source=SourceRef(name=source, fetched_at=datetime.now(timezone.utc),
                             from_cache=True),
        )

    result = await make_request()
    if result.ok and result.data:
        cache.put(source, ref.canonical, result.data)
    return result


async def _collect_one(ref: PackageRef, client: httpx.AsyncClient) -> Evidence:
    # WAVE 1 -- independent, concurrent. gather protects each from the other.
    osv_raw, npm_raw = await asyncio.gather(
        _cached(base.NAME_OSV, ref, lambda: osv.fetch(ref, client)),
        _cached(base.NAME_NPM, ref, lambda: npm.fetch(ref, client)),
        return_exceptions=True,
    )
    osv_result = base._survive(osv_raw)
    npm_result = base._survive(npm_raw)

    registry = npm.parse(npm_result.data, ref) if npm_result.ok else None

    # WAVE 2 -- depends on wave 1. Not inside a gather, so it needs the same
    # protection gather gives wave 1, spelled out. The first draft of this
    # module left it unguarded, and a raise in github.fetch_for escaped
    # _collect_one entirely (D.2).
    if npm_result.skipped:
        # npm was not ATTEMPTED, so the repository was never looked for.
        # Nothing failed; GitHub is simply not attempted either. Without this
        # branch, fetch_for would read registry=None as a failed lookup and
        # put a false line in degraded_sources.
        gh_result = CollectorResult(
            ok=False, skipped=True, error="not attempted (registry not consulted)"
        )
    else:
        try:
            # npm_result.ok travels with the parsed registry so fetch_for can
            # tell a failed lookup from an unreadable 200 (D.3).
            gh_result = await _cached(
                base.NAME_GITHUB, ref,
                lambda: github.fetch_for(registry, npm_result.ok, ref, client),
            )
        except Exception as exc:        # Exception only -- see base._survive
            gh_result = base._survive(exc)

    return _assemble(ref, osv_result, npm_result, gh_result, registry)


def _assemble(ref, osv_r, npm_r, gh_r, registry) -> Evidence:
    # Names paired with results AT THE POINT OF USE. The first draft zipped a
    # names tuple against a results list positionally; reorder one and a
    # GitHub 403 renders as "osv: 403 rate limited" (D.5).
    named = (
        (base.NAME_OSV, osv_r),
        (base.NAME_NPM, npm_r),
        (base.NAME_GITHUB, gh_r),
    )
    degraded = [f"{n}: {r.error}" for n, r in named if r.error and not r.skipped]

    return Evidence(
        package=ref,
        vulnerabilities=(
            osv.parse_vulns(osv_r.data, ref, osv_r.source) if osv_r.ok else []
        ),
        registry=registry,
        # None, never a defaulted RepositoryInfo(): None means "not collected",
        # and a default would be a measurement that never happened (A.2).
        repository=github.parse(gh_r.data, gh_r.source) if gh_r.ok else None,
        # Only sources that ANSWERED. `check` prints these as having answered.
        sources=[r.source for _, r in named if r.ok and r.source],
        partial=bool(degraded),          # satisfies the Evidence validator
        degraded_sources=degraded,
        unavailable=[f"{n}: {r.error}" for n, r in named if r.skipped],
    )


def _failed_evidence(ref: PackageRef, exc: BaseException) -> Evidence:
    """One ref's pipeline broke. Its Evidence says so; the others are intact.

    No sources, partial=True, the exception named -- which run.py routes
    through offline_policy exactly as it routes a total source failure.
    A non-Exception BaseException is re-raised for the same reason as _survive.
    """
    if not isinstance(exc, Exception):
        raise exc
    return Evidence(
        package=ref,
        sources=[],
        partial=True,
        degraded_sources=[f"pipeline: {type(exc).__name__}: {exc}"],
    )