"""Collect evidence for each package: collect(refs) -> list[Evidence].

Runs in two waves because GitHub needs the repository URL from npm:

    wave 1:   osv   npm-registry      concurrent, independent
                          |
    wave 2:            github         after npm has answered

Collectors are called through their modules (osv.fetch, npm.fetch, ...) rather
than imported by name, so tests can patch the module attributes.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from .. import cache, config
from ..models import Evidence, PackageRef, SourceRef
from . import base, github, npm, osv
from .base import CollectorResult


def collect(refs: list[PackageRef]) -> list[Evidence]:
    """The only asyncio.run in the codebase; everything above it stays sync."""
    if not refs:
        return []
    return asyncio.run(_collect_all(refs))


async def _collect_all(refs: list[PackageRef]) -> list[Evidence]:
    async with httpx.AsyncClient(timeout=base.TIMEOUT, headers=base.HEADERS) as client:
        # A failure in one package's pipeline must not lose the others' evidence.
        results = await asyncio.gather(
            *(_collect_one(r, client) for r in refs), return_exceptions=True
        )
    return [
        r if isinstance(r, Evidence) else _failed_evidence(ref, r)
        for ref, r in zip(refs, results)
    ]


async def _cached(source: str, ref: PackageRef, make_request) -> CollectorResult:
    """Return a cached response, or fetch and cache it on success.

    `make_request` is a zero-argument callable so the coroutine is only created
    on a cache miss. Only raw transport payloads are cached; parsing runs on
    every call so derived values such as ages stay current. Failures are never
    cached.
    """
    hit = cache.get(source, ref.canonical,
                    ttl_hours=config.get("cache_ttl_hours"))
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
    osv_raw, npm_raw = await asyncio.gather(
        _cached(base.NAME_OSV, ref, lambda: osv.fetch(ref, client)),
        _cached(base.NAME_NPM, ref, lambda: npm.fetch(ref, client)),
        return_exceptions=True,
    )
    osv_result = base._survive(osv_raw)
    npm_result = base._survive(npm_raw)

    registry = npm.parse(npm_result.data, ref) if npm_result.ok else None

    # Wave 2 is outside gather, so it needs its own exception guard.
    if npm_result.skipped:
        # npm was not attempted, so GitHub is not attempted either. Without this
        # branch fetch_for would report registry=None as a failed lookup.
        gh_result = CollectorResult(
            ok=False, skipped=True, error="not attempted (registry not consulted)"
        )
    else:
        try:
            # npm_result.ok lets fetch_for tell a failed lookup from an
            # unreadable response.
            gh_result = await _cached(
                base.NAME_GITHUB, ref,
                lambda: github.fetch_for(registry, npm_result.ok, ref, client),
            )
        except Exception as exc:
            gh_result = base._survive(exc)

    return _assemble(ref, osv_result, npm_result, gh_result, registry)


def _assemble(ref, osv_r, npm_r, gh_r, registry) -> Evidence:
    # Names are paired with results here so reordering cannot mislabel an error.
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
        # None means "not collected"; a default RepositoryInfo() would imply a
        # measurement.
        repository=github.parse(gh_r.data, gh_r.source) if gh_r.ok else None,
        sources=[r.source for _, r in named if r.ok and r.source],
        partial=bool(degraded),
        degraded_sources=degraded,
        unavailable=[f"{n}: {r.error}" for n, r in named if r.skipped],
    )


def _failed_evidence(ref: PackageRef, exc: BaseException) -> Evidence:
    """Evidence for a package whose pipeline raised.

    run.py treats it like a total source failure. Non-Exception BaseExceptions
    are re-raised, as in base._survive.
    """
    if not isinstance(exc, Exception):
        raise exc
    return Evidence(
        package=ref,
        sources=[],
        partial=True,
        degraded_sources=[f"pipeline: {type(exc).__name__}: {exc}"],
    )