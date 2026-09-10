"""Fan-out and degradation. M0 has one source; M1 Step 1.1 makes this async."""
from __future__ import annotations

import httpx

from ..models import Evidence, PackageRef
from .osv import HEADERS, TIMEOUT, SourceResult, collect_osv


def collect(refs: list[PackageRef]) -> list[Evidence]:
    if not refs:
        return []            # no refs, no client -- same discipline as resolve_all
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS) as client:
        return [_evidence(ref, collect_osv(ref, client)) for ref in refs]


def _evidence(ref: PackageRef, result: SourceResult) -> Evidence:
    degraded = [] if result.error is None else [f"{result.source.name}: {result.error}"]
    return Evidence(
        package=ref,
        vulnerabilities=result.vulnerabilities,
        sources=[result.source] if result.ok else [],   # successes only
        partial=bool(degraded),
        degraded_sources=degraded,
    )
