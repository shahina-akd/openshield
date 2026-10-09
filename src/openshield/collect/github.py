"""GitHub collector. The BRANCHES are Step 1.1; the HTTP half is Step 1.3.

The branches are written first because they are assembly logic -- what the
absence of a repository MEANS -- and they are what tests/test_collect.py tests.
Only the network call waits for Step 1.3.
"""
from __future__ import annotations

import os

import httpx

from ..models import PackageRef, RegistryInfo, RepositoryInfo, SourceRef
from .base import CollectorResult


async def fetch_for(
    registry: RegistryInfo | None,
    registry_ok: bool,
    ref: PackageRef,
    client: httpx.AsyncClient,
) -> CollectorResult:
    """Wave 2 (NOTES-M1 A.1). Takes the PARSED registry rather than a URL, so
    every reason not to fetch lives here, in one place."""

    if not os.environ.get("OPENSHIELD_GITHUB_TOKEN"):
        # NOT degradation. This fires on every run for an unconfigured user, and
        # a banner that always fires is furniture -- it would train the reader
        # past the OSV failures that matter (A.3). Reported quietly.
        return CollectorResult(ok=False, skipped=True, error="no token configured")

    if registry is None:
        # Degradation either way -- the repository IS unknown -- but say which
        # thing broke (D.3). An unreadable 200 is not a failed lookup, and
        # claiming otherwise puts a false line in degraded_sources.
        reason = ("registry answered but could not be read" if registry_ok
                  else "registry lookup failed")
        return CollectorResult(ok=False, error=f"repository unknown ({reason})")

    if not registry.repository_owner:
        # Knowing there is no repository is a complete answer (B.5). Skip.
        return CollectorResult(ok=False, skipped=True,
                               error="package declares no GitHub repository")

    # Step 1.3 replaces this with the two GETs, 404/403 handling, and the
    # contributor count from the Link header.
    return CollectorResult(ok=False, skipped=True, error="not implemented until Step 1.3")


def parse(payload: dict, source: SourceRef | None) -> RepositoryInfo | None:
    """Step 1.3. Same None-versus-default rule as npm.parse."""
    return None