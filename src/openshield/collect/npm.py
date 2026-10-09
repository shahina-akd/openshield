"""npm registry collector -- STEP 1.1 SKELETON. Step 1.2 fills in both functions.

Present now so the two-wave fan-out can be built and tested before this
collector exists. It SKIPS rather than fails: the collector was not attempted,
so between Steps 1.1 and 1.2 `openshield check` shows a quiet line rather than
a permanent degraded banner (NOTES-M1 A.3).
"""
from __future__ import annotations

import httpx

from ..models import PackageRef, RegistryInfo
from .base import CollectorResult


async def fetch(ref: PackageRef, client: httpx.AsyncClient) -> CollectorResult:
    return CollectorResult(ok=False, skipped=True, error="not implemented until Step 1.2")


def parse(payload: dict, ref: PackageRef) -> RegistryInfo | None:
    """Step 1.2 obligation (NOTES-M1 D.3): return None for a payload you cannot
    read -- never a defaulted RegistryInfo(), whose repository_owner=None would
    tell github.fetch_for 'this package declares no repository'."""
    return None