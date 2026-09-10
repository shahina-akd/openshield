"""The OSV collector. PackageRef in, Vulnerability list out.

Never raises past collect_osv(). That is Step 1.1's rule, adopted a milestone
early: it costs one try/except now and makes 1.1 a move rather than a rewrite.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from ..models import PackageRef, Severity, SourceRef, Vulnerability

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
TIMEOUT = httpx.Timeout(8.0)
HEADERS = {"User-Agent": "openshield/0.1"}
SOURCE_NAME = "osv"
MAX_PAGES = 5


@dataclass(frozen=True)
class RawResult:
    """Transport outcome. `payload` is the raw response -- M1 Step 1.4 caches
    exactly this, which is why parsing happens elsewhere."""
    ok: bool
    payload: dict = field(default_factory=dict)
    error: str | None = None


@dataclass(frozen=True)
class SourceResult:
    """What one collector contributes to one package's Evidence.

    `ok` and emptiness are SEPARATE facts. ok=False means we could not reach
    OSV; an empty `vulnerabilities` list with ok=True means OSV said there is
    nothing known. Conflating them is the §9.1 invariant violation that makes
    the tool actively harmful.

    ok=True with a non-None error is legitimate: it means "I got an answer and
    it was incomplete" (see MAX_PAGES).
    """
    ok: bool
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    source: SourceRef | None = None
    error: str | None = None