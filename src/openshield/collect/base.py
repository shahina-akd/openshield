"""Helpers shared by all collectors."""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from ..models import SourceRef

NAME_OSV = "osv"
NAME_NPM = "npm-registry"
NAME_GITHUB = "github"

# Every network call has an explicit timeout; a hung tool is worse than a
# failed one.
TIMEOUT = httpx.Timeout(8.0)
HEADERS = {"User-Agent": "openshield/0.1"}


@dataclass(frozen=True)
class CollectorResult:
    """What one collector contributes about one package.

    ok=False means the source was not reached; ok=True with empty data means
    it was reached and knows nothing. ok=True with an error means the answer
    is incomplete (e.g. truncated pagination). skipped=True means the
    collector was not attempted and never marks the result as partial.
    """
    ok: bool
    data: dict = field(default_factory=dict)
    source: SourceRef | None = None
    error: str | None = None
    skipped: bool = False


def _as_list(value: object) -> list:
    """The value if it is a list, otherwise []."""
    return value if isinstance(value, list) else []


def _dig(obj: object, *keys: str) -> object | None:
    """obj['a']['b'] without assuming either level is a dict."""
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _survive(result: object) -> CollectorResult:
    """Normalise a gather(return_exceptions=True) result.

    An Exception becomes a named failure. Other BaseExceptions (Ctrl-C,
    SystemExit, the test network guard) are re-raised.
    """
    if isinstance(result, BaseException):
        if not isinstance(result, Exception):
            raise result
        return CollectorResult(ok=False, error=f"{type(result).__name__}: {result}")
    return result  # type: ignore[return-value]