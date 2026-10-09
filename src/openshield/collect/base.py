"""Shared collector machinery. Moved here from osv.py in M1 Step 1.1.

Everything in this module is used by all three collectors, which is why it was
promoted: the hardening in _as_list / _dig was written once, for OSV, and the
registry and GitHub responses are deeper and more variable than an OSV record
(NOTES-M1-inheritance.md B.4).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from ..models import SourceRef

NAME_OSV = "osv"
NAME_NPM = "npm-registry"
NAME_GITHUB = "github"

# Every network call carries an explicit timeout (§17). A hung tool is worse
# than a wrong one, because you cannot tell it is hung.
TIMEOUT = httpx.Timeout(8.0)
HEADERS = {"User-Agent": "openshield/0.1"}


@dataclass(frozen=True)
class CollectorResult:
    """What one collector contributes about one package.

    `ok` and emptiness are SEPARATE facts (NOTES-0_4 §1.1.3). ok=False means
    the source was not reached; ok=True with empty data means it was reached
    and said nothing is known. Conflating them is the §9.1 violation that makes
    the tool actively harmful.

    ok=True with a non-None error is legitimate: "I got an answer and it was
    incomplete" -- pagination truncation.

    skipped=True means NOT ATTEMPTED -- no token configured, no repository to
    look up. Not a failure, so it never sets `partial` (NOTES-M1 A.3).
    """
    ok: bool
    data: dict = field(default_factory=dict)
    source: SourceRef | None = None
    error: str | None = None
    skipped: bool = False


def _as_list(value: object) -> list:
    """A list, or an empty one. Never raises, never returns None."""
    return value if isinstance(value, list) else []


def _dig(obj: object, *keys: str) -> object | None:
    """obj['a']['b'] without assuming either level is a dict."""
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _survive(result: object) -> CollectorResult:
    """Normalise whatever gather(return_exceptions=True) handed back.

    A collector should never raise past its own body, so an Exception here
    means a bug -- surface it as a named failure rather than let it deny the
    other collectors their evidence.

    Anything that is a BaseException but NOT an Exception is re-raised:
    KeyboardInterrupt, SystemExit, and the test suite's RealNetworkAttempted
    guard. Converting those into "source failed" lines would turn a user's
    Ctrl-C into a degraded result, and would make the network guard invisible
    to every test that goes through collect() (NOTES-M1 D.1).
    """
    if isinstance(result, BaseException):
        if not isinstance(result, Exception):
            raise result
        return CollectorResult(ok=False, error=f"{type(result).__name__}: {result}")
    return result  # type: ignore[return-value]