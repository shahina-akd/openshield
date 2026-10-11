"""OSV vulnerability collector.

fetch() returns the raw payload; parse_vulns() turns it into Vulnerability
models.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from ..models import PackageRef, Severity, SourceRef, Vulnerability
from . import base, cvss
from .base import CollectorResult, _as_list, _dig

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_PAGES = 5


# ------------------------------ severity words ---------------------------------

# GHSA uses "moderate" and CVSS uses "medium"; both map to "moderate".
_WORDS: dict[str, Severity] = {
    "critical": "critical",
    "high": "high",
    "moderate": "moderate",
    "medium": "moderate",
    "low": "low",
}


def _word(value: object) -> Severity | None:
    """A recognised severity word, or None. No fuzzy matching."""
    if not isinstance(value, str):
        return None
    return _WORDS.get(value.strip().casefold())


# -------------------------------- extraction -----------------------------------

def severity_of(vuln: dict) -> Severity:
    """Determine severity from the first source that provides one.

    The publisher's own word is preferred over a computed CVSS score, so the
    rating matches what `npm audit` and GitHub show.
    """
    word = _word(_dig(vuln, "database_specific", "severity"))
    if word:
        return word

    for affected in _as_list(vuln.get("affected")):
        word = _word(_dig(affected, "database_specific", "severity"))
        if word:
            return word

    # Vectors appear in no fixed order, so skip unparseable ones (e.g. v4)
    # rather than stopping at the first.
    for entry in _as_list(vuln.get("severity")):
        score = cvss.base_score(_dig(entry, "score"))
        if score is not None:
            return cvss.band(score)  # type: ignore[return-value]

    return "unknown"


def fixed_versions(vuln: dict, ref: PackageRef) -> list[str]:
    """Every 'fixed' version for this package, in record order, deduplicated.

    Filtered by ecosystem as well as name, since one advisory can cover
    several ecosystems with colliding package names.
    """
    out: list[str] = []
    for affected in _as_list(vuln.get("affected")):
        pkg = _dig(affected, "package")
        if not isinstance(pkg, dict):
            continue
        if pkg.get("ecosystem") != ref.ecosystem or pkg.get("name") != ref.name:
            continue
        for rng in _as_list(_dig(affected, "ranges")):
            for event in _as_list(_dig(rng, "events")):
                value = _dig(event, "fixed")
                if isinstance(value, str) and value and value not in out:
                    out.append(value)
    return out


def parse_vulns(payload: dict, ref: PackageRef, source: SourceRef) -> list[Vulnerability]:
    """Raw payload -> Vulnerability models. Pure; never raises."""
    out: list[Vulnerability] = []
    for vuln in _as_list(_dig(payload, "vulns")):
        if not isinstance(vuln, dict):
            continue
        if vuln.get("withdrawn"):
            continue
        identifier = vuln.get("id")
        if not isinstance(identifier, str) or not identifier:
            continue
        summary = vuln.get("summary")
        out.append(Vulnerability(
            id=identifier,
            aliases=[a for a in _as_list(vuln.get("aliases")) if isinstance(a, str)],
            summary=summary if isinstance(summary, str) else None,
            severity=severity_of(vuln),
            fixed_versions=fixed_versions(vuln, ref),
            source=source,
        ))
    return out


# -------------------------------- transport ------------------------------------

async def fetch(ref: PackageRef, client: httpx.AsyncClient) -> CollectorResult:
    """Query OSV, following pagination, and return the raw payload.

    Never raises an Exception; BaseExceptions propagate.
    """
    try:
        return await _query(ref, client)
    except httpx.TimeoutException:
        # Must precede RequestError, which is its superclass.
        return CollectorResult(ok=False, error="timeout after 8s")
    except httpx.RequestError as exc:
        return CollectorResult(ok=False, error=f"network error: {type(exc).__name__}")
    except Exception as exc:
        return CollectorResult(ok=False, error=f"{type(exc).__name__}: {exc}")


async def _query(ref: PackageRef, client: httpx.AsyncClient) -> CollectorResult:
    body = {"version": ref.version,
            "package": {"name": ref.name, "ecosystem": ref.ecosystem}}
    vulns: list = []
    token: str | None = None

    for _ in range(MAX_PAGES):
        page = dict(body, page_token=token) if token else body
        response = await client.post(OSV_QUERY_URL, json=page)
        # OSV returns 200 with an empty body for a package with no advisories,
        # so any other status is a failure.
        if response.status_code != 200:
            return CollectorResult(ok=False, error=f"{response.status_code} from api.osv.dev")
        try:
            payload = response.json()
        except ValueError:
            return CollectorResult(ok=False, error="non-JSON response from api.osv.dev")
        if not isinstance(payload, dict):
            return CollectorResult(ok=False, error="response was not a JSON object")
        vulns.extend(_as_list(payload.get("vulns")))
        next_token = payload.get("next_page_token")
        if not isinstance(next_token, str) or not next_token:
            return CollectorResult(ok=True, data={"vulns": vulns}, source=_source())
        token = next_token

    # Page limit reached with more results pending: report as incomplete.
    return CollectorResult(ok=True, data={"vulns": vulns}, source=_source(),
                           error=f"results truncated after {MAX_PAGES} pages")


def _source() -> SourceRef:
    return SourceRef(name=base.NAME_OSV, fetched_at=datetime.now(timezone.utc))