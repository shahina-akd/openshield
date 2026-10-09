"""The OSV collector. PackageRef in, raw payload out; parse_vulns is separate.

M1 Step 1.1 converted the transport to async. parse_vulns and the extraction
helpers are UNCHANGED from M0 -- which is the payoff of keeping transport and
parsing split (NOTES-M1 B.1): the async conversion rewrote only fetch(), and
M1 Step 1.4's cache will wrap only fetch().
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

# GHSA says MODERATE. CVSS says MEDIUM. §9.1 says moderate. Both publisher
# words map onto our vocabulary; missing the CVSS spelling means every
# CVSS-derived medium finding silently lands on "unknown" and scores zero.
_WORDS: dict[str, Severity] = {
    "critical": "critical",
    "high": "high",
    "moderate": "moderate",
    "medium": "moderate",
    "low": "low",
}


def _word(value: object) -> Severity | None:
    """A publisher's severity word, or None if it is not one we recognise.

    No fuzzy matching: "unknown" is honest, a guess is not.
    """
    if not isinstance(value, str):
        return None
    return _WORDS.get(value.strip().casefold())


# -------------------------------- extraction -----------------------------------

def severity_of(vuln: dict) -> Severity:
    """OSV publishes severity in three places because three parties disagree.

    Order is not arbitrary: the curating publisher's word beats a number
    computed from a vector, because that word is what `npm audit` and GitHub
    already showed the user. Our "high" should mean what their "high" means.

    Measured 2026-09-10 (NOTES-0_4 §8.1): tier 1 fired on 100% of ~40 npm
    advisories sampled, so tiers 2-3 are insurance rather than working code.
    Tier 1 is still not redundant -- GHSA-8hc4-vh64-cxmj carries a word and an
    empty vector list, so tier 3 could never cover for it.
    """
    word = _word(_dig(vuln, "database_specific", "severity"))
    if word:
        return word

    for affected in _as_list(vuln.get("affected")):
        word = _word(_dig(affected, "database_specific", "severity"))
        if word:
            return word

    # CONTINUE past a vector we cannot parse -- do not stop at the first entry.
    # Records carry several vectors in no guaranteed order: [CVSS_V4, CVSS_V3]
    # still has a usable score in it, and base_score() declines v4.
    for entry in _as_list(vuln.get("severity")):
        score = cvss.base_score(_dig(entry, "score"))
        if score is not None:
            return cvss.band(score)  # type: ignore[return-value]

    return "unknown"


def fixed_versions(vuln: dict, ref: PackageRef) -> list[str]:
    """Every 'fixed' event for THIS package, in record order, deduped.

    The ecosystem check is not tidiness: one advisory can carry affected[]
    entries for several ecosystems, and package names collide across them.
    Comparing against ref.ecosystem rather than a literal "npm" keeps adding
    PyPI a type error rather than a filter that silently matches nothing.
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
    """PURE: dict in, models out. Never raises. Unchanged by the async move."""
    out: list[Vulnerability] = []
    for vuln in _as_list(_dig(payload, "vulns")):
        if not isinstance(vuln, dict):
            continue
        # A retracted advisory is a false positive, and false positives erode
        # exactly the attention §3.3.4 says the score exists to direct.
        if vuln.get("withdrawn"):
            continue
        identifier = vuln.get("id")
        if not isinstance(identifier, str) or not identifier:
            continue          # unciteable -- §4 needs a named evidence field
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
    """POST the query (following pagination). Returns the RAW payload.

    Raw, not parsed: Step 1.4 caches exactly this, because parsers change
    weekly during development and cached raw responses survive that.

    Never raises an Exception -- the never-raises rule, adopted in M0. A
    BaseException (Ctrl-C, the test suite's network guard) is left alone and
    propagates, which is what `except Exception` rather than a bare except is
    for.
    """
    try:
        return await _query(ref, client)
    except httpx.TimeoutException:
        # BEFORE RequestError: TimeoutException subclasses TransportError
        # subclasses RequestError. Reversed, this branch is dead code.
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
        # No 404 branch, unlike resolve(): a package with no advisories comes
        # back 200 with an empty body. Every non-200 is a failure to reach OSV.
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

    # Out of pages with a token outstanding: an answer, and an incomplete one.
    # ok=True, but named, so it surfaces as degradation rather than rounding up.
    return CollectorResult(ok=True, data={"vulns": vulns}, source=_source(),
                           error=f"results truncated after {MAX_PAGES} pages")


def _source() -> SourceRef:
    # The clock read belongs in a collector (§9.2 bans it in score(), not here).
    return SourceRef(name=base.NAME_OSV, fetched_at=datetime.now(timezone.utc))