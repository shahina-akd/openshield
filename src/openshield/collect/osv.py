"""The OSV collector. PackageRef in, Vulnerability list out.

Never raises past collect_osv(). That is Step 1.1's rule, adopted a milestone
early: it costs one try/except now and makes 1.1 a move rather than a rewrite.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import cvss

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


# GHSA says MODERATE. CVSS says MEDIUM. §9.1 says moderate. Both publisher
# words map onto our vocabulary; missing the CVSS spelling means every
# CVSS-derived medium finding silently lands on "unknown" and scores zero.
_WORDS = {
    "critical": "critical",
    "high": "high",
    "moderate": "moderate",
    "medium": "moderate",
    "low": "low",
}


def _word(value: object) -> Severity | None:
    """A publisher's severity word, or None if it is not one we recognise.

    An unrecognised word is not a severity -- SEVERE, IMPORTANT, or a private
    label falls through to the next tier and eventually to "unknown". No fuzzy
    matching: "unknown" is honest, a guess is not.
    """
    if not isinstance(value, str):
        return None
    return _WORDS.get(value.strip().casefold())

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

    for entry in _as_list(vuln.get("severity")):
        score = cvss.base_score(_dig(entry, "score"))
        if score is not None:
            return cvss.band(score)

    return "unknown"


def fixed_versions(vuln: dict, ref: PackageRef) -> list[str]:
    """Every 'fixed' event for THIS package, in record order, deduped.

    The ecosystem check is not tidiness: one advisory can carry affected[]
    entries for several ecosystems, and package names collide across them
    freely. Without it you can pull a PyPI fix version into an npm finding --
    and in M1 that moves the score, because §9.4 grants +5 only when every
    critical/high vulnerability has a fix.

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
        for rng in _as_list(affected.get("ranges")):
            for event in _as_list(_dig(rng, "events")):
                value = _dig(event, "fixed")
                if isinstance(value, str) and value and value not in out:
                    out.append(value)
    return out

def parse_vulns(payload: dict, ref: PackageRef, source: SourceRef) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for vuln in _as_list(payload.get("vulns")):
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

def query(ref: PackageRef, client: httpx.Client | None = None) -> RawResult:
    """One POST (or a few, if paginated). Returns the raw payload.

    Raw, not parsed: M1 Step 1.4 caches exactly this, because parsers change
    weekly during development and cached raw responses survive that.
    """
    body = {"version": ref.version,
            "package": {"name": ref.name, "ecosystem": ref.ecosystem}}
    owned = client is None
    client = client or httpx.Client(timeout=TIMEOUT, headers=HEADERS)
    vulns: list = []
    token: str | None = None
    try:
        for _ in range(MAX_PAGES):
            page = dict(body, page_token=token) if token else body
            response = client.post(OSV_QUERY_URL, json=page)
            if response.status_code != 200:
                return RawResult(False, error=f"{response.status_code} from api.osv.dev")
            try:
                payload = response.json()
            except ValueError:
                return RawResult(False, error="non-JSON response from api.osv.dev")
            if not isinstance(payload, dict):
                return RawResult(False, error="response was not a JSON object")
            vulns.extend(_as_list(payload.get("vulns")))
            token = payload.get("next_page_token")
            if not isinstance(token, str) or not token:
                return RawResult(True, {"vulns": vulns})
        return RawResult(True, {"vulns": vulns},
                         f"results truncated after {MAX_PAGES} pages")
    except httpx.TimeoutException:
        return RawResult(False, error="timeout after 8s")
    except httpx.RequestError as exc:
        return RawResult(False, error=f"network error: {type(exc).__name__}")
    finally:
        if owned:
            client.close()

def collect_osv(ref: PackageRef, client: httpx.Client | None = None) -> SourceResult:
    source = SourceRef(name=SOURCE_NAME, fetched_at=datetime.now(timezone.utc))
    try:
        raw = query(ref, client)
        if not raw.ok:
            return SourceResult(False, source=source, error=raw.error)
        return SourceResult(True, parse_vulns(raw.payload, ref, source),
                            source, raw.error)
    except Exception as exc:
        return SourceResult(False, source=source, error=f"{type(exc).__name__}: {exc}")