"""GitHub repository collector.

    GET https://api.github.com/repos/{owner}/{repo}
    GET https://api.github.com/repos/{owner}/{repo}/contributors?per_page=1&anon=1

Runs after the npm collector, which supplies the repository. A token is
required; without one the collector is skipped rather than failed, since the
unauthenticated rate limit is too low to be useful.
"""
from __future__ import annotations

import asyncio
import os
import re

import httpx

from ..models import PackageRef, RegistryInfo, RepositoryInfo, SourceRef
from . import base
from .base import CollectorResult, _dig
from .npm import _parse_iso

API = "https://api.github.com"
TOKEN_ENV = "OPENSHIELD_GITHUB_TOKEN"

# With per_page=1, the page number in the `rel="last"` link is the
# contributor count.
_LAST_PAGE = re.compile(r'[?&]page=(\d+)[^>]*>;\s*rel="last"')


# -------------------------------- the gate ------------------------------------

async def fetch_for(
    registry: RegistryInfo | None,
    registry_ok: bool,
    ref: PackageRef,
    client: httpx.AsyncClient,
) -> CollectorResult:
    """Decide whether to fetch, then fetch.

      no token            -> skip
      registry unreadable -> failure, naming what broke
      no repository       -> skip
      a repository        -> fetch it
    """
    token = os.environ.get(TOKEN_ENV)
    if not token:
        return CollectorResult(ok=False, skipped=True, error="no token configured")

    if registry is None:
        reason = ("registry answered but could not be read" if registry_ok
                  else "registry lookup failed")
        return CollectorResult(ok=False, error=f"repository unknown ({reason})")

    if not registry.repository_owner or not registry.repository_name:
        # Includes non-GitHub hosts and monorepo subpaths.
        return CollectorResult(ok=False, skipped=True,
                               error="package declares no GitHub repository")

    try:
        return await _fetch(registry.repository_owner, registry.repository_name,
                            token, client)
    except Exception as exc:
        return CollectorResult(ok=False, error=f"{type(exc).__name__}: {exc}")


# ------------------------------- transport ------------------------------------

async def _fetch(owner: str, repo: str, token: str,
                 client: httpx.AsyncClient) -> CollectorResult:
    """Fetch the repository and contributor count concurrently.

    A failed contributor lookup leaves the count unknown rather than failing
    the collector.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    repo_raw, contrib_raw = await asyncio.gather(
        _get_repo(client, owner, repo, headers),
        _get_contributor_count(client, owner, repo, headers),
        return_exceptions=True,
    )
    repo_result = base._survive(repo_raw)
    contrib = base._survive(contrib_raw)

    if not repo_result.ok:
        return CollectorResult(ok=False, error=repo_result.error)

    data = dict(repo_result.data)
    if contrib.ok:
        # Underscore-prefixed so it cannot collide with a GitHub field.
        data["_contributor_count"] = _dig(contrib.data, "count")
        return CollectorResult(ok=True, data=data, source=_source())

    return CollectorResult(ok=True, data=data, source=_source(),
                           error=f"contributor count unavailable ({contrib.error})")


async def _get_repo(client, owner: str, repo: str, headers: dict) -> CollectorResult:
    try:
        response = await client.get(f"{API}/repos/{owner}/{repo}", headers=headers)
    except httpx.TimeoutException:
        return CollectorResult(ok=False, error="timeout after 8s")
    except httpx.RequestError as exc:
        return CollectorResult(ok=False, error=f"network error: {type(exc).__name__}")

    failure = _status_error(response)
    if failure is not None:
        return CollectorResult(ok=False, error=failure)

    try:
        payload = response.json()
    except ValueError:
        return CollectorResult(ok=False, error="non-JSON response from api.github.com")
    if not isinstance(payload, dict):
        return CollectorResult(ok=False, error="response was not a JSON object")
    return CollectorResult(ok=True, data=payload)


def _status_error(response: httpx.Response) -> str | None:
    """None for a usable response, otherwise a reason that distinguishes 404,
    rate limiting and other 403s."""
    code = response.status_code
    if code == 200:
        return None
    if code == 404:
        return "404 -- repository moved, renamed, private or deleted"
    if code in (403, 429):
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining == "0":
            return f"rate limited -- resets {_reset_hint(response)}"
        return f"{code} -- forbidden (token scope or repository access)"
    return f"{code} from api.github.com"


def _reset_hint(response: httpx.Response) -> str:
    """X-RateLimit-Reset as a UTC clock time, e.g. 'at 18:42Z'."""
    from datetime import datetime, timezone
    raw = response.headers.get("X-RateLimit-Reset")
    try:
        moment = datetime.fromtimestamp(int(raw), tz=timezone.utc)
    except (TypeError, ValueError):
        return "at an unknown time"
    return f"at {moment:%H:%M}Z"


async def _get_contributor_count(client, owner: str, repo: str,
                                 headers: dict) -> CollectorResult:
    """Count contributors via the Link header of a one-per-page listing.

    anon=1 includes contributors without GitHub accounts.
    """
    url = f"{API}/repos/{owner}/{repo}/contributors?per_page=1&anon=1"
    try:
        response = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return CollectorResult(ok=False, error="timeout after 8s")
    except httpx.RequestError as exc:
        return CollectorResult(ok=False, error=f"network error: {type(exc).__name__}")

    failure = _status_error(response)
    if failure is not None:
        return CollectorResult(ok=False, error=failure)

    return CollectorResult(ok=True, data={"count": contributor_count(response)})


def contributor_count(response: httpx.Response) -> int | None:
    """The Link header's last page; otherwise the body length; None if the body
    is not a list.

    Without a Link header there is only one page, so the fallback counts the
    body rather than assuming zero.
    """
    link = response.headers.get("Link") or response.headers.get("link")
    if link:
        match = _LAST_PAGE.search(link)
        if match:
            return int(match.group(1))

    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, list):
        return None
    return len(payload)


def _source() -> SourceRef:
    from datetime import datetime, timezone
    return SourceRef(name=base.NAME_GITHUB, fetched_at=datetime.now(timezone.utc))


# -------------------------------- parsing -------------------------------------

def parse(payload: dict, source: SourceRef | None) -> RepositoryInfo | None:
    """Repository JSON -> RepositoryInfo, or None if unreadable.

    The age is computed here rather than in fetch so it stays correct when the
    payload comes from the cache.
    """
    if not isinstance(payload, dict) or "archived" not in payload:
        return None

    archived = payload.get("archived")
    pushed = _parse_iso(payload.get("pushed_at"))
    stars = payload.get("stargazers_count")
    contributors = payload.get("_contributor_count")

    from datetime import datetime, timezone
    days = (datetime.now(timezone.utc) - pushed).days if pushed else None

    return RepositoryInfo(
        archived=archived if isinstance(archived, bool) else None,
        days_since_last_push=days,
        contributors=contributors if isinstance(contributors, int) else None,
        stars=stars if isinstance(stars, int) else None,
    )