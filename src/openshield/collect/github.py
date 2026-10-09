"""The GitHub collector -- wave 2, and the only one with a dependency.

    GET https://api.github.com/repos/{owner}/{repo}
    GET https://api.github.com/repos/{owner}/{repo}/contributors?per_page=1&anon=1

It runs after npm because it needs `repository.url`, which only the registry
can supply (NOTES-M1 A.1). The BRANCH logic was written in Step 1.1 -- what the
absence of a repository means is assembly logic, not transport -- and this step
adds the two requests behind it.

AUTHENTICATION IS NOT OPTIONAL HERE (NOTES-M1 A.3). Without a token GitHub
allows 60 requests an hour, which M2's ambient interception exhausts in
minutes. So "no token" is a SKIP rather than a failure: it fires on every run
for an unconfigured user, and a warning that always fires is furniture -- it
would train the reader past the OSV failures that matter.
"""
from __future__ import annotations

import asyncio
import os
import re

import httpx

from ..models import PackageRef, RegistryInfo, RepositoryInfo, SourceRef
from . import base
from .base import CollectorResult, _dig
from .npm import _parse_iso            # same Z-suffix trap; one implementation

API = "https://api.github.com"
TOKEN_ENV = "OPENSHIELD_GITHUB_TOKEN"

# `rel="last"` carries the final page number. With per_page=1 that number IS
# the contributor count -- GitHub does not expose the count any other way.
_LAST_PAGE = re.compile(r'[?&]page=(\d+)[^>]*>;\s*rel="last"')


# -------------------------------- the gate ------------------------------------

async def fetch_for(
    registry: RegistryInfo | None,
    registry_ok: bool,
    ref: PackageRef,
    client: httpx.AsyncClient,
) -> CollectorResult:
    """Every reason not to fetch lives here, in one place.

    Four outcomes, and the difference between them is the whole of A.3 and D.3:

      no token            -> SKIP. Not degradation; reported quietly.
      registry unreadable -> degradation, and say WHICH thing broke.
      no repository       -> SKIP. Knowing there is none is a complete answer.
      a repository        -> fetch it.
    """
    token = os.environ.get(TOKEN_ENV)
    if not token:
        return CollectorResult(ok=False, skipped=True, error="no token configured")

    if registry is None:
        # Degradation either way -- the repository IS unknown -- but an
        # unreadable 200 is not a failed lookup, and claiming otherwise puts a
        # false line in degraded_sources, the one block §9.1 requires to be
        # trustworthy (D.3).
        reason = ("registry answered but could not be read" if registry_ok
                  else "registry lookup failed")
        return CollectorResult(ok=False, error=f"repository unknown ({reason})")

    if not registry.repository_owner or not registry.repository_name:
        # Includes GitLab, Bitbucket and monorepo subpaths, which npm.py
        # deliberately refuses to guess at. B.5: nothing to fetch is a
        # complete answer.
        return CollectorResult(ok=False, skipped=True,
                               error="package declares no GitHub repository")

    try:
        return await _fetch(registry.repository_owner, registry.repository_name,
                            token, client)
    except Exception as exc:
        # The never-raises rule. _collect_one guards wave 2 as a backstop, but
        # a raise there is reported as `github: KeyError: ...` rather than as a
        # sentence a person can act on.
        return CollectorResult(ok=False, error=f"{type(exc).__name__}: {exc}")


# ------------------------------- transport ------------------------------------

async def _fetch(owner: str, repo: str, token: str,
                 client: httpx.AsyncClient) -> CollectorResult:
    """The repository, and the contributor count, concurrently.

    The contributor count is a nice-to-have: its failure leaves `contributors`
    as None rather than failing the collector, the same relationship the
    downloads host has to the packument in npm.py.
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
        # Merged under a key GitHub itself never sends, so parse() cannot
        # confuse a computed value with a reported one.
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
    """None when the response is usable; a named reason otherwise.

    404 and 403 get DISTINCT messages (NOTES-M1 B.5). Both are failures, for
    different reasons, and in six months you will want to tell them apart at a
    glance rather than by re-reading this function.
    """
    code = response.status_code
    if code == 200:
        return None
    if code == 404:
        # Moved, renamed, made private, or deleted. We do NOT know which, and
        # we do not know anything about the repository -- so this is a failure,
        # unlike a 404 from the npm downloads host, which is a real answer.
        return "404 -- repository moved, renamed, private or deleted"
    if code in (403, 429):
        remaining = response.headers.get("X-RateLimit-Remaining")
        if remaining == "0":
            # Say WHEN it resets, not merely that it failed. A message you can
            # act on beats a message you can only read.
            return f"rate limited -- resets {_reset_hint(response)}"
        return f"{code} -- forbidden (token scope or repository access)"
    return f"{code} from api.github.com"


def _reset_hint(response: httpx.Response) -> str:
    """X-RateLimit-Reset is a Unix timestamp. Rendered as a UTC clock time,
    because 'resets at 18:42Z' is actionable and '1760000000' is not."""
    from datetime import datetime, timezone
    raw = response.headers.get("X-RateLimit-Reset")
    try:
        moment = datetime.fromtimestamp(int(raw), tz=timezone.utc)
    except (TypeError, ValueError):
        return "at an unknown time"
    return f"at {moment:%H:%M}Z"


async def _get_contributor_count(client, owner: str, repo: str,
                                 headers: dict) -> CollectorResult:
    """One contributor per page, then read the LAST page number.

    GitHub does not expose a contributor count, so the trick is to ask for
    pages of one and let the Link header do the counting. anon=1 includes
    contributors without GitHub accounts, which is what the number means to a
    reader.
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
    """The Link header's last page, or 1, or None.

    NO LINK HEADER MEANS ONE PAGE, SO THE FALLBACK IS 1 -- NEVER 0. Zero would
    read as "no contributors" and cost the package -8 under §9.4, for a
    repository that simply has a single contributor or for a parse that went
    slightly wrong. Same family as OSV's next_page_token: an answer that is
    complete only if you notice the continuation.

    None is reserved for "the body was not a list of contributors at all",
    which means we genuinely do not know.
    """
    link = response.headers.get("Link") or response.headers.get("link")
    if link:
        match = _LAST_PAGE.search(link)
        if match:
            return int(match.group(1))

    # No Link header: one page at most. Distinguish an empty list (a real zero,
    # which GitHub returns for a repository with no commits) from a non-list.
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
    """Raw repository JSON -> RepositoryInfo, or None if unreadable.

    Same None-versus-default rule as npm.parse (D.3): None means "could not
    read it". Unlike the registry, nothing downstream branches on this
    distinction yet -- but §9.4 does, because archived=None must not score the
    same as archived=False (A.2).

    THE CLOCK READ IS HERE, NOT IN fetch (B.2). parse runs on every request,
    cache hit or miss, so a cached pushed_at still yields a correct age.
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