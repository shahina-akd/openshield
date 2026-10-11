"""npm registry collector.

    GET https://registry.npmjs.org/{name}                       -- the packument
    GET https://api.npmjs.org/downloads/point/last-week/{name}  -- download counts

fetch() returns raw payloads (which is what the cache stores); parse() turns
them into a RegistryInfo. Ages are computed in parse() so they stay correct
for cached payloads.
"""
from __future__ import annotations

import asyncio
import urllib.parse
from datetime import datetime, timezone

import httpx

from ..models import PackageRef, RegistryInfo, SourceRef
from ..resolve import registry_url
from . import base
from .base import CollectorResult, _as_list, _dig

DOWNLOADS_HOST = "https://api.npmjs.org/downloads/point/last-week"

# Long enough for real deprecation notices, short enough not to flood the screen.
_MAX_MESSAGE = 200


# ------------------------------- transport ------------------------------------

def downloads_url(name: str) -> str:
    """Unlike the registry, the downloads API takes scoped names unencoded."""
    return f"{DOWNLOADS_HOST}/{urllib.parse.quote(name, safe='@/')}"


async def fetch(ref: PackageRef, client: httpx.AsyncClient) -> CollectorResult:
    """Fetch the packument and download count concurrently.

    Never raises an Exception; BaseExceptions propagate.
    """
    try:
        packument_raw, downloads_raw = await asyncio.gather(
            _get(client, registry_url(ref.name)),
            _get(client, downloads_url(ref.name)),
            return_exceptions=True,
        )
        packument = base._survive(packument_raw)
        downloads = base._survive(downloads_raw)
    except Exception as exc:
        return CollectorResult(ok=False, error=f"{type(exc).__name__}: {exc}")

    # Without the packument there is no registry evidence at all.
    if not packument.ok:
        return CollectorResult(ok=False, error=packument.error)

    data = {"packument": packument.data, "downloads": downloads.data}
    source = _source()

    if downloads.ok:
        return CollectorResult(ok=True, data=data, source=source)

    # The registry answered but the download count is missing: an incomplete
    # answer rather than a failure.
    return CollectorResult(ok=True, data=data, source=source,
                           error=f"downloads unavailable ({downloads.error})")


async def _get(client: httpx.AsyncClient, url: str) -> CollectorResult:
    """One GET, with every failure returned rather than raised."""
    try:
        response = await client.get(url)
    except httpx.TimeoutException:
        # Must precede RequestError, which is its superclass.
        return CollectorResult(ok=False, error="timeout after 8s")
    except httpx.RequestError as exc:
        return CollectorResult(ok=False, error=f"network error: {type(exc).__name__}")

    if response.status_code == 404:
        return CollectorResult(ok=False, error="404 not found")
    if response.status_code != 200:
        return CollectorResult(ok=False, error=f"{response.status_code} from {response.url.host}")

    try:
        payload = response.json()
    except ValueError:
        return CollectorResult(ok=False, error=f"non-JSON response from {response.url.host}")
    if not isinstance(payload, dict):
        return CollectorResult(ok=False, error="response was not a JSON object")
    return CollectorResult(ok=True, data=payload)


def _source() -> SourceRef:
    return SourceRef(name=base.NAME_NPM, fetched_at=datetime.now(timezone.utc))


# -------------------------------- parsing -------------------------------------

def parse(payload: dict, ref: PackageRef) -> RegistryInfo | None:
    """Raw payloads -> RegistryInfo, or None if the packument is unreadable.

    None means "could not read", not "nothing there": a default RegistryInfo()
    would look like a package that declares no repository. Never raises.
    """
    packument = _dig(payload, "packument")
    if not isinstance(packument, dict) or "versions" not in packument:
        return None

    versions = _dig(packument, "versions")
    this_version = _dig(versions, ref.version) if isinstance(versions, dict) else None

    owner_repo = parse_github_repo(
        _dig(this_version, "repository") or _dig(packument, "repository")
    )

    # The version-level notice wins: a maintainer can deprecate one release
    # without deprecating the package.
    deprecated = _clean_message(_dig(this_version, "deprecated"))
    if deprecated is None:
        deprecated = _clean_message(_dig(packument, "deprecated"))

    directory = _dig(this_version, "repository", "directory")
    if not isinstance(directory, str) or not directory:
        directory = _dig(packument, "repository", "directory")

    return RegistryInfo(
        maintainer_count=_count(_dig(packument, "maintainers")),
        license=_license(this_version, packument),
        weekly_downloads=_weekly_downloads(payload),
        days_since_last_publish=_days_since_publish(packument, ref),
        repository_owner=owner_repo[0] if owner_repo else None,
        repository_name=owner_repo[1] if owner_repo else None,
        repository_directory=directory if isinstance(directory, str) and directory else None,
        deprecated=deprecated,
    )


def _count(value: object) -> int | None:
    """List length, or None (not 0) when absent or malformed."""
    return len(value) if isinstance(value, list) else None


def _license(this_version: object, packument: object) -> str | None:
    """Version-level licence first, since packages can relicense between releases."""
    for source in (this_version, packument):
        value = _dig(source, "license")
        if isinstance(value, str) and value:
            return value
        # Legacy form: {"type": "MIT", "url": "..."}
        legacy = _dig(source, "license", "type")
        if isinstance(legacy, str) and legacy:
            return legacy
    return None


def _weekly_downloads(payload: object) -> int | None:
    value = _dig(payload, "downloads", "downloads")
    return value if isinstance(value, int) else None


def _days_since_publish(packument: object, ref: PackageRef) -> int | None:
    times = _dig(packument, "time")
    published = _parse_iso(_dig(times, ref.version)) if isinstance(times, dict) else None
    if published is None:
        return None
    return (datetime.now(timezone.utc) - published).days


def _parse_iso(value: object) -> datetime | None:
    """ISO-8601 timestamp -> aware datetime, or None. Never raises.

    Accepts the trailing `Z` used by npm and GitHub, which fromisoformat
    rejects before Python 3.11. Naive timestamps are refused.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _clean_message(value: object) -> str | None:
    """Make a publisher-supplied message safe to print, or return None.

    The text is untrusted. Control characters, escape sequences, newlines and
    non-ASCII characters are replaced with spaces so the message cannot alter
    the terminal or forge lines of output, and long messages are truncated.

    `deprecated: true` with no text becomes a generic message.
    """
    if value is True:
        return "deprecated by its maintainer (no message given)"
    if not isinstance(value, str):
        return None
    # Replace rather than delete, so adjacent words are not joined.
    safe = "".join(
        character if character.isprintable() and character.isascii() else " "
        for character in value
    )
    cleaned = " ".join(safe.split())
    if not cleaned:
        return None
    if len(cleaned) > _MAX_MESSAGE:
        return cleaned[:_MAX_MESSAGE] + "..."
    return cleaned


# --------------------------- repository shorthand ------------------------------

_HOSTS = ("github.com",)


def parse_github_repo(repository: object) -> tuple[str, str] | None:
    """npm's `repository` field -> (owner, repo), or None.

    Returns None rather than guessing, since a wrong pair would attribute
    another project's data to this package. Non-GitHub hosts also return None.
    """
    url = repository if isinstance(repository, str) else _dig(repository, "url")
    if not isinstance(url, str) or not url:
        return None

    text = url.strip()

    if text.startswith("github:"):
        return _owner_repo(text[len("github:"):])

    if text.startswith(("gitlab:", "bitbucket:", "gist:")):
        return None

    # scp-style ssh: git@github.com:owner/repo.git
    if "@" in text and ":" in text and "://" not in text:
        host, _, path = text.partition("@")[2].partition(":")
        return _owner_repo(path) if host in _HOSTS else None

    if "://" in text:
        rest = text.split("://", 1)[1]
        host, _, path = rest.partition("/")
        host = host.rpartition("@")[2]          # drop any user:pass@
        return _owner_repo(path) if host in _HOSTS else None

    # Bare `owner/repo` is GitHub shorthand in npm.
    return _owner_repo(text)


def _owner_repo(path: str) -> tuple[str, str] | None:
    """'axios/axios.git#main' -> ('axios', 'axios'). None for anything else,
    including monorepo subpaths."""
    cleaned = path.split("#", 1)[0].strip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[: -len(".git")]
    parts = [p for p in cleaned.split("/") if p]
    if len(parts) != 2:
        return None
    owner, repo = parts
    if not owner or not repo:
        return None
    return owner, repo