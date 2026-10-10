"""The npm registry collector. Two hosts, one CollectorResult.

    GET https://registry.npmjs.org/{name}                       -- the packument
    GET https://api.npmjs.org/downloads/point/last-week/{name}  -- download counts

Transport and parsing stay split (NOTES-M1 B.1): fetch() returns the RAW
payloads, parse() turns them into a RegistryInfo. Step 1.4's cache stores
exactly what fetch() returns, and the async conversion in Step 1.1 touched only
the transport half -- both are consequences of that split.

THE CLOCK READ LIVES IN parse(), NOT fetch() (NOTES-M1 B.2). parse runs on
every request, cache hit or miss; fetch does not. An age computed at fetch time
and cached would be stale by the age of the cache entry, and the same package
would score differently depending on cache state -- exactly the reproducibility
§9.2 exists to protect.
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

# Long enough for any real deprecation notice (`request`'s is 78 characters),
# short enough that one field cannot flood the screen.
_MAX_MESSAGE = 200


# ------------------------------- transport ------------------------------------

def downloads_url(name: str) -> str:
    """Scoped names need encoding here too, but this host is NOT the registry.

    Verified by curl before writing this (see the guide's verify block): the
    downloads API accepts the scope unencoded. safe="@/" keeps both characters
    literal so `@babel/core` stays `@babel/core`.
    """
    return f"{DOWNLOADS_HOST}/{urllib.parse.quote(name, safe='@/')}"


async def fetch(ref: PackageRef, client: httpx.AsyncClient) -> CollectorResult:
    """Both requests, concurrently, into one raw payload.

    Two hosts means two round trips, and they are independent, so they overlap
    -- the same reasoning as wave 1 in collect/__init__.py, one level down.

    Never raises: the never-raises rule (NOTES-0_3 §2). A BaseException
    (Ctrl-C, the test suite's network guard) is deliberately left to propagate.
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

    # The packument is the collector's reason to exist. Without it there is no
    # registry evidence at all, so its failure is the collector's failure.
    if not packument.ok:
        return CollectorResult(ok=False, error=packument.error)

    data = {"packument": packument.data, "downloads": downloads.data}
    source = _source()

    if downloads.ok:
        return CollectorResult(ok=True, data=data, source=source)

    # An answer, and an incomplete one. ok=True with a named error is a
    # legitimate state (CollectorResult's docstring): the registry answered, we
    # just do not have the download count. _assemble surfaces it as degradation
    # while still listing npm-registry among the sources that answered.
    return CollectorResult(ok=True, data=data, source=source,
                           error=f"downloads unavailable ({downloads.error})")


async def _get(client: httpx.AsyncClient, url: str) -> CollectorResult:
    """One GET, with every failure as a return value.

    404 is handled by the CALLER, because the two hosts disagree about what it
    means (NOTES-M1 B.5): absent from the registry is a failure, absent from
    the downloads host is a real answer of zero.
    """
    try:
        response = await client.get(url)
    except httpx.TimeoutException:
        # Before RequestError: TimeoutException is a subclass of it, so
        # reversing these makes this branch dead code.
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
        # Valid JSON, wrong shape -- the bug resolve() shipped with in M0.
        # Parsing succeeding does not mean the thing parsed is a packument.
        return CollectorResult(ok=False, error="response was not a JSON object")
    return CollectorResult(ok=True, data=payload)


def _source() -> SourceRef:
    """Stamped at fetch time. §9.2 bans clock reads in score(), not here --
    this is the collector, which is exactly where they belong."""
    return SourceRef(name=base.NAME_NPM, fetched_at=datetime.now(timezone.utc))


# -------------------------------- parsing -------------------------------------

def parse(payload: dict, ref: PackageRef) -> RegistryInfo | None:
    """Raw payloads -> RegistryInfo, or None if the packument is unreadable.

    NONE MEANS "COULD NOT READ IT", NEVER "NOTHING IS THERE" (NOTES-M1 D.3).
    A defaulted RegistryInfo() would carry repository_owner=None, which
    github.fetch_for reads as "this package declares no repository" -- a SKIP.
    So an unreadable response would be reported as a known absence: the false
    claim D.3 removed, reintroduced one layer down and quieter.

    Never raises. Every lookup goes through _dig/_as_list, which tolerate any
    shape (NOTES-M1 B.4).
    """
    packument = _dig(payload, "packument")
    if not isinstance(packument, dict) or "versions" not in packument:
        return None          # unreadable -- NOT RegistryInfo()

    versions = _dig(packument, "versions")
    this_version = _dig(versions, ref.version) if isinstance(versions, dict) else None

    owner_repo = parse_github_repo(
        _dig(this_version, "repository") or _dig(packument, "repository")
    )

    # Per-version first, then the whole package. A package can deprecate one
    # release without deprecating itself -- and the version you are installing
    # is the one that matters (§7).
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
    """None when the field is absent or the wrong shape -- not 0.

    0 maintainers is a MEASUREMENT (and an alarming one); a missing field is
    an absence. §9.4 must never treat them alike.
    """
    return len(value) if isinstance(value, list) else None


def _license(this_version: object, packument: object) -> str | None:
    """Per-version first: a package can change licence between releases, and
    the version-level field is the one that applies to what you are installing.
    """
    for source in (this_version, packument):
        value = _dig(source, "license")
        if isinstance(value, str) and value:
            return value
        # The legacy object form: {"type": "MIT", "url": "..."}
        legacy = _dig(source, "license", "type")
        if isinstance(legacy, str) and legacy:
            return legacy
    return None


def _weekly_downloads(payload: object) -> int | None:
    """None if the downloads host did not answer; the number if it did.

    A 404 from that host was turned into ok=False upstream, so `downloads` is
    an empty dict here and this returns None. That is correct: we do not know.
    Distinguishing "no stats published" from "could not ask" would need a
    separate flag, and §9.4 treats both as "no positive signal" anyway.
    """
    value = _dig(payload, "downloads", "downloads")
    return value if isinstance(value, int) else None


def _days_since_publish(packument: object, ref: PackageRef) -> int | None:
    """THE CLOCK READ. In parse, not fetch -- see the module docstring."""
    times = _dig(packument, "time")
    published = _parse_iso(_dig(times, ref.version)) if isinstance(times, dict) else None
    if published is None:
        return None
    return (datetime.now(timezone.utc) - published).days


def _parse_iso(value: object) -> datetime | None:
    """ISO-8601 from npm or GitHub -> aware UTC datetime, or None. Never raises.

    The registry sends `2024-05-01T12:00:00.000Z`; GitHub sends
    `2024-05-01T12:00:00Z`. Both end in Z, which datetime.fromisoformat
    rejected before Python 3.11 -- so a parser tested only against
    datetime.isoformat() output (which produces `+00:00`) can be wrong about
    every real timestamp and still pass (NOTES-M1 D.4).

    Refuses naive results (§17): a timestamp with no offset is a guess about
    the timezone, not a timestamp.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _clean_message(value: object) -> str | None:
    """A maintainer-authored message, made safe to print. None if absent.

    THIS IS UNTRUSTED TEXT WE PUT ON A TERMINAL. The registry serves whatever
    the publisher typed, and a publisher is exactly the party this tool treats
    as potentially hostile (§7). Three things get stripped:

      ANSI escapes and control characters -- `\x1b[2J` clears the screen,
      `\r` overwrites the line just printed. A deprecation notice that could
      erase the findings above it would turn the renderer into the attack.
      §11.3 bans ANSI in our own output; text we PASS THROUGH is the same ban.

      Newlines -- collapsed to spaces, so one field cannot forge extra lines of
      output that look like the tool's own.

      Length -- capped. A megabyte of text in one field is a denial of service
      against the reader.

    npm also publishes `deprecated: true` with no message, which becomes a
    generic string: the fact is the signal, and None would lose it.
    """
    if value is True:
        return "deprecated by its maintainer (no message given)"
    if not isinstance(value, str):
        return None
    # Every disallowed character becomes a SPACE, not nothing. Deleting them
    # would join the words either side -- "foo\x00bar" -> "foobar" -- which
    # misrepresents what the publisher wrote. Substituting keeps the seam
    # visible, and the collapse below tidies the result.
    #
    # `isprintable()` is already False for \n, \r, \t and every other control
    # character, so no separate whitespace clause is needed; `isascii()` then
    # removes the non-ASCII lookalikes that could dress text up as our own
    # output (U+00A0, the box-drawing range, right-to-left overrides).
    safe = "".join(
        character if character.isprintable() and character.isascii() else " "
        for character in value
    )
    cleaned = " ".join(safe.split())     # collapses runs, strips the ends
    if not cleaned:
        return None
    if len(cleaned) > _MAX_MESSAGE:
        return cleaned[:_MAX_MESSAGE] + "..."
    return cleaned


# --------------------------- repository shorthand ------------------------------

_HOSTS = ("github.com",)


def parse_github_repo(repository: object) -> tuple[str, str] | None:
    """npm's `repository` field -> (owner, repo), or None.

    NONE RATHER THAN A GUESS. A wrong owner/repo pair means showing GitHub
    evidence about somebody else's project next to this package's name, which
    is worse than showing none.

    GitLab and Bitbucket also return None: real repositories this collector
    cannot read, which makes them a SKIP in github.fetch_for, not a failure.
    """
    url = repository if isinstance(repository, str) else _dig(repository, "url")
    if not isinstance(url, str) or not url:
        return None

    text = url.strip()

    # `github:owner/repo` -- npm's own shorthand.
    if text.startswith("github:"):
        return _owner_repo(text[len("github:"):])

    # Other hosts' shorthand is explicitly not ours.
    if text.startswith(("gitlab:", "bitbucket:", "gist:")):
        return None

    # scp-style ssh: git@github.com:owner/repo.git
    if "@" in text and ":" in text and "://" not in text:
        host, _, path = text.partition("@")[2].partition(":")
        return _owner_repo(path) if host in _HOSTS else None

    if "://" in text:
        # git+https://, git://, https://, ssh:// -- strip any scheme prefix.
        rest = text.split("://", 1)[1]
        host, _, path = rest.partition("/")
        host = host.rpartition("@")[2]          # drop any user:pass@
        return _owner_repo(path) if host in _HOSTS else None

    # Bare `owner/repo`, which npm reads as GitHub shorthand.
    return _owner_repo(text)


def _owner_repo(path: str) -> tuple[str, str] | None:
    """'axios/axios.git#main' -> ('axios', 'axios'). None for anything else."""
    cleaned = path.split("#", 1)[0].strip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[: -len(".git")]
    parts = [p for p in cleaned.split("/") if p]
    if len(parts) != 2:
        # Monorepo subpaths (owner/repo/tree/main/packages/x) land here. A
        # subpath names a DIRECTORY, not a repository, and guessing which of
        # the segments is the repo is how you end up fetching the wrong one.
        return None
    owner, repo = parts
    if not owner or not repo:
        return None
    return owner, repo