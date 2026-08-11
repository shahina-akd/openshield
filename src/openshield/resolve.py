"""Specifier -> PackageRef, or a refusal that says why.

The only module that decides whether the network is touched at all. The gate
in resolve() reads RESOLVABLE, not a list of bad kinds: a SpecifierKind added
later and forgotten here is refused rather than fetched.
"""
from __future__ import annotations

import urllib.parse
from typing import cast

import httpx
from pydantic import ValidationError

from .models import (
    RESOLVABLE,
    PackageRef,
    Unresolvable,
    UnresolvableReason,
)
from .parse import classify_specifier, split_specifier

REGISTRY = "https://registry.npmjs.org"

# Every network call carries an explicit timeout. A hung tool is worse than a
# wrong one because you cannot tell it is hung -- and from M2 a hang here is a
# frozen `npm install` inside a Makefile with no visible cause.
TIMEOUT = httpx.Timeout(8.0)
HEADERS = {"User-Agent": "openshield/0.1"}


def registry_url(name: str) -> str:
    """Scoped names carry a '/' that must not become a path separator.

    safe='@' keeps the scope marker literal while '/' becomes %2F.
    """
    return f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}"


def normalize_version(v: str) -> str:
    """npm's semver grammar permits a lowercase 'v' prefix only, and the
    registry's `versions` keys never carry it. Strip it here so one package
    has exactly one canonical identity -- this string becomes an M1 cache key
    and half of an M2 decision primary key.

    Uppercase 'V' is not a version at all, so there is nothing to normalize;
    stripping it would invent acceptance npm does not have.
    """
    return v[1:] if v.startswith("v") else v


def resolve(spec: str, client: httpx.Client | None = None) -> PackageRef | Unresolvable:
    """A specifier the user typed -> what npm will actually install."""
    kind = classify_specifier(spec)

    # THE GATE. Nothing below this line runs for a non-resolvable form.
    if kind not in RESOLVABLE:
        assert kind != "registry"          # documents why the cast is sound
        return Unresolvable(specifier=spec, reason=cast(UnresolvableReason, kind))

    if client is not None:
        return _lookup(client, spec)
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS) as owned:
        return _lookup(owned, spec)


def _lookup(client: httpx.Client, spec: str) -> PackageRef | Unresolvable:
    name, version = split_specifier(spec)

    try:
        resp = client.get(registry_url(name))
    except httpx.TimeoutException:
        return Unresolvable(specifier=spec, reason="network",
                            detail="registry timed out after 8s")
    except httpx.RequestError as exc:
        # Parent of connect/read/proxy errors. Offline must be a return value:
        # §11.1's offline_policy governs a value, not a stack trace.
        return Unresolvable(specifier=spec, reason="network",
                            detail=f"registry unreachable: {type(exc).__name__}")

    if resp.status_code == 404:
        return Unresolvable(specifier=spec, reason="not_found",
                            detail=f"no package named {name}")
    if resp.status_code != 200:
        # A 5xx is the registry failing, not the package being absent. The
        # reason labels are explicitly not a closed set; 'network' is the
        # honest bucket, and the one offline_policy should govern.
        return Unresolvable(specifier=spec, reason="network",
                            detail=f"registry returned {resp.status_code}")

    try:
        doc = resp.json()
    except ValueError:
        # A captive portal or corporate proxy serving an HTML error page with
        # status 200 is real, and .json() raising here would escape the
        # pipeline at exactly the wrong moment.
        return Unresolvable(specifier=spec, reason="network",
                            detail="registry returned non-JSON")

    # The registry's own spelling is authoritative: casing drift at the call
    # site must not produce a second identity for one package.
    reg_name = doc.get("name") or name
    versions = doc.get("versions") or {}

    if version is None:
        # dist-tags.latest is what npm installs for a bare name. It is NOT
        # max(versions) -- prereleases deliberately live under next/beta.
        resolved = (doc.get("dist-tags") or {}).get("latest")
        if not resolved:
            return Unresolvable(specifier=spec, reason="not_found",
                                detail=f"{reg_name} has no 'latest' dist-tag")
    else:
        resolved = normalize_version(version)
        if resolved not in versions:
            return Unresolvable(specifier=spec, reason="not_found",
                                detail=f"{reg_name} has no version {resolved}")

    try:
        return PackageRef(name=reg_name, version=resolved)
    except ValidationError as exc:
        # classify_specifier validates the FORM, not the name -- 'registry'
        # does not imply constructible. The validator is the structural
        # guarantee that no range reaches downstream code; when it fires for a
        # shape we did not predict, refuse visibly rather than raise.
        return Unresolvable(specifier=spec, reason="unknown",
                            detail=f"registry data rejected: {exc.errors()[0]['msg']}")


def resolve_all(
    specs: list[str], client: httpx.Client | None = None
) -> list[PackageRef | Unresolvable]:
    """One connection pool per command line. `run.py` calls this.

    Opens no client when nothing is resolvable, so "unresolvable means no
    network" stays true of the batch path too.
    """
    if client is not None:
        return [resolve(s, client=client) for s in specs]
    if not any(classify_specifier(s) in RESOLVABLE for s in specs):
        return [resolve(s) for s in specs]
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS) as owned:
        return [resolve(s, client=owned) for s in specs]