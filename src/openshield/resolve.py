"""Resolve a specifier to a PackageRef, or an Unresolvable explaining why not.

Only kinds in RESOLVABLE reach the network; any other kind, including ones
added later, is refused.
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

TIMEOUT = httpx.Timeout(8.0)
HEADERS = {"User-Agent": "openshield/0.1"}


def registry_url(name: str) -> str:
    """Registry URL for a package; the scope's '/' is encoded as %2F."""
    return f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}"


def normalize_version(v: str) -> str:
    """Strip a lowercase 'v' prefix so each package has one canonical identity.

    npm does not accept an uppercase 'V', so it is left alone.
    """
    return v[1:] if v.startswith("v") else v


def resolve(spec: str, client: httpx.Client | None = None) -> PackageRef | Unresolvable:
    """Resolve a specifier to the exact version npm would install."""
    kind = classify_specifier(spec)

    if kind not in RESOLVABLE:
        assert kind != "registry"
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
        return Unresolvable(specifier=spec, reason="network",
                            detail=f"registry unreachable: {type(exc).__name__}")

    if resp.status_code == 404:
        return Unresolvable(specifier=spec, reason="not_found",
                            detail=f"no package named {name}")
    if resp.status_code != 200:
        # A registry error, not a missing package.
        return Unresolvable(specifier=spec, reason="network",
                            detail=f"registry returned {resp.status_code}")

    try:
        doc = resp.json()
    except ValueError:
        # e.g. a captive portal or proxy returning HTML with status 200.
        return Unresolvable(specifier=spec, reason="network",
                            detail="registry returned non-JSON")

    # Use the registry's spelling so casing differences cannot create a
    # second identity.
    reg_name = doc.get("name") or name
    versions = doc.get("versions") or {}

    if version is None:
        # npm installs dist-tags.latest for a bare name, not the highest version.
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
        # The specifier's form was valid but the registry data was not.
        return Unresolvable(specifier=spec, reason="unknown",
                            detail=f"registry data rejected: {exc.errors()[0]['msg']}")


def resolve_all(
    specs: list[str], client: httpx.Client | None = None
) -> list[PackageRef | Unresolvable]:
    """Resolve several specifiers over one connection pool.

    No client is opened when nothing is resolvable.
    """
    if client is not None:
        return [resolve(s, client=client) for s in specs]
    if not any(classify_specifier(s) in RESOLVABLE for s in specs):
        return [resolve(s) for s in specs]
    with httpx.Client(timeout=TIMEOUT, headers=HEADERS) as owned:
        return [resolve(s, client=owned) for s in specs]