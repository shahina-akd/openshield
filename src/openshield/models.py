"""Data models. Validation lives at the boundary, not in every caller."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

# Exact semver. This regex is the definition of "an exact version" for the
# whole project: parse.py uses it to classify, PackageRef uses it to refuse
# anything else. One definition, two enforcement points.
SEMVER = re.compile(
    r"^v?\d+\.\d+\.\d+"          # core
    r"(?:-[0-9A-Za-z.-]+)?"      # prerelease
    r"(?:\+[0-9A-Za-z.-]+)?$"    # build metadata
)


class PackageRef(BaseModel):
    """An exact thing npm will install. Frozen: it is a cache key and part of
    a decision primary key, so it must be hashable and must not drift."""

    model_config = ConfigDict(frozen=True)

    ecosystem: Literal["npm"] = "npm"
    name: str
    version: str

    @field_validator("version")
    @classmethod
    def _must_be_exact(cls, v: str) -> str:
        # SPEC 7 / CONTEXT 4.1: never a range, never a dist-tag. A
        # non-negotiable that depends on callers remembering it isn't one.
        if not SEMVER.match(v):
            raise ValueError(f"PackageRef.version must be exact, got {v!r}")
        return v

    @property
    def canonical(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


SpecifierKind = Literal[
    "registry",     # RESOLVABLE: bare name, or exact version
    "range",        # unresolvable
    "tag",          # unresolvable
    "alias",        # unresolvable -- `foo@npm:bar`
    "local_path",   # unresolvable
    "vcs",          # unresolvable
    "tarball",      # unresolvable
    "unknown",      # unresolvable -- a form we did not anticipate
]

# The load-bearing line in the whole module. Everything not in here is
# refused; only the membership of this set is a security property, the other
# labels are reading aids.
RESOLVABLE: frozenset[str] = frozenset({"registry"})


UnresolvableReason = Literal[
    # from parse.py
    "range", "tag", "alias", "local_path", "vcs", "tarball", "unknown",
    # from resolve.py -- no parse-time equivalent
    "not_found", "network",
]


class Unresolvable(BaseModel):
    specifier: str
    reason: UnresolvableReason
    detail: str | None = None


class Invocation(BaseModel):
    kind: Literal["intercepted", "pass_through"]
    npm_args: list[str]         # forwarded to execute.run_npm verbatim
    subcommand: str | None
    specifiers: list[str]       # raw strings, unclassified
    bare_install: bool = False  # `npm install` with no specifiers