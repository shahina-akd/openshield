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

 # npm's rules: lowercase, <=214 chars, optional @scope/, no leading dot
# or underscore, URL-safe characters only.
_NAME = re.compile(r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$")


class PackageRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    ecosystem: Literal["npm"] = "npm"
    name: str
    version: str

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if len(v) > 214 or not _NAME.match(v):
            raise ValueError(f"invalid npm package name: {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def _must_be_exact(cls, v: str) -> str:
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
    model_config = ConfigDict(extra="forbid")
    specifier: str
    reason: UnresolvableReason
    detail: str | None = None


class Invocation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["intercepted", "pass_through"]
    npm_args: list[str]         # forwarded to execute.run_npm verbatim
    subcommand: str | None
    specifiers: list[str]       # raw strings, unclassified
    bare_install: bool = False  # `npm install` with no specifiers
    lockfile_install: bool = False