"""Data models. Validation lives at the boundary, not in every caller."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

# Exact semver. This regex is the definition of "an exact version" for the
# whole project: parse.py uses it to classify, PackageRef uses it to refuse
# anything else. One definition, two enforcement points.
#
# The `v?` is deliberate and load-bearing: npm installs `axios@v1.7.2`, so
# parse.py must classify that form as resolvable rather than refusing a
# legitimate exact version. PackageRef refuses it separately, below.
#
# ALWAYS call this with .fullmatch(). '$' matches at end of string OR
# immediately before a trailing newline, so .match("1.7.2\n") succeeds.
SEMVER = re.compile(
    r"^v?\d+\.\d+\.\d+"          # core
    r"(?:-[0-9A-Za-z.-]+)?"      # prerelease
    r"(?:\+[0-9A-Za-z.-]+)?$"    # build metadata
)

# npm's rules: <=214 chars including scope, optional @scope/, no leading dot
# or underscore, URL-safe ASCII only.
#
# Uppercase is legal-but-legacy. npm refuses NEW uppercase names, but
# published ones still install -- `JSONStream` is the canonical example -- so
# refusing them here would raise on a real package.
#
# re.ASCII because \w is Unicode-aware by default: without it, `axiós`
# validates and reaches a cache key in a supply-chain tool.
#
# No anchors: used with .fullmatch().
_NAME = re.compile(
    r"(?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*",
    re.ASCII,
)


class PackageRef(BaseModel):
    # frozen: this is a cache key and half of an M2 decision primary key, so
    # it must be hashable and must not drift.
    # extra=forbid: without it, PackageRef(..., ecosytem="npm") silently
    # constructs with the default.
    model_config = ConfigDict(frozen=True, extra="forbid")

    ecosystem: Literal["npm"] = "npm"
    name: str
    version: str

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if len(v) > 214 or not _NAME.fullmatch(v):
            raise ValueError(f"invalid npm package name: {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def _must_be_exact(cls, v: str) -> str:
        if not SEMVER.fullmatch(v):
            raise ValueError(f"PackageRef.version must be exact, got {v!r}")
        # SEMVER permits a lowercase 'v' prefix so parse.py can classify
        # `axios@v1.7.2` as resolvable. The canonical identity may not carry
        # it: npm:axios@v1.7.2 and npm:axios@1.7.2 would be two cache keys and
        # two decision rows for one package, so an M2 approval would silently
        # fail to apply. resolve.normalize_version() strips it at the boundary;
        # arriving here with one means that step was skipped.
        if v.startswith("v"):
            raise ValueError(
                f"version must be canonical, not {v!r} -- strip the leading 'v'"
            )
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
    # from parse.py -- every non-resolvable SpecifierKind appears here, so
    # resolve() can pass a classification straight through as a reason
    "range", "tag", "alias", "local_path", "vcs", "tarball", "unknown",
    # from resolve.py -- lookup outcomes, with no parse-time equivalent
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