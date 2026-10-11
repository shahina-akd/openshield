"""Data models. Validation happens here rather than in every caller."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# The project's definition of an exact version, used by parse.py to classify
# and by PackageRef to validate.
#
# The optional `v` lets parse.py accept `axios@v1.7.2`; PackageRef rejects it
# separately.
#
# Always use .fullmatch(): `$` also matches before a trailing newline.
SEMVER = re.compile(
    r"^v?\d+\.\d+\.\d+"          # core
    r"(?:-[0-9A-Za-z.-]+)?"      # prerelease
    r"(?:\+[0-9A-Za-z.-]+)?$"    # build metadata
)

# npm package names: optional @scope/, no leading dot or underscore, ASCII
# only. Uppercase is allowed because older published packages use it.
# re.ASCII stops \w from matching Unicode letters. Used with .fullmatch().
_NAME = re.compile(
    r"(?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*",
    re.ASCII,
)


class PackageRef(BaseModel):
    # Frozen because it is used as a cache and decision key.
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
        # One package must have one identity; resolve.normalize_version()
        # strips the prefix before this point.
        if v.startswith("v"):
            raise ValueError(
                f"version must be canonical, not {v!r} -- strip the leading 'v'"
            )
        return v

    @property
    def canonical(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


# A vulnerability's severity is "moderate"; a package's risk band is "medium".
# Separate types keep the two from being mixed up.
Severity = Literal["critical", "high", "moderate", "low", "unknown"]
RiskLevel = Literal["critical", "high", "medium", "low"]

DecisionAction = Literal["approve", "reject"]


def _require_aware(v: datetime) -> datetime:
    """Reject naive datetimes."""
    if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
        raise ValueError("timestamps must be timezone-aware")
    return v


class SourceRef(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str                      # "osv", "npm-registry", "github"
    fetched_at: datetime
    from_cache: bool = False

    @field_validator("fetched_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return _require_aware(v)


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str                        # "GHSA-…" / "CVE-…"
    aliases: list[str] = []
    summary: str | None = None
    severity: Severity             # "unknown" when no rating is recognised
    fixed_versions: list[str] = [] # empty when no fix is published
    source: SourceRef


# ------------------------------ evidence --------------------------------------
#
# None means "not collected"; 0 and False are measurements. Scoring treats
# them differently.

class RegistryInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    maintainer_count: int | None = None
    license: str | None = None
    weekly_downloads: int | None = None
    days_since_last_publish: int | None = None
    repository_owner: str | None = None
    repository_name: str | None = None
    # Monorepo subpath, e.g. "packages/babel-core". Recorded but not scored.
    repository_directory: str | None = None
    # The maintainer's deprecation message, sanitised by npm.parse.
    deprecated: str | None = None


class RepositoryInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    archived: bool | None = None
    # Set by GitHub itself (DMCA, terms of service or abuse), not the maintainer.
    disabled: bool | None = None
    days_since_last_push: int | None = None
    contributors: int | None = None
    stars: int | None = None


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: PackageRef
    vulnerabilities: list[Vulnerability] = []
    registry: RegistryInfo | None = None
    repository: RepositoryInfo | None = None
    sources: list[SourceRef] = []              # sources that succeeded
    partial: bool = False
    degraded_sources: list[str] = []           # ["github: 403 rate limited"]
    # Collectors not attempted (no token, no repository). Does not set `partial`.
    unavailable: list[str] = []

    @model_validator(mode="after")
    def _partial_names_its_failures(self) -> "Evidence":
        """`partial` must be set exactly when a failed source is named."""
        if self.partial != bool(self.degraded_sources):
            raise ValueError(
                "partial and degraded_sources must agree: "
                f"partial={self.partial}, degraded_sources={self.degraded_sources}"
            )
        return self


class Contribution(BaseModel):
    """One row of the score calculation, as displayed.

    Built by score() and displayed as-is; the rows sum to the score.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    points: int


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence: Evidence
    # Display order; sums to `score`. score() always populates it.
    contributions: list[Contribution] = []
    score: int = Field(ge=0, le=100)
    # Not derivable from `score`: an unfixed critical forces at least "high".
    risk: RiskLevel
    scoring_version: str


SpecifierKind = Literal[
    "registry",     # resolvable: bare name or exact version
    "range",
    "tag",
    "alias",        # `foo@npm:bar`
    "local_path",
    "vcs",
    "tarball",
    "unknown",      # an unrecognised form
]

# Only these kinds are resolved; everything else is refused.
RESOLVABLE: frozenset[str] = frozenset({"registry"})


UnresolvableReason = Literal[
    # Every non-resolvable SpecifierKind, so resolve() can pass one through.
    "range", "tag", "alias", "local_path", "vcs", "tarball", "unknown",
    # Lookup outcomes from resolve.py.
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
    npm_args: list[str]         # passed to execute.run_npm unchanged
    subcommand: str | None
    specifiers: list[str]
    bare_install: bool = False  # `npm install` with no specifiers
    lockfile_install: bool = False