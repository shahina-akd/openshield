"""Data models. Validation lives at the boundary, not in every caller."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


# Two vocabularies, deliberately different, deliberately not interchangeable.
# A vulnerability is "moderate" (GHSA's word). A package's risk band is
# "medium" (§9.5's word). Keeping them as separate Literals makes a mix-up a
# type error instead of an odd line of output.
Severity = Literal["critical", "high", "moderate", "low", "unknown"]
RiskLevel = Literal["critical", "high", "medium", "low"]

# What a human said. M2 adds a Decision RECORD (project, package, version,
# timestamp, score) -- this is just the verb.
DecisionAction = Literal["approve", "reject"]


def _require_aware(v: datetime) -> datetime:
    """§17: timezone-aware UTC, never naive. Enforced at the boundary because
    a naive timestamp written to the M1 cache and read back in M2 is a silent
    hour-offset bug in `history` with no visible cause."""
    if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
        raise ValueError("timestamps must be timezone-aware")
    return v


class SourceRef(BaseModel):
    # frozen: no lists, so it stays hashable, which lets Evidence.sources be
    # deduped without a key function.
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str                      # "osv", "npm-registry", "github"
    fetched_at: datetime
    from_cache: bool = False       # M1 Step 1.4 sets this on a cache hit

    @field_validator("fetched_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return _require_aware(v)


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str                        # "GHSA-…" / "CVE-…"
    aliases: list[str] = []
    summary: str | None = None
    # OSV publishes severity in at least three shapes. "unknown" is a
    # legitimate value, not a parse failure -- §9.4 scores it as zero. The
    # collector must never let an unrecognised shape raise here.
    severity: Severity
    fixed_versions: list[str] = [] # may be empty -- no fix published
    source: SourceRef


# ------------------------------ M1 evidence -----------------------------------
#
# Every field is `| None`. None means "not collected"; 0 and False mean
# something was MEASURED. §9.4 must never treat the two alike -- archived=None
# from a failed fetch must not score the same as archived=False.

class RegistryInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    maintainer_count: int | None = None
    license: str | None = None
    weekly_downloads: int | None = None
    days_since_last_publish: int | None = None     # §9.2: an integer, not a date
    repository_owner: str | None = None
    repository_name: str | None = None
    # The monorepo subpath, when the package declares one
    # ("packages/babel-core"). Parsed but UNWEIGHTED -- its presence means the
    # repository-level community signals belong to the parent project rather
    # than to this package (NOTES-1_3 §3). Recorded so the decision can be
    # revisited without re-reading every packument.
    repository_directory: str | None = None
    # THE MAINTAINER'S OWN MESSAGE, verbatim, or None.
    #
    # A STRING rather than a bool, because the message IS the signal: "use
    # String.prototype.padStart()" tells you what to do instead, which no
    # boolean can. Sanitised at parse (npm.py) because it is free text from the
    # registry that we print to a terminal.
    deprecated: str | None = None


class RepositoryInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    archived: bool | None = None
    # GitHub disabled the repository -- DMCA, terms-of-service, or abuse. Not
    # the maintainer's statement but the host's, and rarer and stronger than
    # archiving: somebody complained and GitHub agreed.
    disabled: bool | None = None
    days_since_last_push: int | None = None
    contributors: int | None = None
    stars: int | None = None


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: PackageRef
    vulnerabilities: list[Vulnerability] = []
    registry: RegistryInfo | None = None       # M1 Step 1.2
    repository: RepositoryInfo | None = None   # M1 Step 1.3
    sources: list[SourceRef] = []              # sources that SUCCEEDED
    partial: bool = False
    degraded_sources: list[str] = []           # ["github: 403 rate limited"]
    # Collectors NOT ATTEMPTED -- no token, no repository. Not degradation, so
    # it never sets `partial`; rendered as a quiet line (NOTES-M1 A.3).
    unavailable: list[str] = []

    @model_validator(mode="after")
    def _partial_names_its_failures(self) -> "Evidence":
        """§9.1's invariant, made structural: a degraded result must be
        distinguishable from a clean one. `partial` without a named source is
        a warning nobody can act on; a named failure without `partial` is a
        failure the renderer will not show. Neither is constructible."""
        if self.partial != bool(self.degraded_sources):
            raise ValueError(
                "partial and degraded_sources must agree: "
                f"partial={self.partial}, degraded_sources={self.degraded_sources}"
            )
        return self


class Contribution(BaseModel):
    """One line of the score's arithmetic, as it will be displayed.

    §4: every number shown traces to a visible evidence field. The LABEL names
    the field and its measured value ("published 871 days ago"), so the reader
    can check the reasoning rather than taking the total on trust.

    Built by score(), never recomputed by render.py. Two implementations of the
    same arithmetic can disagree, and a breakdown that contradicts its own
    total is worse than no breakdown -- so these rows ARE the calculation, and
    their sum is the score (tests/test_score.py pins that).
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    points: int


class Assessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence: Evidence
    # The arithmetic, in display order, summing to `score`. Empty is legal for
    # a hand-built Assessment in a test; score() always populates it.
    contributions: list[Contribution] = []
    # ge/le makes §9.3's clamp structural. A weight change that overflows the
    # scale becomes a loud test failure rather than "137/100 -- low".
    score: int = Field(ge=0, le=100)
    # NOT derivable from `score`: §9.5's override forces at least "high" for an
    # unfixed critical regardless of the number. Computed in score(), carried
    # here, never re-derived downstream.
    risk: RiskLevel
    scoring_version: str            # §9.2; stored per-decision by §10.3


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