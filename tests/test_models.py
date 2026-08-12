"""models.py -- identity validation and the label vocabularies.

Nothing here imports parse.py. If this file goes red, the identity contract
broke, not the parser.
"""
from datetime import datetime, timezone
from typing import get_args

import pytest
from pydantic import ValidationError

from openshield.models import (
    RESOLVABLE,
    SEMVER,
    Assessment,
    Evidence,
    Invocation,
    PackageRef,
    RiskLevel,
    Severity,
    SourceRef,
    SpecifierKind,
    Unresolvable,
    UnresolvableReason,
    Vulnerability,
)

# Shared fixtures for the evidence models. Deliberately module-level constants
# rather than pytest fixtures: they are immutable inputs, not per-test state,
# and half of them are needed inside @parametrize decorators, which run at
# collection time and cannot see fixtures.
#
# Constructed with keyword arguments -- Evidence gains `registry` and
# `repository` in M1 Step 1.2-1.3, and positional construction is the only
# thing that would make adding them a breaking change.
TS = datetime(2026, 1, 1, tzinfo=timezone.utc)
SOURCE = SourceRef(name="osv", fetched_at=TS)
REF = PackageRef(name="axios", version="1.7.2")
EV = Evidence(package=REF)


# ------------------------------- version: exactness -----------------------------

@pytest.mark.parametrize("version", ["^1.0.0", "latest", "1.2", "", "npm:react"])
def test_refuses_inexact_versions(version):
    with pytest.raises(ValueError):
        PackageRef(name="axios", version=version)


@pytest.mark.parametrize("version", [
    "1.7.2", "0.0.1", "10.20.30",
    "14.2.0-canary.3",          # prerelease is still exact
    "1.0.0+build.5",            # build metadata
    "1.0.0-alpha.1+build.5",
])
def test_accepts_exact_versions(version):
    assert PackageRef(name="axios", version=version).version == version


def test_refuses_non_canonical_versions():
    """SEMVER permits a lowercase 'v' so parse.py can classify `axios@v1.7.2`
    as resolvable -- npm accepts that form. The identity may not carry it:
    npm:axios@v1.7.2 and npm:axios@1.7.2 would be two cache keys and two
    decision rows for one package, so an M2 approval would silently fail to
    apply. resolve.normalize_version() strips it; arriving here with one means
    that step was skipped, and the message must say so."""
    with pytest.raises(ValidationError, match="canonical"):
        PackageRef(name="axios", version="v1.7.2")


def test_uppercase_v_is_not_a_version_at_all():
    """node-semver accepts a lowercase prefix only, so V1.7.2 is not a
    near-miss to normalize -- it fails the exactness check outright, and
    normalize_version() must not 'helpfully' strip it."""
    with pytest.raises(ValidationError, match="must be exact"):
        PackageRef(name="axios", version="V1.7.2")


@pytest.mark.parametrize("version", [
    "1.7.2\n", "1.7.2\r\n", " 1.7.2", "1.7.2 ", "1.7.2\t",
])
def test_whitespace_never_reads_as_an_exact_version(version):
    """'$' matches at end of string OR immediately before a trailing newline,
    so SEMVER.match('1.7.2\\n') succeeds. A version arriving from $(cat VERSION)
    or a changelog paste would otherwise become a distinct cache key for a
    package that already has one."""
    with pytest.raises(ValueError):
        PackageRef(name="axios", version=version)


def test_semver_is_only_ever_used_with_fullmatch():
    """Asserts the trap itself, so nobody 'simplifies' a call site back to
    .match(). The regex ends in '$', which is not end-of-string."""
    assert SEMVER.match("1.7.2\n")          # the trap, demonstrated
    assert not SEMVER.fullmatch("1.7.2\n")  # the fix


# --------------------------------- names ----------------------------------------

@pytest.mark.parametrize("name", [
    "",
    "../etc",
    "./package",
    "a b",
    "_private",
    ".private",
    "@scope",
    "@scope/",
    "UP/down",          # an unscoped '/' is git shorthand, not a name
    "axiós",            # \w is Unicode-aware by default -- re.ASCII closes it
    "@scopé/pkg",
    "axios\n",          # '$' matches before a trailing newline; needs fullmatch
    "a" * 215,          # npm's limit is 214, scope included
])
def test_refuses_invalid_names(name):
    with pytest.raises(ValueError):
        PackageRef(name=name, version="1.7.2")


@pytest.mark.parametrize("name", [
    "axios",
    "lodash",
    "my-package",
    "package.js",
    "foo_bar",
    "@babel/core",
    "@types/node",
    "@scope/my-package",
    # Legal-but-legacy. npm refuses NEW uppercase names; published ones still
    # install, so refusing them here would raise on a real package.
    "JSONStream",
    "@types/Node",
    "a",                # single character
    "a" * 214,          # exactly at the limit
])
def test_accepts_valid_names(name):
    assert PackageRef(name=name, version="1.7.2").name == name


# ------------------------------ identity properties ------------------------------

def test_canonical_and_hashable():
    ref = PackageRef(name="axios", version="1.7.2")
    assert ref.canonical == "npm:axios@1.7.2"
    assert len({ref, PackageRef(name="axios", version="1.7.2")}) == 1


def test_canonical_is_stable_across_scoped_names():
    assert PackageRef(name="@babel/core", version="7.24.0").canonical == \
        "npm:@babel/core@7.24.0"


def test_rejects_unknown_fields():
    """Without extra='forbid', a typo'd kwarg silently constructs with the
    default. This model is half of an M2 decision primary key."""
    with pytest.raises(ValidationError):
        PackageRef(name="axios", version="1.7.2", ecosytem="npm")


def test_is_immutable():
    ref = PackageRef(name="axios", version="1.7.2")
    with pytest.raises(ValidationError):
        ref.version = "1.7.3"


# ----------------------------- reason vocabularies -------------------------------

def test_every_refused_kind_is_a_valid_unresolvable_reason():
    """resolve() passes a non-resolvable SpecifierKind straight through as an
    Unresolvable.reason. That is only sound if the label sets line up."""
    assert set(get_args(SpecifierKind)) - RESOLVABLE <= set(get_args(UnresolvableReason))


def test_resolvable_kinds_are_never_reasons():
    """'registry' must not be expressible as a refusal reason -- the gate in
    resolve() excludes it, and the type should say so too."""
    assert not (RESOLVABLE & set(get_args(UnresolvableReason)))


def test_resolve_only_reasons_have_no_parse_equivalent():
    """not_found and network are lookup outcomes, not classifications. If one
    appeared in SpecifierKind, parse.py would be claiming knowledge it cannot
    have without touching the network."""
    assert {"not_found", "network"}.isdisjoint(get_args(SpecifierKind))


def test_resolvable_is_a_subset_of_the_kinds():
    """Guards a typo in RESOLVABLE, which would otherwise silently refuse
    everything -- safe, but the tool would stop working entirely."""
    assert RESOLVABLE <= set(get_args(SpecifierKind))


# -------------------------- the other boundary models ----------------------------

def test_unresolvable_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        Unresolvable(specifier="axios@^1.0.0", reason="range", detials="x")


def test_unresolvable_rejects_an_unlisted_reason():
    with pytest.raises(ValidationError):
        Unresolvable(specifier="axios", reason="registry")


def test_invocation_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        Invocation(
            kind="pass_through", npm_args=[], subcommand="ls",
            specifiers=[], lockfile_instal=True,     # typo'd
        )


# ----------------------------- the evidence models -------------------------------

def test_naive_timestamps_are_refused():
    """§17: timezone-aware UTC, never naive. A naive timestamp written to the
    M1 cache and read back in M2 is a silent hour-offset bug in `history`."""
    with pytest.raises(ValidationError):
        SourceRef(name="osv", fetched_at=datetime(2026, 1, 1))


def test_aware_timestamps_are_accepted():
    assert SourceRef(name="osv", fetched_at=TS).fetched_at == TS


@pytest.mark.parametrize("severity", ["severe", "important", "MEDIUM", "", None])
def test_severity_vocabulary_is_closed(severity):
    with pytest.raises(ValidationError):
        Vulnerability(id="GHSA-x", severity=severity, source=SOURCE)


def test_unknown_is_a_legitimate_severity():
    """Not a parse failure. OSV publishes severity in three shapes and §9.4
    scores an unrecognised one as zero -- the collector must have somewhere
    honest to put it."""
    vuln = Vulnerability(id="GHSA-x", severity="unknown", source=SOURCE)
    assert vuln.severity == "unknown"


def test_severity_and_risk_are_different_vocabularies():
    """'moderate' is a finding; 'medium' is a band. Pinning the difference
    stops a future 'tidy-up' from merging them."""
    assert "medium" not in get_args(Severity)
    assert "moderate" not in get_args(RiskLevel)


@pytest.mark.parametrize("partial,degraded", [
    (True, []),                       # a warning nobody can act on
    (False, ["github: 403"]),         # a failure the renderer will not show
])
def test_partial_and_degraded_sources_must_agree(partial, degraded):
    with pytest.raises(ValidationError):
        Evidence(package=REF, partial=partial, degraded_sources=degraded)


@pytest.mark.parametrize("partial,degraded", [
    (False, []),                      # clean
    (True, ["osv: 503 from api.osv.dev"]),   # degraded, and it says which
])
def test_consistent_evidence_constructs(partial, degraded):
    """The positive half. Without it, a validator that raised unconditionally
    would pass the test above and make Evidence unconstructible."""
    ev = Evidence(package=REF, partial=partial, degraded_sources=degraded)
    assert ev.partial is partial


@pytest.mark.parametrize("score", [-1, 101, 137])
def test_score_is_clamped_by_the_model(score):
    with pytest.raises(ValidationError):
        Assessment(evidence=EV, score=score, risk="low", scoring_version="0.1.0")


@pytest.mark.parametrize("score", [0, 100])
def test_the_scale_boundaries_are_inclusive(score):
    """§9.3 clamps to [0, 100] -- both ends are legal scores, not errors."""
    assert Assessment(
        evidence=EV, score=score, risk="low", scoring_version="0.1.0"
    ).score == score


def test_assessment_carries_its_evidence():
    """§4: every number traces to a visible evidence field. Structural, not
    conventional -- you cannot hold a score without the evidence behind it."""
    a = Assessment(evidence=EV, score=80, risk="low", scoring_version="0.1.0")
    assert a.evidence.package.canonical == "npm:axios@1.7.2"


@pytest.mark.parametrize("model,kwargs", [
    (SourceRef,     dict(name="osv", fetched_at=TS, from_cach=True)),
    (Vulnerability, dict(id="x", severity="low", source=SOURCE, fixed_version=[])),
    (Evidence,      dict(package=REF, vulnerabilites=[])),
    # Every required field is present and correct; the ONLY defect is the
    # extra key. Omitting scoring_version here would make the test pass on a
    # missing-field error even with extra='forbid' removed.
    (Assessment,    dict(evidence=EV, score=1, risk="low",
                         scoring_version="0.1.0", scoring_verison="0")),
])
def test_new_models_forbid_unknown_fields(model, kwargs):
    with pytest.raises(ValidationError):
        model(**kwargs)