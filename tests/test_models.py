"""Tests for models.py: identity validation and label vocabularies."""
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

# Module-level constants rather than fixtures, because @parametrize needs them
# at collection time.
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
    "14.2.0-canary.3",
    "1.0.0+build.5",
    "1.0.0-alpha.1+build.5",
])
def test_accepts_exact_versions(version):
    assert PackageRef(name="axios", version=version).version == version


def test_refuses_non_canonical_versions():
    """npm accepts `v1.7.2`, but the identity must not carry the prefix or one
    package would have two cache keys. resolve.normalize_version() strips it
    beforehand."""
    with pytest.raises(ValidationError, match="canonical"):
        PackageRef(name="axios", version="v1.7.2")


def test_uppercase_v_is_not_a_version_at_all():
    """node-semver accepts only a lowercase prefix."""
    with pytest.raises(ValidationError, match="must be exact"):
        PackageRef(name="axios", version="V1.7.2")


@pytest.mark.parametrize("version", [
    "1.7.2\n", "1.7.2\r\n", " 1.7.2", "1.7.2 ", "1.7.2\t",
])
def test_whitespace_never_reads_as_an_exact_version(version):
    with pytest.raises(ValueError):
        PackageRef(name="axios", version=version)


def test_semver_is_only_ever_used_with_fullmatch():
    """`$` also matches before a trailing newline, so .match() is unsafe."""
    assert SEMVER.match("1.7.2\n")
    assert not SEMVER.fullmatch("1.7.2\n")


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
    "UP/down",          # unscoped '/' is git shorthand
    "axiós",
    "@scopé/pkg",
    "axios\n",
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
    # npm refuses new uppercase names, but existing ones still install.
    "JSONStream",
    "@types/Node",
    "a",
    "a" * 214,
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
    """Prevents a misspelled keyword from silently falling back to a default."""
    with pytest.raises(ValidationError):
        PackageRef(name="axios", version="1.7.2", ecosytem="npm")


def test_is_immutable():
    ref = PackageRef(name="axios", version="1.7.2")
    with pytest.raises(ValidationError):
        ref.version = "1.7.3"


# ----------------------------- reason vocabularies -------------------------------

def test_every_refused_kind_is_a_valid_unresolvable_reason():
    """resolve() passes non-resolvable kinds through as Unresolvable.reason."""
    assert set(get_args(SpecifierKind)) - RESOLVABLE <= set(get_args(UnresolvableReason))


def test_resolvable_kinds_are_never_reasons():
    assert not (RESOLVABLE & set(get_args(UnresolvableReason)))


def test_resolve_only_reasons_have_no_parse_equivalent():
    """These are lookup outcomes, which parsing alone cannot determine."""
    assert {"not_found", "network"}.isdisjoint(get_args(SpecifierKind))


def test_resolvable_is_a_subset_of_the_kinds():
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
            specifiers=[], lockfile_instal=True,
        )


# ----------------------------- the evidence models -------------------------------

def test_naive_timestamps_are_refused():
    with pytest.raises(ValidationError):
        SourceRef(name="osv", fetched_at=datetime(2026, 1, 1))


def test_aware_timestamps_are_accepted():
    assert SourceRef(name="osv", fetched_at=TS).fetched_at == TS


@pytest.mark.parametrize("severity", ["severe", "important", "MEDIUM", "", None])
def test_severity_vocabulary_is_closed(severity):
    with pytest.raises(ValidationError):
        Vulnerability(id="GHSA-x", severity=severity, source=SOURCE)


def test_unknown_is_a_legitimate_severity():
    """Used when OSV reports a severity the collector does not recognise."""
    vuln = Vulnerability(id="GHSA-x", severity="unknown", source=SOURCE)
    assert vuln.severity == "unknown"


def test_severity_and_risk_are_different_vocabularies():
    """'moderate' is a finding severity; 'medium' is a risk band."""
    assert "medium" not in get_args(Severity)
    assert "moderate" not in get_args(RiskLevel)


@pytest.mark.parametrize("partial,degraded", [
    (True, []),
    (False, ["github: 403"]),
])
def test_partial_and_degraded_sources_must_agree(partial, degraded):
    with pytest.raises(ValidationError):
        Evidence(package=REF, partial=partial, degraded_sources=degraded)


@pytest.mark.parametrize("partial,degraded", [
    (False, []),
    (True, ["osv: 503 from api.osv.dev"]),
])
def test_consistent_evidence_constructs(partial, degraded):
    ev = Evidence(package=REF, partial=partial, degraded_sources=degraded)
    assert ev.partial is partial


@pytest.mark.parametrize("score", [-1, 101, 137])
def test_score_is_clamped_by_the_model(score):
    with pytest.raises(ValidationError):
        Assessment(evidence=EV, score=score, risk="low", scoring_version="0.1.0")


@pytest.mark.parametrize("score", [0, 100])
def test_the_scale_boundaries_are_inclusive(score):
    assert Assessment(
        evidence=EV, score=score, risk="low", scoring_version="0.1.0"
    ).score == score


def test_assessment_carries_its_evidence():
    a = Assessment(evidence=EV, score=80, risk="low", scoring_version="0.1.0")
    assert a.evidence.package.canonical == "npm:axios@1.7.2"


@pytest.mark.parametrize("model,kwargs", [
    (SourceRef,     dict(name="osv", fetched_at=TS, from_cach=True)),
    (Vulnerability, dict(id="x", severity="low", source=SOURCE, fixed_version=[])),
    (Evidence,      dict(package=REF, vulnerabilites=[])),
    # All required fields are present so that only the extra key can fail.
    (Assessment,    dict(evidence=EV, score=1, risk="low",
                         scoring_version="0.1.0", scoring_verison="0")),
])
def test_new_models_forbid_unknown_fields(model, kwargs):
    with pytest.raises(ValidationError):
        model(**kwargs)