"""models.py -- identity validation and the label vocabularies.

Nothing here imports parse.py. If this file goes red, the identity contract
broke, not the parser.
"""
from typing import get_args

import pytest
from pydantic import ValidationError

from openshield.models import (
    RESOLVABLE,
    SEMVER,
    Invocation,
    PackageRef,
    SpecifierKind,
    Unresolvable,
    UnresolvableReason,
)

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