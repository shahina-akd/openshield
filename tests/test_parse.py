from typing import get_args

import pytest
from pydantic import ValidationError

from openshield.models import (
    RESOLVABLE,
    SEMVER,
    PackageRef,
    SpecifierKind,
    UnresolvableReason,
)
from openshield.parse import (
    classify_invocation,
    classify_specifier,
    split_specifier,
)

# -------------------------------- split_specifier ------------------------------

@pytest.mark.parametrize("spec,expected", [
    ("axios",                  ("axios", None)),
    ("axios@1.7.2",            ("axios", "1.7.2")),
    ("axios@",                 ("axios", None)),      # empty version is no version
    ("@babel/core",            ("@babel/core", None)),
    ("@babel/core@7.24.0",     ("@babel/core", "7.24.0")),
    ("@babel/core@",           ("@babel/core", None)),
    ("@scope",                 ("@scope", None)),
    ("my-react@npm:react",     ("my-react", "npm:react")),
    ("jquery2@npm:jquery@2",   ("jquery2", "npm:jquery@2")),
])
def test_split_specifier(spec, expected):
    assert split_specifier(spec) == expected


# ------------------------------ classify_specifier -----------------------------

RESOLVABLE_CASES = [
    ("axios",                        "registry"),
    ("axios@1.7.2",                  "registry"),
    ("axios@",                       "registry"),
    ("@babel/core",                  "registry"),
    ("@babel/core@7.24.0",           "registry"),
    # npm installs this form, so parse MUST accept it. resolve() strips the
    # 'v' before constructing the PackageRef -- see the canonical test below.
    ("axios@v1.7.2",                 "registry"),
    ("next@14.2.0-canary.3",         "registry"),   # prerelease is still exact
    ("pkg@1.0.0+build.5",            "registry"),
    ("axios@01.7.2",                 "registry"),   # leading zero; npm tolerates
]

UNRESOLVABLE_CASES = [
    # range
    ("axios@^1.0.0",                 "range"),
    ("axios@~1.2",                   "range"),
    ("axios@>=1.0.0",                "range"),
    ("axios@>1.0.0",                 "range"),
    ("axios@=1.7.2",                 "range"),
    ("axios@1.2.x",                  "range"),
    ("axios@1.2",                    "range"),      # not full semver
    ("axios@*",                      "range"),
    ("axios@1.2.3 || 1.4.0",         "range"),
    ("axios@1.7.2||1.8.0",           "range"),
    ("axios@1.2.3 - 1.4.0",          "range"),
    ("axios@1.7.2.3",                "range"),      # digit-ish, not exact
    # tag
    ("axios@latest",                 "tag"),
    ("next@canary",                  "tag"),
    ("react@beta",                   "tag"),
    ("axios@v",                      "tag"),
    # alias -- npm's documented `foo@npm:bar` form
    ("my-react@npm:react",           "alias"),
    ("jquery2@npm:jquery@2",         "alias"),
    ("x@npm:@babel/core",            "alias"),      # slash lives in the TARGET
    ("x@npm:@babel/core@7.24.0",     "alias"),
    # local_path
    ("./local",                      "local_path"),
    ("../x",                         "local_path"),
    ("/abs/path",                    "local_path"),
    (".",                            "local_path"),
    ("..",                           "local_path"),
    ("file:./pkg",                   "local_path"),
    ("./pkg.tgz",                    "local_path"),  # a path, deliberately
    # vcs
    ("git+https://github.com/u/r.git", "vcs"),
    ("git://github.com/u/r.git",     "vcs"),
    ("git+ssh://git@github.com/u/r", "vcs"),
    ("github:axios/axios",           "vcs"),
    ("expressjs/express",            "vcs"),        # bare owner/repo
    # tarball
    ("https://example.com/p.tgz",    "tarball"),
    ("https://example.com/p.tar.gz", "tarball"),
    ("http://example.com/p?ref=1",   "tarball"),
    # unknown -- adversarial version strings nobody planned for
    ("axios@1x7y2",                  "unknown"),
    ("axios@1-7-2",                  "unknown"),
    ("axios@1/7/2",                  "unknown"),    # slash is in the VERSION
    ("axios@ 1.7.2",                 "unknown"),
    ("axios@1.7.2 ",                 "unknown"),
    ("axios@@1.7.2",                 "unknown"),
]

ALL_CASES = RESOLVABLE_CASES + UNRESOLVABLE_CASES


@pytest.mark.parametrize("spec,kind", ALL_CASES)
def test_classify_specifier(spec, kind):
    assert classify_specifier(spec) == kind


def test_only_exact_or_bare_is_ever_resolvable():
    """The one security property in this module. Labels are reading aids;
    membership of RESOLVABLE is what decides whether we hit the network."""
    for spec, _ in ALL_CASES:
        if classify_specifier(spec) in RESOLVABLE:
            _, version = split_specifier(spec)
            assert version is None or SEMVER.fullmatch(version), spec


@pytest.mark.parametrize("spec,_kind", UNRESOLVABLE_CASES)
def test_unresolvable_never_lands_in_resolvable(spec, _kind):
    assert classify_specifier(spec) not in RESOLVABLE


def test_parse_keeps_the_v_form_resolvable():
    """Guards against 'simplifying' SEMVER by deleting the `v?`. Without it,
    axios@v1.7.2 falls through to _TAG (which matches ^[A-Za-z]) and is refused
    as a tag -- refusing a legitimate exact version npm would install."""
    assert classify_specifier("axios@v1.7.2") == "registry"
    assert classify_specifier("axios@v") == "tag"      # a bare 'v' really IS a tag


def test_uppercase_v_form_is_refused_by_parse():
    """node-semver accepts a lowercase prefix only. Label unpinned -- it
    currently reads as 'tag' via _TAG. What matters is that it never reaches
    the network."""
    assert classify_specifier("axios@V1.7.2") not in RESOLVABLE


@pytest.mark.parametrize("spec", [
    "axios@1.7.2\n", "axios@1.7.2\r\n", "axios@1.7.2\t",
])
def test_trailing_whitespace_versions_are_refused(spec):
    """Label unpinned deliberately: which of 'range'/'unknown' this lands in
    depends on anchor details in _RANGE, and both are equally refused. The
    property is that it never reaches the network."""
    assert classify_specifier(spec) not in RESOLVABLE


# --------------------------------- PackageRef ----------------------------------

@pytest.mark.parametrize("version", ["^1.0.0", "latest", "1.2", "", "npm:react"])
def test_package_ref_refuses_inexact_versions(version):
    with pytest.raises(ValueError):
        PackageRef(name="axios", version=version)


def test_package_ref_refuses_non_canonical_versions():
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
    or a changelog paste would become a distinct cache key for one package."""
    with pytest.raises(ValueError):
        PackageRef(name="axios", version=version)


def test_semver_is_only_ever_used_with_fullmatch():
    """Asserts the trap itself, so nobody 'simplifies' a call site back to
    .match(). The regex ends in '$', which is not end-of-string."""
    assert SEMVER.match("1.7.2\n")          # the trap, demonstrated
    assert not SEMVER.fullmatch("1.7.2\n")  # the fix


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
def test_package_ref_refuses_invalid_names(name):
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
    # install, so refusing them here raises on a real package.
    "JSONStream",
    "@types/Node",
    "a",                # single character
    "a" * 214,          # exactly at the limit
])
def test_package_ref_accepts_valid_names(name):
    assert PackageRef(name=name, version="1.7.2").name == name


def test_package_ref_canonical_and_hashable():
    ref = PackageRef(name="axios", version="1.7.2")
    assert ref.canonical == "npm:axios@1.7.2"
    assert len({ref, PackageRef(name="axios", version="1.7.2")}) == 1


def test_package_ref_rejects_unknown_fields():
    """Without extra='forbid', a typo'd kwarg silently constructs with the
    default. This model is half of an M2 decision primary key."""
    with pytest.raises(ValidationError):
        PackageRef(name="axios", version="1.7.2", ecosytem="npm")


def test_package_ref_is_immutable():
    ref = PackageRef(name="axios", version="1.7.2")
    with pytest.raises(ValidationError):
        ref.version = "1.7.3"


def test_classify_accepts_names_that_package_ref_would_reject():
    """classify_specifier validates the FORM, not the name -- it splits and
    inspects the version only. So 'registry' does not imply constructible, and
    resolve() must catch ValidationError and return Unresolvable rather than
    letting it escape. This test documents the gap; Step 0.3 closes it."""
    assert classify_specifier("axiós") in RESOLVABLE
    with pytest.raises(ValidationError):
        PackageRef(name="axiós", version="1.0.0")


# ----------------------------- reason vocabularies -----------------------------

def test_every_refused_kind_is_a_valid_unresolvable_reason():
    """resolve() passes a non-resolvable SpecifierKind straight through as an
    Unresolvable.reason. That is only sound if the label sets line up."""
    kinds = set(get_args(SpecifierKind))
    reasons = set(get_args(UnresolvableReason))
    assert kinds - RESOLVABLE <= reasons


def test_resolvable_kinds_are_never_reasons():
    """'registry' must not be expressible as a refusal reason -- the gate in
    resolve() excludes it, and the type should say so too."""
    assert not (RESOLVABLE & set(get_args(UnresolvableReason)))


def test_resolve_only_reasons_have_no_parse_equivalent():
    """not_found and network are lookup outcomes, not classifications. If one
    appeared in SpecifierKind, parse.py would be claiming knowledge it cannot
    have without the network."""
    assert {"not_found", "network"}.isdisjoint(get_args(SpecifierKind))


# ------------------------------ classify_invocation ----------------------------

@pytest.mark.parametrize("argv,specs", [
    (["npm", "install", "axios"],                        ["axios"]),
    (["install", "axios"],                               ["axios"]),   # npm-less
    (["/usr/local/bin/npm", "install", "axios"],         ["axios"]),
    (["npm", "i", "axios", "lodash"],                    ["axios", "lodash"]),
    (["npm", "add", "@babel/core@7.24.0"],               ["@babel/core@7.24.0"]),
    (["npm", "install", "-D", "typescript"],             ["typescript"]),
    (["npm", "install", "--save-dev", "typescript"],     ["typescript"]),
    (["npm", "install", "-g", "axios"],                  ["axios"]),
    (["npm", "install", "-E", "axios"],                  ["axios"]),
    (["npm", "--prefix", "/tmp", "install", "axios"],    ["axios"]),
    (["npm", "install", "--registry", "https://r.example", "axios"], ["axios"]),
    (["npm", "install", "--omit", "dev", "axios"],       ["axios"]),
    (["npm", "install", "--workspace", "api", "axios"],  ["axios"]),
    (["npm", "install", "--prefix=/tmp", "axios"],       ["axios"]),
    (["npm", "install", "--", "axios"],                  ["axios"]),
    *[(["npm", a, "axios"], ["axios"]) for a in
      ("install", "i", "in", "ins", "inst", "insta", "instal", "add",
       "isnt", "isnta", "isntal", "isntall")],
])
def test_intercepted(argv, specs):
    inv = classify_invocation(argv)
    assert inv.kind == "intercepted"
    assert inv.specifiers == specs


@pytest.mark.parametrize("argv", [
    ["npm", "--before", "2023-01-01", "install", "axios"],
    ["npm", "--userconfig", "/tmp/rc", "install", "axios"],
    ["npm", "--some-future-flag", "value", "install", "axios"],
    ["npm", "-C", "/tmp", "install", "axios"],
])
def test_unknown_value_flags_do_not_hide_an_install(argv):
    """The dangerous direction: a flag we don't know about must never push
    the install out of the subcommand slot."""
    assert classify_invocation(argv).kind == "intercepted"


@pytest.mark.parametrize("argv,sub", [
    (["npm", "ls"],                  "ls"),
    (["npm", "--version"],           None),
    (["npm", "-v"],                  None),
    (["npm", "run", "dev"],          "run"),
    (["npm", "run", "install"],      "run"),   # 'install' as a script name
    (["npm", "test"],                "test"),
    (["npm", "uninstall", "axios"],  "uninstall"),
    (["npm", "ci"],                  "ci"),
    (["npm"],                        None),
])
def test_pass_through(argv, sub):
    inv = classify_invocation(argv)
    assert inv.kind == "pass_through"
    assert inv.subcommand == sub
    assert inv.specifiers == []


def test_value_flag_value_is_not_mistaken_for_a_command():
    inv = classify_invocation(["npm", "--tag", "install", "publish"])
    assert inv.kind == "pass_through"
    assert inv.subcommand == "publish"


def test_bare_install_is_distinct_from_lockfile_install():
    inv = classify_invocation(["npm", "install"])
    assert inv.kind == "pass_through"
    assert inv.subcommand == "install"
    assert inv.specifiers == []
    assert inv.bare_install is True
    assert inv.lockfile_install is False


def test_lockfile_install_is_flagged_separately_from_bare_install():
    inv = classify_invocation(["npm", "ci"])
    assert inv.kind == "pass_through"
    assert inv.subcommand == "ci"
    assert inv.specifiers == []
    assert inv.bare_install is False
    assert inv.lockfile_install is True


def test_ls_is_ordinary_pass_through():
    inv = classify_invocation(["npm", "ls"])
    assert inv.kind == "pass_through"
    assert inv.subcommand == "ls"
    assert inv.specifiers == []
    assert inv.bare_install is False
    assert inv.lockfile_install is False


def test_npm_args_never_include_npm():
    assert classify_invocation(["npm", "install", "axios"]).npm_args == \
        ["install", "axios"]