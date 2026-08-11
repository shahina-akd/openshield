import pytest

from openshield.models import RESOLVABLE, SEMVER, PackageRef
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
            assert version is None or SEMVER.match(version), spec


@pytest.mark.parametrize("spec,_kind", UNRESOLVABLE_CASES)
def test_unresolvable_never_lands_in_resolvable(spec, _kind):
    assert classify_specifier(spec) not in RESOLVABLE


# --------------------------------- PackageRef ----------------------------------

@pytest.mark.parametrize("version", ["^1.0.0", "latest", "1.2", "", "npm:react"])
def test_package_ref_refuses_inexact_versions(version):
    with pytest.raises(ValueError):
        PackageRef(name="axios", version=version)


def test_package_ref_canonical_and_hashable():
    ref = PackageRef(name="axios", version="1.7.2")
    assert ref.canonical == "npm:axios@1.7.2"
    assert len({ref, PackageRef(name="axios", version="1.7.2")}) == 1


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


def test_bare_install_passes_through_but_is_flagged():
    inv = classify_invocation(["npm", "install"])
    assert inv.kind == "pass_through"
    assert inv.bare_install is True


def test_npm_args_never_include_npm():
    assert classify_invocation(["npm", "install", "axios"]).npm_args == \
        ["install", "axios"]