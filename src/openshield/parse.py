"""argv -> Invocation, and specifier -> kind. No network, no I/O, no clock."""
from __future__ import annotations

import re
from pathlib import Path

from .models import SEMVER, Invocation, SpecifierKind

# --------------------------------- SPECIFIERS ---------------------------------

# A dist-tag is a bare identifier: `latest`, `next`, `beta`, `canary`.
# Used with .fullmatch() -- '$' alone would let `beta\n` through as a tag.
_TAG = re.compile(r"^[A-Za-z][0-9A-Za-z._-]*$")

# Range-ish forms. Incompleteness here is SAFE: anything unmatched falls to
# "unknown", which is equally unresolvable. This regex only refines the
# label, it never decides whether something is refused.
#
# '\Z' rather than '$' in the numeric alternative: '$' also matches before a
# trailing newline, so `1.7.2\n` would read as "range" rather than "unknown".
# Cosmetic -- both are refused -- but it keeps every anchor in the project
# meaning end-of-string.
_RANGE = re.compile(
    r"^[\^~]"                    # ^1.0.0  ~1.2
    r"|^[><]=?"                  # >=1.0.0  >1.0.0
    r"|^="                       # =1.7.2
    r"|^\*\Z"                    # *
    r"|^v?[\dxX][\d.xX*]*\Z"     # 1.2  1.2.x  1.*
    r"|\|\|"                     # 1.2.3 || 1.4.0   (anywhere)
    r"|\s-\s"                    # 1.2.3 - 1.4.0    (anywhere)
)

# Any URL scheme. Registry specifiers are never URLs, so no extension test is
# needed -- .tar.gz and ?ref=… are covered for free.
_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

_VCS_PREFIXES = (
    "git://", "git+ssh://", "git+http://", "git+https://", "git+file://",
    "github:", "gitlab:", "bitbucket:", "gist:",
)


def split_specifier(spec: str) -> tuple[str, str | None]:
    """'axios@1.7.2' -> ('axios', '1.7.2');  '@babel/core' -> ('@babel/core', None)"""
    if spec.startswith("@"):
        at = spec.find("@", 1)           # a version delimiter is a LATER '@'
        if at == -1:
            return spec, None
        name, version = spec[:at], spec[at + 1:]
        return (name, version or None)
    name, sep, version = spec.partition("@")
    return (name, version) if (sep and version) else (name, None)


def classify_specifier(spec: str) -> SpecifierKind:
    """Only bare names and exact versions are resolvable. Everything else is
    refused and labelled; an unanticipated form becomes 'unknown', never a
    confident lookup of the wrong version.

    Note this validates the *form*, not the name -- 'registry' does not imply
    that PackageRef will accept it. resolve() catches that separately.
    """
    if spec in (".", "..") or spec.startswith(("./", "../", "/", "~/", "file:")):
        return "local_path"

    if spec.startswith(_VCS_PREFIXES):
        return "vcs"

    if _URL_SCHEME.match(spec):
        return "tarball"

    name, version = split_specifier(spec)

    # `expressjs/express` -- npm reads bare owner/repo as GitHub shorthand.
    # Judged on the NAME, after splitting: testing the whole specifier would
    # swallow aliases whose target is scoped (`x@npm:@babel/core`).
    if "/" in name and not name.startswith("@"):
        return "vcs"

    if version is None:
        return "registry"            # bare name -> dist-tags.latest

    # `my-react@npm:react` -- a package alias, not a version. Resolvable in
    # principle (the target names a package) but not implemented; see M3.
    if version.startswith("npm:"):
        return "alias"

    # fullmatch, always: SEMVER ends in '$', which is not end-of-string.
    if SEMVER.fullmatch(version):
        return "registry"
    if _TAG.fullmatch(version):
        return "tag"
    if _RANGE.search(version):
        return "range"
    return "unknown"


# --------------------------------- INVOCATION ---------------------------------

# npm's aliases for `install`, typo-tolerance included. THIS is the only set
# whose incompleteness is dangerous -- a missing alias is a silent
# interception hole. Reconcile against `npm help install`.
_INSTALL_ALIASES = frozenset({
    "install", "i", "in", "ins", "inst", "insta", "instal", "add",
    "isnt", "isnta", "isntal", "isntall", "install-test", "it",
})

_LOCKFILE_COMMANDS = frozenset({
    "ci", "install-ci-test", "cit", "clean-install-test", "sit",
})

# Every other npm command. Incompleteness here is SAFE: an unrecognised
# command falls through to pass_through, which is correct for anything that
# is not an install.
_OTHER_COMMANDS = frozenset({
    "access", "audit", "bugs", "cache", "config", "dedupe", "deprecate",
    "diff", "dist-tag", "docs", "doctor", "edit", "exec", "explain", "explore",
    "find-dupes", "fund", "help", "hook", "init", "la", "link", "list", "ll",
    "login", "logout", "ls", "org", "outdated", "owner", "pack", "ping", "pkg",
    "prefix", "profile", "prune", "publish", "query", "r", "rb", "rebuild",
    "repo", "restart", "rm", "root", "run", "run-script", "s", "se", "search",
    "shrinkwrap", "star", "stars", "start", "stop", "t", "team", "test",
    "token", "tst", "un", "uninstall", "unlink", "unpublish", "unstar", "up",
    "update", "version", "view", "whoami",
})

_KNOWN_COMMANDS = _INSTALL_ALIASES | _LOCKFILE_COMMANDS | _OTHER_COMMANDS

# Flags whose *next* token is a value. Incompleteness here degrades to a
# spurious specifier that resolves to not_found and is surfaced -- noisy,
# not silent.
_VALUE_FLAGS = frozenset({
    "--prefix", "--registry", "--userconfig", "--globalconfig", "--cache",
    "--otp", "--tag", "--omit", "--include", "--workspace", "-w",
    "--loglevel", "--script-shell", "--node-options", "--before",
})


def _advance(args: list[str], i: int) -> int:
    """Index of the next token that could be a command or a specifier."""
    return i + 2 if args[i] in _VALUE_FLAGS else i + 1


def _find_subcommand(args: list[str]) -> tuple[int, str | None]:
    """Locate the npm subcommand by NAME, not by position.

    Taking 'the first non-flag token' means an unknown value-taking flag
    (`npm --before 2023-01-01 install axios`) puts its value in the
    subcommand slot, the command reads as pass_through, and the install
    proceeds unreviewed. Matching a known command instead makes the flag
    list non-load-bearing.
    """
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            continue
        if tok.startswith("-"):
            i = _advance(args, i)
            continue
        if tok in _KNOWN_COMMANDS:
            return i, tok
        i += 1

    # No known command. Report the first non-flag token for display only --
    # this path is always pass_through.
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            i += 1
            continue
        if tok.startswith("-"):
            i = _advance(args, i)
            continue
        return i, tok
    return len(args), None


def classify_invocation(argv: list[str]) -> Invocation:
    args = list(argv)
    if args and Path(args[0]).name == "npm":
        args = args[1:]

    i, sub = _find_subcommand(args)

    if sub in _LOCKFILE_COMMANDS:
        return Invocation(
            kind="pass_through",
            npm_args=args,
            subcommand=sub,
            specifiers=[],
            lockfile_install=True,
        )

    if sub not in _INSTALL_ALIASES:
        return Invocation(
            kind="pass_through",
            npm_args=args,
            subcommand=sub,
            specifiers=[],
        )

    specs: list[str] = []
    j = i + 1

    while j < len(args):
        tok = args[j]

        if tok == "--":
            j += 1
            continue

        if tok.startswith("-"):
            j = _advance(args, j)
            continue

        specs.append(tok)
        j += 1

    if not specs:
        return Invocation(
            kind="pass_through",
            npm_args=args,
            subcommand=sub,
            specifiers=[],
            bare_install=True,
        )

    return Invocation(
        kind="intercepted",
        npm_args=args,
        subcommand=sub,
        specifiers=specs,
    )