"""Classify npm command lines and package specifiers. No I/O."""
from __future__ import annotations

import re
from pathlib import Path

from .models import SEMVER, Invocation, SpecifierKind

# --------------------------------- SPECIFIERS ---------------------------------

# A dist-tag such as `latest` or `beta`. Used with .fullmatch().
_TAG = re.compile(r"^[A-Za-z][0-9A-Za-z._-]*$")

# Range forms. Only refines the label: anything unmatched becomes "unknown",
# which is also refused. `\Z` is used because `$` matches before a newline.
_RANGE = re.compile(
    r"^[\^~]"                    # ^1.0.0  ~1.2
    r"|^[><]=?"                  # >=1.0.0  >1.0.0
    r"|^="                       # =1.7.2
    r"|^\*\Z"                    # *
    r"|^v?[\dxX][\d.xX*]*\Z"     # 1.2  1.2.x  1.*
    r"|\|\|"                     # 1.2.3 || 1.4.0
    r"|\s-\s"                    # 1.2.3 - 1.4.0
)

_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

_VCS_PREFIXES = (
    "git://", "git+ssh://", "git+http://", "git+https://", "git+file://",
    "github:", "gitlab:", "bitbucket:", "gist:",
)


def split_specifier(spec: str) -> tuple[str, str | None]:
    """'axios@1.7.2' -> ('axios', '1.7.2');  '@babel/core' -> ('@babel/core', None)"""
    if spec.startswith("@"):
        at = spec.find("@", 1)
        if at == -1:
            return spec, None
        name, version = spec[:at], spec[at + 1:]
        return (name, version or None)
    name, sep, version = spec.partition("@")
    return (name, version) if (sep and version) else (name, None)


def classify_specifier(spec: str) -> SpecifierKind:
    """Classify a specifier's form. Only bare names and exact versions are
    resolvable; unrecognised forms become 'unknown'.

    This checks the form only; the name is validated later by PackageRef.
    """
    if spec in (".", "..") or spec.startswith(("./", "../", "/", "~/", "file:")):
        return "local_path"

    if spec.startswith(_VCS_PREFIXES):
        return "vcs"

    if _URL_SCHEME.match(spec):
        return "tarball"

    name, version = split_specifier(spec)

    # Bare `owner/repo` is GitHub shorthand. Checked on the name so aliases to
    # scoped packages (`x@npm:@babel/core`) are not caught.
    if "/" in name and not name.startswith("@"):
        return "vcs"

    if version is None:
        return "registry"

    if version.startswith("npm:"):
        return "alias"

    if SEMVER.fullmatch(version):
        return "registry"
    if _TAG.fullmatch(version):
        return "tag"
    if _RANGE.search(version):
        return "range"
    return "unknown"


# --------------------------------- INVOCATION ---------------------------------

# npm's aliases for `install`, including its typo aliases. A missing entry
# would let an install bypass review.
_INSTALL_ALIASES = frozenset({
    "install", "i", "in", "ins", "inst", "insta", "instal", "add",
    "isnt", "isnta", "isntal", "isntall", "install-test", "it",
})

_LOCKFILE_COMMANDS = frozenset({
    "ci", "install-ci-test", "cit", "clean-install-test", "sit",
})

# Other npm commands. A missing entry is harmless: unknown commands pass through.
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

# Flags that take a value as the next token. A missing entry produces a
# spurious specifier that fails to resolve visibly.
_VALUE_FLAGS = frozenset({
    "--prefix", "--registry", "--userconfig", "--globalconfig", "--cache",
    "--otp", "--tag", "--omit", "--include", "--workspace", "-w",
    "--loglevel", "--script-shell", "--node-options", "--before",
})


def _advance(args: list[str], i: int) -> int:
    """Index of the next token after the flag at `i` and any value it takes."""
    return i + 2 if args[i] in _VALUE_FLAGS else i + 1


def _find_subcommand(args: list[str]) -> tuple[int, str | None]:
    """Locate the npm subcommand by name rather than position.

    Matching known commands means an unrecognised value-taking flag cannot
    push its value into the subcommand slot and hide an install.
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

    # No known command: report the first non-flag token (always pass-through).
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