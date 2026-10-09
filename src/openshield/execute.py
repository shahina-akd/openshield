"""execute.py -- the ONLY code in the project that runs npm.

§4's separation of analysis and execution. Today that reads as pedantry: the
analysis cannot install anything because it never calls subprocess. It stops
being pedantry the moment a malware feed is added, when the code path that
concludes "this package is malicious" must be structurally incapable of
installing it.

Keeping that true means keeping this file the only importer of subprocess, and
keeping it imported only by run.py, only after an approval.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .exit_codes import INTERNAL_ERROR

SHIM_DIR = Path.home() / ".openshield" / "shims"


def real_npm(path: str | None = None) -> str | None:
    """Resolve npm with OUR shim directory removed from PATH.

    Unused until M2 and written now anyway: a shim that resolves itself is an
    infinite loop that will fork-bomb your shell (§12), and retrofitting this
    while debugging under a live shim is the worst possible time to write it.

    Removes ONLY OpenShield's directory. Node version managers (nvm, asdf,
    volta) install their own shims, and stripping those would run npm under the
    wrong Node -- which is the M2 `doctor` check about node managers, in
    advance.

    casefold per §17: macOS volumes are case-insensitive, so a PATH entry
    differing only in case is the same directory.
    """
    wanted = str(SHIM_DIR).casefold()
    entries = (path if path is not None else os.environ.get("PATH", "")).split(os.pathsep)
    cleaned = [p for p in entries if p and str(Path(p)).casefold() != wanted]
    return shutil.which("npm", path=os.pathsep.join(cleaned))


def run_npm(argv: list[str]) -> int:
    """Run npm and return ITS exit code.

    List form, never shell=True (§17). This argv came off a command line the
    tool is explicitly treating as untrusted; handing it to a shell would let a
    package specifier containing a semicolon do something no amount of
    scoring would catch.

    The return value is npm's own code, propagated verbatim (§11.2), so
    `openshield intercept -- npm install x && npm test` behaves exactly as
    `npm install x && npm test` would.
    """
    npm = real_npm()
    if npm is None:
        return INTERNAL_ERROR
    return subprocess.run([npm, *argv]).returncode