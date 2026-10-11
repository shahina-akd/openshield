"""The only module that runs npm.

Analysis and execution are kept separate: this should remain the only
importer of subprocess, and only run.py should import it.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .exit_codes import INTERNAL_ERROR

SHIM_DIR = Path.home() / ".openshield" / "shims"


def real_npm(path: str | None = None) -> str | None:
    """Find npm on PATH, excluding OpenShield's own shim directory.

    Excluding the shim prevents it from invoking itself. Other shims (nvm,
    asdf, volta) are kept so npm runs under the intended Node. The comparison
    is case-insensitive for case-insensitive filesystems.
    """
    wanted = str(SHIM_DIR).casefold()
    entries = (path if path is not None else os.environ.get("PATH", "")).split(os.pathsep)
    cleaned = [p for p in entries if p and str(Path(p)).casefold() != wanted]
    return shutil.which("npm", path=os.pathsep.join(cleaned))


def run_npm(argv: list[str]) -> int:
    """Run npm with `argv` and return npm's exit code.

    Uses list form, never a shell, because argv is untrusted.
    """
    npm = real_npm()
    if npm is None:
        return INTERNAL_ERROR
    return subprocess.run([npm, *argv]).returncode