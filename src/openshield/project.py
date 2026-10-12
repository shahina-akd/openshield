"""Project identity."""
from __future__ import annotations

import hashlib
import os
import unicodedata
from pathlib import Path

GLOBAL = "__global__"


def find_root(start: Path | None = None) -> Path | None:
    """The nearest ancestor containing package.json."""
    here = (start or Path.cwd()).resolve()
    for directory in [here, *here.parents]:
        if (directory / "package.json").exists():
            return directory
    return None


def current_path() -> Path:
    """The current project directory, or OPENSHIELD_PROJECT if set."""
    override = os.environ.get("OPENSHIELD_PROJECT")
    if override:
        return Path(override)
    return find_root() or Path.cwd()


def project_id(path: Path) -> str:
    """A stable id for a directory, identical for every spelling of it.

    The path is resolved (symlinks, `..`), NFC-normalised (macOS can return
    differently composed Unicode) and casefolded (case-insensitive volumes).
    """
    resolved = unicodedata.normalize("NFC", str(Path(path).resolve()))
    return hashlib.sha256(resolved.casefold().encode()).hexdigest()[:16]


def current_project() -> str:
    return project_id(current_path())