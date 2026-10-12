
import os
from pathlib import Path


def current_project() -> str:
    """Return the normalized path of the current project."""
    override = os.environ.get("OPENSHIELD_PROJECT")
    path = Path(override) if override else Path.cwd()

    return str(path.resolve())
