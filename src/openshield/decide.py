"""Ask the user whether to proceed."""
from __future__ import annotations

import os
import sys

from .models import DecisionAction


def is_interactive() -> bool:
    return sys.stdin.isatty() and os.environ.get("CI", "").lower() != "true"


def prompt(question: str = "install?") -> DecisionAction:
    try:
        answer = input(f"{question} [y/N] ").strip().casefold()
    except EOFError:
        return "reject"
    except KeyboardInterrupt:
        print()
        return "reject"
    return "approve" if answer in ("y", "yes") else "reject"