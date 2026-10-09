"""decide.py -- ask the human. Knows nothing about npm, packages, or storage."""
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
        # stdin closed mid-prompt. Nobody answered, so this is a policy
        # outcome, not a rejection -- run.py maps it to POLICY_BLOCKED.
        return "reject"
    except KeyboardInterrupt:
        print()
        return "reject"
    return "approve" if answer in ("y", "yes") else "reject"