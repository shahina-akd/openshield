"""score.py -- Evidence -> Assessment. PURE.

No network, no file I/O, no clock, no randomness. §9.2 requires this and
tests/test_score.py enforces it structurally: the module's own imports are
parsed and anything that can read the world fails the suite.

A score that depends on when you ran it cannot be golden-tested and cannot
explain a decision you made three months ago -- which is exactly what §10.3
stores scoring_version in order to do.
"""
from __future__ import annotations

from .models import Assessment, Evidence, RiskLevel, Severity

# Bump on ANY weight or banding change. Stamped on every Assessment (§9.2) and
# stored with every decision from M2 (§10.3), so a past decision stays
# explicable after the table moves under it.
SCORING_VERSION = "0.1.0"

# §9.3. Subtract-only from 100, which M1 replaces wholesale -- see the note at
# the end of this file's tests about what 31 findings do to this table.
_WEIGHTS: dict[Severity, int] = {
    "critical": 40,
    "high": 20,
    "moderate": 10,
    "low": 3,
    # A finding whose severity could not be determined costs nothing. That is
    # fail-open, and it is only acceptable because render.py shows the finding
    # by ID regardless -- see NOTES-0_4.md §1.1(4).
    "unknown": 0,
}