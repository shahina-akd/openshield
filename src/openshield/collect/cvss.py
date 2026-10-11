"""CVSS v3.0/3.1 base score calculation.

OSV's `severity` entries carry a CVSS vector string rather than a number, so
the base score is computed here to band it.
"""
from __future__ import annotations

import math

# Metric weights from the CVSS v3.1 specification.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}   # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                          # Attack Complexity
_UI = {"N": 0.85, "R": 0.62}                          # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}              # Confidentiality/Integrity/Availability

# Privileges Required weights depend on whether Scope is Changed.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: up to one decimal, using integer arithmetic to avoid
    floating-point disagreement with published scores."""
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: object) -> float | None:
    """'CVSS:3.1/AV:N/AC:L/...' -> 9.8, or None if not a parseable v3 vector.

    v2 and v4 vectors are declined rather than approximated.
    """
    if not isinstance(vector, str):
        return None
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        return None

    try:
        metrics = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
        scope = metrics["S"]
        privileges = (_PR_UNCHANGED if scope == "U" else _PR_CHANGED)[metrics["PR"]]

        exploitability = (
            8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
            * privileges * _UI[metrics["UI"]]
        )
        iss = 1 - (
            (1 - _CIA[metrics["C"]])
            * (1 - _CIA[metrics["I"]])
            * (1 - _CIA[metrics["A"]])
        )
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    except (KeyError, ValueError):
        return None

    if impact <= 0:
        return 0.0
    total = impact + exploitability
    if scope == "C":
        total *= 1.08
    return _roundup(min(total, 10.0))


def band(score: float) -> str:
    """Map a CVSS score onto the project's severity vocabulary.

    CVSS "Medium" becomes "moderate". A score of 0.0 ("None" in CVSS) becomes
    "unknown" rather than "low", since the publisher gave no rating.
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "moderate"
    if score > 0.0:
        return "low"
    return "unknown"