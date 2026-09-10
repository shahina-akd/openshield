"""CVSS v3.0/3.1 base score. Pure arithmetic, no dependencies.

Tier 3 of the severity fallback in osv.py. OSV's schema puts machine-readable
severity in `vuln["severity"]` as a list of {"type": …, "score": <vector>} --
where "score" holds a VECTOR STRING, not a number. Banding it means computing
the base score.

Thirty lines of published arithmetic, checkable against vectors with known
scores, and cheaper than a dependency (§16). Hand-written on purpose: this is a
learning project, and an opaque library that works is worth less than a function
that is understood (CONTEXT.md §12).
"""
from __future__ import annotations

import math

# Metric weights, CVSS v3.1 specification table.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}   # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                          # Attack Complexity
_UI = {"N": 0.85, "R": 0.62}                          # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}              # Confidentiality/Integrity/Availability

# Privileges Required is scored differently when Scope is Changed: escaping the
# vulnerable component makes held privileges worth more.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(value: float) -> float:
    """CVSS v3.1's own rounding: integer arithmetic, always up, one decimal.

    Specified this way rather than as round(x, 1) because binary floating point
    makes the naive version disagree with published scores at the boundaries.
    """
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: object) -> float | None:
    """'CVSS:3.1/AV:N/AC:L/…' -> 9.8. None for anything not a parseable v3 vector.

    Declines v2 and v4 rather than approximating them: v2 uses a different
    formula and v4 a lookup table. Both fall through to "unknown" in
    severity_of, which is the honest answer -- §9.4 scores it as zero.
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
        # A missing or unrecognised metric is not a severity. Same discipline
        # as the rest of the collector: an unexpected shape becomes "unknown",
        # never an exception out of a pipeline stage.
        return None

    if impact <= 0:
        return 0.0
    total = impact + exploitability
    if scope == "C":
        total *= 1.08
    return _roundup(min(total, 10.0))


def band(score: float) -> str:
    """CVSS qualitative ratings, mapped onto SPEC §9.1's severity vocabulary.

    CVSS says "Medium" where §9.1 says "moderate" -- the same translation
    _WORDS makes for publisher words, kept in one place per vocabulary.

    CVSS 0.0 is rated "None", a level §9.1 does not have. It bands to "unknown"
    rather than "low", because calling it low would invent a rating the
    publisher did not give.
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