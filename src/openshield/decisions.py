"""Decision memory: lookup, record, revoke, audit."""
from __future__ import annotations

from datetime import datetime, timezone

from . import db
from .models import PackageRef, StoredDecision

GLOBAL = "__global__"

_COLUMNS = ("action, decided_at, scoring_version, trust_score, "
            "project_path, is_global")


def get_decision(ref: PackageRef, project: str, *,
                 ttl_days: int) -> StoredDecision | None:
    """The applicable prior decision for this package, or None.

    Only approvals expire; rejections apply indefinitely.
    """
    rows = [r for r in (_fetch(ref, project), _fetch(ref, GLOBAL)) if r]
    decisions = [StoredDecision(**dict(r)) for r in rows]

    # A rejection at either scope takes precedence over any approval.
    for decision in decisions:
        if decision.action == "reject":
            return decision

    for decision in decisions:
        if decision.age_days <= ttl_days:
            return decision
    return None


def _fetch(ref: PackageRef, project: str):
    with db.session() as conn:
        return conn.execute(
            f"SELECT {_COLUMNS} FROM decisions "
            "WHERE project_id=? AND ecosystem=? AND name=? AND version=?",
            (project, ref.ecosystem, ref.name, ref.version),
        ).fetchone()


def save_decision(ref: PackageRef, project: str, action: str, *,
                  trust_score: int | None = None,
                  scoring_version: str | None = None,
                  project_path: str | None = None,
                  is_global: bool = False) -> None:
    """Record the decision and its audit row in one transaction."""
    if action not in ("approve", "reject"):
        raise ValueError(f"action must be approve or reject, got {action!r}")

    now = datetime.now(timezone.utc).isoformat()
    with db.session() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO decisions (project_id, ecosystem, name, "
            "version, action, decided_at, scoring_version, trust_score, "
            "project_path, is_global) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (project, ref.ecosystem, ref.name, ref.version, action, now,
             scoring_version, trust_score, project_path, int(is_global)),
        )
        conn.execute(
            "INSERT INTO audit (at, event, project_id, identity, trust_score, "
            "scoring_version, detail) VALUES (?,?,?,?,?,?,?)",
            (now, action, project, ref.canonical, trust_score,
             scoring_version, None),
        )


def revoke(ref: PackageRef, project: str) -> bool:
    """Delete the decision and log the revocation. True if one existed."""
    now = datetime.now(timezone.utc).isoformat()
    with db.session() as conn:
        cursor = conn.execute(
            "DELETE FROM decisions WHERE project_id=? AND ecosystem=? "
            "AND name=? AND version=?",
            (project, ref.ecosystem, ref.name, ref.version),
        )
        conn.execute(
            "INSERT INTO audit (at, event, project_id, identity) "
            "VALUES (?,?,?,?)",
            (now, "revoke", project, ref.canonical),
        )
        return cursor.rowcount > 0


def audit(event: str, *, ref: PackageRef | None = None,
          project: str | None = None, detail: str | None = None) -> None:
    """Append to the audit log. Never raises, so logging cannot affect the
    outcome."""
    try:
        with db.session() as conn:
            conn.execute(
                "INSERT INTO audit (at, event, project_id, identity, detail) "
                "VALUES (?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), event, project,
                 ref.canonical if ref else None, detail),
            )
    except Exception:
        pass