
from datetime import datetime, timedelta, timezone

from openshield.db import connect


DEFAULT_TTL_DAYS = 90


def get_decision(package: str, version: str, project: str):
    """Return a valid saved decision, or None if none exists."""
    with connect() as conn:
        row = conn.execute(
            """
            SELECT decision, expires_at
            FROM decisions
            WHERE package = ? AND version = ? AND project = ?
            """,
            (package, version, project),
        ).fetchone()

    if row is None:
        return None

    # Rejections remain in effect until explicitly changed.
    if row["decision"] == "reject":
        return "reject"

    expires_at = row["expires_at"]
    if expires_at:
        expiry = datetime.fromisoformat(expires_at)
        if expiry <= datetime.now(timezone.utc):
            return None

    return row["decision"]


def save_decision(
    package: str,
    version: str,
    project: str,
    decision: str,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> None:
    """Save or replace a package decision."""
    if decision not in {"approve", "reject"}:
        raise ValueError("decision must be 'approve' or 'reject'")

    now = datetime.now(timezone.utc)
    expires_at = (
        (now + timedelta(days=ttl_days)).isoformat()
        if decision == "approve"
        else None
    )

    with connect() as conn:
        conn.execute(
            """
            INSERT INTO decisions
                (package, version, project, decision, decided_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(package, version, project)
            DO UPDATE SET
                decision = excluded.decision,
                decided_at = excluded.decided_at,
                expires_at = excluded.expires_at
            """,
            (
                package,
                version,
                project,
                decision,
                now.isoformat(),
                expires_at,
            ),
        )
