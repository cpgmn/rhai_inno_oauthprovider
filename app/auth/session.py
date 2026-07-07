"""Session management using cookies.

Sessions track authenticated users during the authorization flow.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from app.db.session import SessionLocal


SESSION_TTL_SECONDS = 3600


def _now_utc() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)

def _normalize_dt(value: Any) -> datetime:
    """Normalize DB datetime values to timezone-aware UTC."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    raise ValueError("Invalid datetime value from session store")


def create_session(user_id: int) -> str:
    """Create a new user session.

    Args:
        user_id: The authenticated user's ID.

    Returns:
        Session ID (opaque string).
    """
    session_id = secrets.token_urlsafe(32)
    expires_at = _now_utc() + timedelta(seconds=SESSION_TTL_SECONDS)

    with SessionLocal() as db:
        db.execute(
            text(
                """
                INSERT INTO user_sessions (session_id, user_id, expires_at, last_seen_at)
                VALUES (:session_id, :user_id, :expires_at, NOW())
                """
            ),
            {
                "session_id": session_id,
                "user_id": user_id,
                "expires_at": expires_at,
            },
        )
        db.commit()

    return session_id


def get_session(session_id: str) -> dict | None:
    """Retrieve session data by ID.

    Args:
        session_id: The session ID to look up.

    Returns:
        Session dictionary with 'user_id' and 'expires_at',
        or None if session is not found or has expired.
    """
    if not session_id:
        return None

    with SessionLocal() as db:
        row = db.execute(
            text(
                """
                SELECT user_id, expires_at, invalidated_at
                FROM user_sessions
                WHERE session_id = :session_id
                LIMIT 1
                """
            ),
            {"session_id": session_id},
        ).mappings().first()

        if not row:
            return None

        expires_at = _normalize_dt(row["expires_at"])
        invalidated_at = row["invalidated_at"]

        if invalidated_at is not None or _now_utc() > expires_at:
            db.execute(
                text("DELETE FROM user_sessions WHERE session_id = :session_id"),
                {"session_id": session_id},
            )
            db.commit()
            return None

        db.execute(
            text(
                """
                UPDATE user_sessions
                SET last_seen_at = NOW()
                WHERE session_id = :session_id
                """
            ),
            {"session_id": session_id},
        )
        db.commit()

        return {
            "user_id": row["user_id"],
            "expires_at": expires_at,
        }


def delete_session(session_id: str) -> None:
    """Delete a session (logout).

    Args:
        session_id: The session ID to delete.
    """
    if not session_id:
        return None

    with SessionLocal() as db:
        db.execute(
            text(
                """
                UPDATE user_sessions
                SET invalidated_at = NOW(), expires_at = NOW()
                WHERE session_id = :session_id
                """
            ),
            {"session_id": session_id},
        )
        db.commit()
