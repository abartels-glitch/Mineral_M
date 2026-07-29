"""Password hashing, session cookies, and role/org authorization helpers.

Session model (pinned decision): server-side session, httpOnly cookie
holding a random token; only the token's SHA-256 hash is stored in the
`sessions` table. Roles are collapsed to three — org_user, buyer_auditor,
platform_admin — rather than the spec's literal four, since one pilot org
currently plays supplier/reviewer/manufacturer itself (see README).

Not production-hardened: no rate limiting on login, no password reset,
no HTTPS enforcement on the cookie (`secure=False` — fine for local dev
over http, must flip before any real deployment).
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, Request

from db import get_db

COOKIE_NAME = "session_token"
SESSION_TTL_DAYS = 7


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(conn, user_id: str) -> str:
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=SESSION_TTL_DAYS)
    conn.execute(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (uuid.uuid4().hex, user_id, _hash_token(raw_token), now.isoformat(), expires_at.isoformat()),
    )
    conn.commit()
    return raw_token


def delete_session(conn, raw_token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(raw_token),))
    conn.commit()


def get_session_user(conn, raw_token: str) -> dict | None:
    row = conn.execute(
        """
        SELECT users.id, users.org_id, users.email, users.role, sessions.expires_at
        FROM sessions JOIN users ON sessions.user_id = users.id
        WHERE sessions.token_hash = ?
        """,
        (_hash_token(raw_token),),
    ).fetchone()
    if row is None:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return None
    return dict(row)


def get_current_user(request: Request, conn=Depends(get_db)) -> dict:
    """FastAPI dependency: resolves the session cookie to a user or 401s.

    Takes `conn` via the same shared `db.get_db` dependency main.py's
    routes use, rather than opening its own connection — keeps this on
    one request-scoped connection and lets tests override `db.get_db`
    once to cover every route, including this one.
    """
    raw_token = request.cookies.get(COOKIE_NAME)
    if not raw_token:
        raise HTTPException(401, "not authenticated")
    user = get_session_user(conn, raw_token)
    if user is None:
        raise HTTPException(401, "session invalid or expired")
    return user


def require_role(user: dict, *roles: str) -> None:
    if user["role"] not in roles:
        raise HTTPException(403, f"requires role: {', '.join(roles)}")


def require_org_match(user: dict, org_id: str) -> None:
    # platform_admin and buyer_auditor are both legitimately cross-org
    # read roles — the callers that actually let buyer_auditor reach
    # this check (e.g. the audit-trail route) want that; document/review
    # routes never grant buyer_auditor access in the first place, since
    # require_role already excludes it there.
    if user["role"] in ("platform_admin", "buyer_auditor"):
        return
    if user["org_id"] != org_id:
        raise HTTPException(403, "not authorized for this organization")
