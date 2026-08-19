import os
import logging
import jwt
from jwt import PyJWKClient
from fastapi import Header, HTTPException, Depends
from dotenv import load_dotenv
from supabase import create_client, Client
from typing import Any

load_dotenv()

log = logging.getLogger("auth")

SUPABASE_URL: str = os.getenv("SUPABASE_URL") or ""
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

OWNER_EMAILS = {
    e.strip().lower()
    for e in os.getenv("OWNER_EMAILS", "").split(",")
    if e.strip()
}

OWNER_USER_IDS = {
    uid.strip()
    for uid in os.getenv("OWNER_USER_IDS", "").split(",")
    if uid.strip()
}

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL not set")

JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
_jwk_client = PyJWKClient(JWKS_URL)

ROLE_RANK = {"viewer": 0, "member": 1, "admin": 2, "owner": 3}

_admin_client: Client | None = None


def _admin() -> Client:
    """Service-role client. Bypasses RLS entirely - used ONLY for role
    reads/writes. Never import this into db.py or any other business
    logic; everything else stays on the least-privilege anon+JWT pattern
    the rest of the app already uses."""
    global _admin_client
    if _admin_client is None:
        if not SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY not set")
        _admin_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _admin_client


def decode_jwt(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "")

    if alg == "HS256":
        if not SUPABASE_JWT_SECRET:
            raise jwt.InvalidTokenError("HS256 token but no secret configured")
        return jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated",
            options={"require": ["exp", "sub"]},
        )
    else:
        signing_key = _jwk_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256", "RS256"],
            audience="authenticated",
            options={"require": ["exp", "sub"]},
        )


def try_decode(token: str):
    try:
        return decode_jwt(token)
    except Exception:
        return None


def get_bearer(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header.")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(401, "Empty token.")
    return token


def verify_token(token: str = Depends(get_bearer)) -> dict:
    try:
        payload = decode_jwt(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired.")
    except Exception as e:
        log.warning("JWT verification failed: %r", e)
        raise HTTPException(401, "Invalid token.")
    if not payload.get("sub"):
        raise HTTPException(401, "Invalid token subject.")
    return payload


def is_owner(payload: dict) -> bool:
    """Fast-path check against OWNER_EMAILS and OWNER_USER_IDS.
    Used for rate-limit exemption and project limit bypass.
    NOTE: Supabase ES256 JWTs may not include email — always check sub too."""
    email = (payload or {}).get("email", "")
    sub = (payload or {}).get("sub", "")
    return (
        (bool(email) and email.strip().lower() in OWNER_EMAILS) or
        (bool(sub) and sub in OWNER_USER_IDS)
    )


def get_user_role(user_id: str, email: str) -> str:
    """Looks up (and lazily bootstraps) a user's role. Always reads from
    the DB via the service-role client - never trusts a role claim from
    the client itself."""
    res = _admin().table("profiles").select("role").eq("id", user_id).execute()
    data: list[dict[str, Any]] = res.data or []  # type: ignore[assignment]
    if data:
        return str(data[0].get("role", "member"))

    role = "owner" if email.strip().lower() in OWNER_EMAILS else "member"
    _admin().table("profiles").insert({
        "id": user_id, "email": email, "role": role, "granted_by": None,
    }).execute()
    return role


def require_role(minimum: str):
    """FastAPI dependency factory. Usage: Depends(require_role('admin'))"""
    def _dep(user: dict = Depends(verify_token)):
        role = get_user_role(user["sub"], user.get("email", ""))
        if ROLE_RANK.get(role, -1) < ROLE_RANK[minimum]:
            raise HTTPException(403, f"Requires {minimum} role or higher.")
        return role
    return _dep