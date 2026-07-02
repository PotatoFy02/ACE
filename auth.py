import os
import jwt
from fastapi import Header, HTTPException, Depends
from dotenv import load_dotenv

load_dotenv()
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
if not SUPABASE_JWT_SECRET:
    raise RuntimeError("SUPABASE_JWT_SECRET not set")


def decode_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        SUPABASE_JWT_SECRET,
        algorithms=["HS256"],
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
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token.")
    if not payload.get("sub"):
        raise HTTPException(401, "Invalid token subject.")
    return payload