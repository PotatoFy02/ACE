import os
import logging
import jwt
from jwt import PyJWKClient
from fastapi import Header, HTTPException, Depends
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger("auth")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")

if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL not set")

# The public keys endpoint for verifying new-style (ES256/RS256) tokens
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
_jwk_client = PyJWKClient(JWKS_URL)


def decode_jwt(token: str) -> dict:
    # Read the token's header to see which algorithm it uses
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "")

    if alg == "HS256":
        # Old style: verify with the shared secret
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
        # New style (ES256/RS256): verify with public key from Supabase
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
