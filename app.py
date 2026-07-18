import os
import logging
from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Core Ingestion & Engine Imports
from github_import import fetch_iac_from_repo, GitHubImportError, verify_pat_scope
from generate import generate_threat_model, GenerationCapExceeded
from auth import verify_token, get_bearer, try_decode, is_owner, require_role, ROLE_RANK, _admin
from validators import validate_description, validate_name
from iac_parser import parse_iac
from db import (save_threat_model, list_projects, get_project, delete_project,
                count_projects, update_threat_status, update_remediation, project_stats)
from pdf import build_pdf

# Logging Setup
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

# Environment Configurations
FREE_PROJECT_LIMIT = int(os.getenv("FREE_PROJECT_LIMIT", "3"))
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
MAX_BODY = 25000
MAX_UPLOAD = 120000
ALLOWED_EXT = (".tf", ".hcl", ".yaml", ".yml", ".json", ".txt")

# JWT/User Aware Rate Limiter Key Generation
def rate_key(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        payload = try_decode(auth.split(" ", 1)[1].strip())
        if payload and payload.get("sub"):
            return f"user:{payload['sub']}"
    return get_remote_address(request)


def _request_is_owner(request: Request) -> bool:
    """Used as slowapi's exempt_when - runs the same JWT decode already
    happening in rate_key, so this costs nothing extra per request."""
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return False
    payload = try_decode(auth.split(" ", 1)[1].strip())
    return bool(payload) and is_owner(payload)

limiter = Limiter(key_func=rate_key)
app = FastAPI(title="ACE", version="2.4.0")
app.state.limiter = limiter
verify_pat_scope()

# Global Exceptions Handlers
@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request, exc):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try later."})

# CORS Middleware Configurations
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# HTTP Security Hardening Middleware
@app.middleware("http")
async def hardening(request: Request, call_next):
    cl = request.headers.get("content-length")
    ctype = request.headers.get("content-type", "")
    limit = MAX_UPLOAD if ctype.startswith("multipart/form-data") else MAX_BODY

    if cl and cl.isdigit() and int(cl) > limit:
        return Response("Payload too large", status_code=413)

    resp = await call_next(request)

    # Secure Headers Injections
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' https://*.supabase.co; "
        "frame-ancestors 'none'"
    )
    return resp

# --- Pydantic Data Verification Models ---
class GenerateRequest(BaseModel):
    name: str = Field("Untitled", max_length=200)
    architecture_description: str = Field(..., max_length=8000)

class GithubImportRequest(BaseModel):
    name: str = Field("Untitled", max_length=200)
    repo_url: str = Field(..., max_length=300)

class StatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(pending|accepted|rejected)$")

class RemediationUpdate(BaseModel):
    status: str = Field(..., pattern="^(not_started|in_progress|resolved)$")

class RoleUpdateRequest(BaseModel):
    role: str

# --- Core API Routes Definitions ---

@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/demo")
@limiter.limit("3/hour")
def demo(request: Request, req: GenerateRequest):
    desc = validate_description(req.architecture_description)
    try:
        return {"threat_model": generate_threat_model(desc)}
    except GenerationCapExceeded:
        raise HTTPException(429, "Service is at capacity today. Please try again later.")
    except ValueError:
        raise HTTPException(502, "AI could not produce a valid result. Try rephrasing.")
    except Exception:
        log.exception("demo failed")
        raise HTTPException(500, "Internal error. Please try again.")

@app.post("/api/generate")
@limiter.limit("20/hour", exempt_when=_request_is_owner)
def generate(request: Request, req: GenerateRequest,
             user=Depends(verify_token), jwt=Depends(get_bearer)):
    desc = validate_description(req.architecture_description)
    name = validate_name(req.name)
    try:
        if not _request_is_owner(request) and count_projects(jwt) >= FREE_PROJECT_LIMIT:
            raise HTTPException(402, f"Free limit reached ({FREE_PROJECT_LIMIT}). Upgrade to save more.")
        model = generate_threat_model(desc)
        pid = save_threat_model(jwt, user["sub"], name, desc, model)
        return {"project_id": pid, "threat_model": model}
    except HTTPException:
        raise
    except GenerationCapExceeded:
        raise HTTPException(429, "Service is at capacity today. Please try again later.")
    except ValueError:
        raise HTTPException(502, "AI could not produce a valid result. Try rephrasing.")
    except Exception:
        log.exception("generate failed")
        raise HTTPException(500, "Internal error. Please try again.")

@app.post("/api/generate-from-file")
@limiter.limit("20/hour", exempt_when=_request_is_owner)
async def generate_from_file(request: Request, file: UploadFile = File(...),
                             name: str = "Untitled",
                             user=Depends(verify_token), jwt=Depends(get_bearer)):
    fname = (file.filename or "config")[:100]
    lower = fname.lower()
    if not (lower == "dockerfile" or lower.endswith("dockerfile")
            or any(lower.endswith(e) for e in ALLOWED_EXT)):
        raise HTTPException(400, "Unsupported file type. Allowed: .tf, .hcl, .yaml, .yml, .json, .txt, Dockerfile")

    raw = await file.read()
    if len(raw) > 100000:
        raise HTTPException(413, "File too large (max 100KB).")
    if not raw:
        raise HTTPException(400, "Empty file.")

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be UTF-8 text.")

    content = "".join(ch for ch in content if ch in ("\n", "\t") or ord(ch) >= 32)
    desc = validate_description(parse_iac(fname, content))

    try:
        if not _request_is_owner(request) and count_projects(jwt) >= FREE_PROJECT_LIMIT:
            raise HTTPException(402, f"Free limit reached ({FREE_PROJECT_LIMIT}). Upgrade.")
        model = generate_threat_model(desc)
        pid = save_threat_model(jwt, user["sub"], validate_name(name), desc, model)
        return {"project_id": pid, "threat_model": model, "parsed_description": desc}
    except HTTPException:
        raise
    except GenerationCapExceeded:
        raise HTTPException(429, "Service is at capacity today. Please try again later.")
    except ValueError:
        raise HTTPException(502, "AI could not analyze this file. Try a manual description.")
    except Exception:
        log.exception("file generate failed")
        raise HTTPException(500, "Internal error.")

@app.post("/api/generate-from-github")
@limiter.limit("10/hour", exempt_when=_request_is_owner)
def generate_from_github(request: Request, req: GithubImportRequest,
                         user=Depends(verify_token), jwt=Depends(get_bearer)):
    try:
        desc = validate_description(fetch_iac_from_repo(req.repo_url, parse_iac))
    except GitHubImportError as e:
        raise HTTPException(400, str(e))

    try:
        if not _request_is_owner(request) and count_projects(jwt) >= FREE_PROJECT_LIMIT:
            raise HTTPException(402, f"Free limit reached ({FREE_PROJECT_LIMIT}). Upgrade to save more.")
        model = generate_threat_model(desc)
        pid = save_threat_model(jwt, user["sub"], validate_name(req.name), desc, model)
        return {"project_id": pid, "threat_model": model, "parsed_description": desc}
    except HTTPException:
        raise
    except GenerationCapExceeded:
        raise HTTPException(429, "Service is at capacity today. Please try again later.")
    except ValueError:
        raise HTTPException(502, "AI could not analyze this repository. Try a manual description.")
    except Exception:
        log.exception("github generate failed")
        raise HTTPException(500, "Internal error.")

@app.get("/api/projects")
@limiter.limit("60/minute")
def projects(request: Request, user=Depends(verify_token), jwt=Depends(get_bearer)):
    try:
        return list_projects(jwt)
    except Exception:
        log.exception("list failed")
        raise HTTPException(500, "Internal error.")

@app.get("/api/projects/{pid}")
@limiter.limit("60/minute")
def project(request: Request, pid: str, user=Depends(verify_token), jwt=Depends(get_bearer)):
    data = get_project(jwt, pid)
    if not data["project"]:
        raise HTTPException(404, "Not found.")
    return data

@app.get("/api/projects/{pid}/stats")
@limiter.limit("120/minute")
def stats(request: Request, pid: str, user=Depends(verify_token), jwt=Depends(get_bearer)):
    try:
        return project_stats(jwt, pid)
    except Exception:
        log.exception("stats failed")
        raise HTTPException(500, "Internal error.")

@app.get("/api/projects/{pid}/pdf")
@limiter.limit("30/minute")
def export_pdf(request: Request, pid: str, user=Depends(verify_token), jwt=Depends(get_bearer)):
    data = get_project(jwt, pid)
    if not data["project"]:
        raise HTTPException(404, "Not found.")
    model_json = {"system_summary": data["project"].get("system_summary", ""),
                  "threats": data["threats"]}
    try:
        pdf = build_pdf(data["project"]["name"], model_json)
    except Exception:
        log.exception("pdf failed")
        raise HTTPException(500, "Could not generate PDF.")
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="audit-threat-model.pdf"'})

@app.patch("/api/threats/{tid}/status")
@limiter.limit("120/minute")
def set_status(request: Request, tid: str, body: StatusUpdate,
               user=Depends(verify_token), jwt=Depends(get_bearer)):
    try:
        update_threat_status(jwt, user["sub"], tid, body.status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("status failed")
        raise HTTPException(500, "Internal error.")
    return {"ok": True}

@app.patch("/api/threats/{tid}/remediation")
@limiter.limit("120/minute")
def set_remediation(request: Request, tid: str, body: RemediationUpdate,
                    user=Depends(verify_token), jwt=Depends(get_bearer)):
    try:
        update_remediation(jwt, user["sub"], tid, body.status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("remediation failed")
        raise HTTPException(500, "Internal error.")
    return {"ok": True}

@app.delete("/api/projects/{pid}")
@limiter.limit("30/minute")
def remove(request: Request, pid: str, user=Depends(verify_token), jwt=Depends(get_bearer)):
    try:
        delete_project(jwt, user["sub"], pid)
    except Exception:
        log.exception("delete failed")
        raise HTTPException(500, "Internal error.")
    return {"deleted": pid}

@app.post("/api/admin/roles/{target_user_id}")
@limiter.limit("30/hour")
def set_user_role(request: Request, target_user_id: str, body: RoleUpdateRequest,
                   _requester_role: str = Depends(require_role("owner"))):
    if body.role not in ROLE_RANK:
        raise HTTPException(400, f"Invalid role. Must be one of {list(ROLE_RANK)}")
    _admin().table("profiles").update({"role": body.role}).eq("id", target_user_id).execute()
    return {"status": "updated", "target_user_id": target_user_id, "role": body.role}

# Fallback Routing for Client Static Assets (Must be mounted last)
app.mount("/", StaticFiles(directory="static", html=True), name="static")