"""
webhook.py — GitHub PR comment webhook handler.
Receives /ace approve <commit_sha> <role_arn> comments,
verifies HMAC signature, rejects replays, writes approval to Supabase.
"""

import hashlib
import hmac
import os
import logging
from fastapi import APIRouter, Request, HTTPException, Header
from supabase import create_client

log = logging.getLogger("webhook")

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
AUTHORIZED_APPROVERS = set(
    filter(None, os.environ.get("AUTHORIZED_APPROVERS", "").split(","))
)


def _service_client():
    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_SERVICE_KEY", "")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL or SUPABASE_SERVICE_KEY not set")
    return create_client(url, key)


def _verify_signature(payload: bytes, sig_header: str) -> bool:
    """
    Proves request is from GitHub, not a random POST.
    GitHub signs the payload with your secret using HMAC-SHA256.
    compare_digest prevents timing attacks.
    """
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    actual = sig_header[len("sha256="):]
    return hmac.compare_digest(expected, actual)


def _reject_replay(delivery_id: str) -> None:
    """
    Idempotency guard — GitHub retries failed webhooks with the same
    X-GitHub-Delivery ID. Without this check, a network blip or a slow
    Supabase write causes the same approval to be recorded twice, producing
    duplicate approver rows in the PDF.

    Strategy: attempt to INSERT the delivery_id. If it already exists
    (unique constraint violation), the delivery is a replay — raise 200
    so GitHub stops retrying without treating it as an error.
    """
    try:
        _service_client().table("webhook_deliveries").insert(
            {"delivery_id": delivery_id}
        ).execute()
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            log.info(f"Replay rejected: delivery {delivery_id} already processed")
            raise HTTPException(status_code=200, detail="already_processed")
        # Non-duplicate error — let it propagate
        raise


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
    x_github_delivery: str = Header(None),
):
    payload = await request.body()

    # Reject anything not signed by GitHub
    if not _verify_signature(payload, x_hub_signature_256 or ""):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Reject replay deliveries before doing any work
    if x_github_delivery:
        _reject_replay(x_github_delivery)

    # Only handle PR comments
    if x_github_event != "issue_comment":
        return {"status": "ignored", "event": x_github_event}

    data = await request.json()

    # Only act on created comments, not edits/deletes
    if data.get("action") != "created":
        return {"status": "ignored", "action": data.get("action")}

    comment_body = data.get("comment", {}).get("body", "").strip()

    # Only act on /ace approve commands
    if not comment_body.lower().startswith("/ace approve"):
        return {"status": "ignored", "reason": "not an ace approve comment"}

    # Check commenter is authorized
    commenter = data.get("comment", {}).get("user", {}).get("login", "")
    if commenter not in AUTHORIZED_APPROVERS:
        log.warning(f"Unauthorized approval attempt by {commenter}")
        raise HTTPException(
            status_code=403,
            detail=f"{commenter} is not an authorized approver"
        )

    # Parse: /ace approve <commit_sha> <role_arn>
    parts = comment_body.split()
    if len(parts) < 4:
        raise HTTPException(
            status_code=400,
            detail="Format: /ace approve <commit_sha> <role_arn>"
        )

    commit_sha = parts[2]
    role_arn = parts[3]
    pr_number = data.get("issue", {}).get("number")
    repo = data.get("repository", {}).get("full_name", "")

    # Write approval to Supabase using service role key
    try:
        _service_client().table("approvals").insert({
            "commit_sha": commit_sha,
            "role_arn": role_arn,
            "approver_github_login": commenter,
            "pr_number": pr_number,
            "repo": repo,
        }).execute()
        log.info(f"Approval recorded: {commenter} approved {role_arn} @ {commit_sha}")
    except Exception as e:
        if "unique" in str(e).lower():
            return {"status": "already_approved"}
        log.error(f"Supabase insert failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to record approval")

    return {
        "status": "approved",
        "commit_sha": commit_sha,
        "role_arn": role_arn,
        "approver": commenter,
    }