# -*- coding: utf-8 -*-
# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE - Automated Cybersecurity Engine
"""
webhook.py - GitHub PR comment webhook handler and Slack interactions handler.
"""

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from supabase import create_client

log = logging.getLogger("webhook")

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
SLACK_SIGNING_SECRET  = os.environ.get("SLACK_SIGNING_SECRET", "")
AUTHORIZED_APPROVERS  = set(
    filter(None, os.environ.get("AUTHORIZED_APPROVERS", "").split(","))
)
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "")  # e.g. PotatoFy02/ACE


def _service_client():
    url = os.environ.get("SUPABASE_URL", "")
    key = os.environ.get("SUPABASE_SERVICE_KEY", "")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL or SUPABASE_SERVICE_KEY not set")
    return create_client(url, key)


def _verify_signature(payload: bytes, sig_header: str) -> bool:
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    actual = sig_header[len("sha256="):]
    return hmac.compare_digest(expected, actual)


def _verify_slack_signature(payload: bytes, timestamp: str, signature: str) -> bool:
    if not SLACK_SIGNING_SECRET:
        return False
    if not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except ValueError:
        return False
    base = f"v0:{timestamp}:{payload.decode()}"
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        base.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _reject_replay(delivery_id: str) -> None:
    try:
        _service_client().table("webhook_deliveries").insert(
            {"delivery_id": delivery_id}
        ).execute()
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            log.info(f"Replay rejected: delivery {delivery_id} already processed")
            raise HTTPException(status_code=200, detail="already_processed")
        raise


async def _open_reduction_pr(role_arn: str) -> str | None:
    """
    Opens a GitHub PR to reduce permissions for the given IAM role ARN.
    Returns the PR URL on success, None on failure.
    """
    if not GITHUB_TOKEN or not GITHUB_REPO:
        log.error("GITHUB_TOKEN or GITHUB_REPO not set — cannot open PR")
        return None

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Sanitize ARN into a valid branch name
    safe_arn = (
        role_arn.replace(":", "-")
                .replace("/", "-")
                .replace("_", "-")
                .lower()
    )
    branch_name = f"ace/reduce-{safe_arn}"[:100]

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # 1. Get default branch SHA
            repo_resp = await client.get(
                f"https://api.github.com/repos/{GITHUB_REPO}",
                headers=headers,
            )
            repo_resp.raise_for_status()
            default_branch = repo_resp.json()["default_branch"]

            ref_resp = await client.get(
                f"https://api.github.com/repos/{GITHUB_REPO}/git/ref/heads/{default_branch}",
                headers=headers,
            )
            ref_resp.raise_for_status()
            base_sha = ref_resp.json()["object"]["sha"]

            # 2. Create branch (422 = already exists, that's fine)
            branch_resp = await client.post(
                f"https://api.github.com/repos/{GITHUB_REPO}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            )
            if branch_resp.status_code not in (201, 422):
                branch_resp.raise_for_status()

            # 3. Open PR
            pr_resp = await client.post(
                f"https://api.github.com/repos/{GITHUB_REPO}/pulls",
                headers=headers,
                json={
                    "title": f"ACE: Reduce permissions for {role_arn}",
                    "body": (
                        f"Automatically opened by ACE Sweeper after Slack approval.\n\n"
                        f"**Role ARN:** `{role_arn}`\n"
                        f"**Action:** Reduce to least-privilege based on last-used activity.\n\n"
                        f"Review and merge to complete the remediation."
                    ),
                    "head": branch_name,
                    "base": default_branch,
                },
            )

            # 422 = PR already exists for this branch
            if pr_resp.status_code == 422:
                existing = await client.get(
                    f"https://api.github.com/repos/{GITHUB_REPO}/pulls",
                    headers=headers,
                    params={
                        "head": f"{GITHUB_REPO.split('/')[0]}:{branch_name}",
                        "state": "open",
                    },
                )
                prs = existing.json()
                return prs[0]["html_url"] if prs else None

            pr_resp.raise_for_status()
            return pr_resp.json()["html_url"]

    except Exception as e:
        log.error(f"_open_reduction_pr failed for {role_arn}: {e}", exc_info=True)
        return None


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
    x_github_delivery: str = Header(None),
):
    payload = await request.body()

    if not _verify_signature(payload, x_hub_signature_256 or ""):
        raise HTTPException(status_code=401, detail="Invalid signature")

    if x_github_delivery:
        _reject_replay(x_github_delivery)

    if x_github_event != "issue_comment":
        return {"status": "ignored", "event": x_github_event}

    data = await request.json()

    if data.get("action") != "created":
        return {"status": "ignored", "action": data.get("action")}

    comment_body = data.get("comment", {}).get("body", "").strip()

    if not comment_body.lower().startswith("/ace approve"):
        return {"status": "ignored", "reason": "not an ace approve comment"}

    commenter = data.get("comment", {}).get("user", {}).get("login", "")
    if commenter not in AUTHORIZED_APPROVERS:
        log.warning(f"Unauthorized approval attempt by {commenter}")
        raise HTTPException(
            status_code=403,
            detail=f"{commenter} is not an authorized approver"
        )

    parts = comment_body.split()
    if len(parts) < 4:
        raise HTTPException(
            status_code=400,
            detail="Format: /ace approve <commit_sha> <role_arn>"
        )

    commit_sha   = parts[2]
    role_arn     = parts[3]
    pr_number    = data.get("issue", {}).get("number")
    repo         = data.get("repository", {}).get("full_name", "")
    commenter_id = str(data.get("comment", {}).get("user", {}).get("id", ""))

    try:
        _service_client().table("approvals").insert({
            "commit_sha":            commit_sha,
            "role_arn":              role_arn,
            "approver_github_login": commenter,
            "approver_github_id":    commenter_id,
            "pr_number":             pr_number,
            "repo":                  repo,
        }).execute()
        log.info(f"Approval recorded: {commenter} (id={commenter_id}) approved {role_arn} @ {commit_sha}")
    except Exception as e:
        if "unique" in str(e).lower():
            return {"status": "already_approved"}
        log.error(f"Supabase insert failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to record approval")

    return {
        "status":      "approved",
        "commit_sha":  commit_sha,
        "role_arn":    role_arn,
        "approver":    commenter,
        "approver_id": commenter_id,
    }


@router.post("/slack/interactions")
async def slack_interactions(
    request: Request,
    x_slack_request_timestamp: str = Header(None),
    x_slack_signature: str = Header(None),
):
    payload = await request.body()

    if not _verify_slack_signature(
        payload,
        x_slack_request_timestamp or "",
        x_slack_signature or ""
    ):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")

    form = urllib.parse.parse_qs(payload.decode())
    raw  = form.get("payload", ["{}"])[0]
    data = json.loads(raw)

    action_id = data.get("actions", [{}])[0].get("action_id", "")
    role_arn  = data.get("actions", [{}])[0].get("value", "")
    user      = data.get("user", {}).get("name", "unknown")

    log.info(f"Slack interaction: {action_id} on {role_arn} by {user}")

    if action_id == "ace_ignore_role":
        try:
            _service_client().table("sweeper_roles").update({
                "ignore_dormancy": True,
                "ignore_reason":   f"Ignored via Slack by {user}",
            }).eq("role_arn", role_arn).execute()
            log.info(f"Role {role_arn} marked ignore_dormancy by {user}")
        except Exception as e:
            log.error(f"Failed to ignore role {role_arn}: {e}")
            raise HTTPException(status_code=500, detail="Failed to update role")

    elif action_id == "ace_approve_role":
        try:
            _service_client().table("sweeper_roles").update({
                "state": "PR_OPEN",
            }).eq("role_arn", role_arn).execute()
            log.info(f"Role {role_arn} state set to PR_OPEN by {user}")
        except Exception as e:
            log.error(f"Failed to update role state {role_arn}: {e}")
            raise HTTPException(status_code=500, detail="Failed to update role")

        pr_url = await _open_reduction_pr(role_arn)

        if pr_url:
            try:
                _service_client().table("sweeper_roles").update({
                    "pr_url": pr_url,
                }).eq("role_arn", role_arn).execute()
                log.info(f"PR opened for {role_arn}: {pr_url}")
            except Exception as e:
                log.error(f"Failed to save pr_url for {role_arn}: {e}")

            return {"text": f"✅ Approved. PR opened: {pr_url}"}
        else:
            log.error(f"PR creation failed for {role_arn}")
            return {"text": f"✅ Approved. State updated to PR_OPEN but PR creation failed — check logs."}

    return {"text": f"Action `{action_id}` recorded for `{role_arn}` by {user}."}