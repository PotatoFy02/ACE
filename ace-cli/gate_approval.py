"""
Checks Supabase for an approval record matching this commit SHA + role ARN.
Called by CI after red-risk is detected.
Exits 0 if approved, exits 1 if not approved (blocks merge).

Why a separate script: the GitHub Action needs a simple pass/fail signal.
A script with sys.exit() is cleaner than parsing JSON in bash.
"""

import asyncio
import os
import sys

import requests


# ── Supabase approval check (unchanged) ──────────────────────────────────────

def check_approval(commit_sha: str, role_arn: str) -> bool:
    url = os.environ["SUPABASE_URL"] + "/rest/v1/approvals"
    headers = {
        "apikey": os.environ["SUPABASE_SERVICE_KEY"],
        "Authorization": "Bearer " + os.environ["SUPABASE_SERVICE_KEY"],
    }
    params = {
        "commit_sha": f"eq.{commit_sha}",
        "role_arn":   f"eq.{role_arn}",
        "limit":      "1",
    }
    r = requests.get(url, headers=headers, params=params)
    r.raise_for_status()
    return len(r.json()) > 0


# ── Audit write (no-op if ACE_DATABASE_URL not set) ──────────────────────────

async def _log_approval_event(commit_sha: str, role_arn: str, approved: bool):
    from audit.store import log_event
    from audit.models import AuditEvent

    await log_event(AuditEvent(
        event_type="approved" if approved else "approval_denied",
        actor=os.environ.get("GITHUB_ACTOR", "ci"),
        metadata={
            "commit_sha": commit_sha,
            "role_arn":   role_arn,
        },
    ))


def _fire_approval_audit(commit_sha: str, role_arn: str, approved: bool):
    if not os.environ.get("ACE_DATABASE_URL"):
        return
    try:
        asyncio.run(_log_approval_event(commit_sha, role_arn, approved))
    except Exception as e:
        # Audit failure must never block CI gate
        print(f"[audit] WARNING: could not write approval event: {e}", file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python gate_approval.py <commit_sha> <role_arn>")
        sys.exit(1)

    commit_sha = sys.argv[1]
    role_arn   = sys.argv[2]

    approved = check_approval(commit_sha, role_arn)
    _fire_approval_audit(commit_sha, role_arn, approved)

    if approved:
        print(f"APPROVED: {role_arn} @ {commit_sha}")
        sys.exit(0)
    else:
        print(f"NOT APPROVED: No approval found for {role_arn} @ {commit_sha}")
        print("Post '/ace approve <commit_sha> <role_arn>' in the PR to approve.")
        sys.exit(1)