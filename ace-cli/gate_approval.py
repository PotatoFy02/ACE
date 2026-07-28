"""
Checks Supabase for an approval record matching this commit SHA + role ARN.
Called by CI after red-risk is detected.
Exits 0 if approved, exits 1 if not approved (blocks merge).

Why a separate script: the GitHub Action needs a simple pass/fail signal.
A script with sys.exit() is cleaner than parsing JSON in bash.
"""

import sys
import os
import requests


def check_approval(commit_sha: str, role_arn: str) -> bool:
    url = os.environ["SUPABASE_URL"] + "/rest/v1/approvals"
    headers = {
        "apikey": os.environ["SUPABASE_SERVICE_KEY"],
        "Authorization": "Bearer " + os.environ["SUPABASE_SERVICE_KEY"],
    }
    params = {
        "commit_sha": f"eq.{commit_sha}",
        "role_arn": f"eq.{role_arn}",
        "limit": "1",
    }
    r = requests.get(url, headers=headers, params=params)
    r.raise_for_status()
    return len(r.json()) > 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python gate_approval.py <commit_sha> <role_arn>")
        sys.exit(1)

    commit_sha = sys.argv[1]
    role_arn = sys.argv[2]

    if check_approval(commit_sha, role_arn):
        print(f"APPROVED: {role_arn} @ {commit_sha}")
        sys.exit(0)
    else:
        print(f"NOT APPROVED: No approval found for {role_arn} @ {commit_sha}")
        print("Post '/ace approve <commit_sha> <role_arn>' in the PR to approve.")
        sys.exit(1)