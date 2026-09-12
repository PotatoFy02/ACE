# github_utils.py - Shared GitHub utility functions
import logging
import os
import httpx

log = logging.getLogger("github_utils")


async def open_reduction_pr(role_arn: str) -> str | None:
    """
    Opens a GitHub PR to reduce permissions for the given IAM role ARN.
    Returns the PR URL on success, None on failure.
    """
    github_token = os.environ.get("GITHUB_TOKEN", "")
    github_repo = os.environ.get("GITHUB_REPO", "")

    if not github_token or not github_repo:
        log.error("GITHUB_TOKEN or GITHUB_REPO not set — cannot open PR")
        return None

    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    safe_arn = (
        role_arn.replace(":", "-")
                .replace("/", "-")
                .replace("_", "-")
                .lower()
    )
    branch_name = f"ace/reduce-{safe_arn}"[:100]

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            repo_resp = await client.get(
                f"https://api.github.com/repos/{github_repo}",
                headers=headers,
            )
            repo_resp.raise_for_status()
            default_branch = repo_resp.json()["default_branch"]

            ref_resp = await client.get(
                f"https://api.github.com/repos/{github_repo}/git/ref/heads/{default_branch}",
                headers=headers,
            )
            ref_resp.raise_for_status()
            base_sha = ref_resp.json()["object"]["sha"]

            branch_resp = await client.post(
                f"https://api.github.com/repos/{github_repo}/git/refs",
                headers=headers,
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            )
            if branch_resp.status_code not in (201, 422):
                branch_resp.raise_for_status()

            pr_resp = await client.post(
                f"https://api.github.com/repos/{github_repo}/pulls",
                headers=headers,
                json={
                    "title": f"ACE: Reduce permissions for {role_arn}",
                    "body": (
                        f"Automatically opened by ACE after in-app approval.\n\n"
                        f"**Role ARN:** `{role_arn}`\n"
                        f"**Action:** Reduce to least-privilege based on last-used activity.\n\n"
                        f"Review and merge to complete the remediation."
                    ),
                    "head": branch_name,
                    "base": default_branch,
                },
            )

            if pr_resp.status_code == 422:
                existing = await client.get(
                    f"https://api.github.com/repos/{github_repo}/pulls",
                    headers=headers,
                    params={
                        "head": f"{github_repo.split('/')[0]}:{branch_name}",
                        "state": "open",
                    },
                )
                prs = existing.json()
                return prs[0]["html_url"] if prs else None

            pr_resp.raise_for_status()
            return pr_resp.json()["html_url"]

    except Exception as e:
        log.error(f"open_reduction_pr failed for {role_arn}: {e}", exc_info=True)
        return None