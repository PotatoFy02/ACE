"""
sweeper/engine.py — state machine orchestrator.
Drives role lifecycle: ACTIVE → PENDING_REDUCTION → REDUCTION_READY → PR_OPEN.
Never opens PRs directly — returns REDUCTION_READY roles for CLI to handle.
Never touches AWS IAM directly — always generates a PR against .tf files.
"""

import logging
from datetime import datetime, timezone

from sweeper.db import (
    upsert_role, get_role, transition,
    get_pending_roles_past_cooling_off, get_roles_by_state
)
from sweeper.notifier import notify_pending_reduction, notify_pr_opened

log = logging.getLogger("sweeper.engine")


def process_role(
    role_arn: str,
    role_name: str,
    repo: str,
    tf_file_path: str,
    owner_slack_id: str | None,
    excess_actions: list[str],
    ignore_dormancy: bool,
    boto3_session,
) -> str:
    """
    Main entry point per role.
    Returns the role's current state after processing.
    """
    upsert_role(
        role_arn=role_arn,
        role_name=role_name,
        repo=repo,
        tf_file_path=tf_file_path,
        owner_slack_id=owner_slack_id,
        ignore_dormancy=ignore_dormancy,
    )

    role = get_role(role_arn)

    if role is None:
        log.error(f"get_role returned None for {role_arn} immediately after upsert — DB write failed")
        return "ACTIVE"

    if ignore_dormancy:
        log.info(f"SKIP {role_arn} — ACE_Dormancy_Ignore=true")
        return "ACTIVE"

    if role["state"] == "PR_OPEN":
        log.info(f"SKIP {role_arn} — PR already open")
        return "PR_OPEN"

    from sweeper.iam_checker import check_role_dormancy
    is_dormant, last_used_at = check_role_dormancy(role_arn, boto3_session)

    now = datetime.now(timezone.utc).isoformat()

    if not is_dormant:
        if role["state"] == "PENDING_REDUCTION":
            transition(
                role_arn=role_arn,
                to_state="ACTIVE",
                reason="Activity detected during cooling-off period — false alarm",
                extra_fields={"last_activity_at": now, "dormancy_detected_at": None},
            )
            log.info(f"RESET {role_arn} — activity detected, back to ACTIVE")
        return "ACTIVE"

    if role["state"] == "ACTIVE":
        transition(
            role_arn=role_arn,
            to_state="PENDING_REDUCTION",
            reason=f"No IAM activity detected in 90 days. Last used: {last_used_at}",
            extra_fields={
                "dormancy_detected_at": now,
                "iam_last_used_at": last_used_at.isoformat() if last_used_at else None,
            },
        )
        notify_pending_reduction(
            role_arn=role_arn,
            role_name=role_name,
            owner_slack_id=owner_slack_id,
            repo=repo,
            excess_actions=excess_actions,
        )
        log.info(f"PENDING {role_arn} — 14-day clock started, owner notified via Slack")
        return "PENDING_REDUCTION"

    if role["state"] in ("PENDING_REDUCTION", "REDUCTION_READY"):
        log.info(f"WAITING {role_arn} — state={role['state']}, cooling-off in progress")
        return role["state"]

    return role["state"]


def advance_cooling_off() -> list[dict]:
    """
    Called once per sweep run.
    Finds all PENDING_REDUCTION roles past 14 days and advances them to REDUCTION_READY.
    Returns list of roles now ready for PR generation.
    """
    ready = get_pending_roles_past_cooling_off()

    for role in ready:
        transition(
            role_arn=role["role_arn"],
            to_state="REDUCTION_READY",
            reason="14-day cooling-off period elapsed with no activity detected",
            extra_fields={"reduction_ready_at": datetime.now(timezone.utc).isoformat()},
        )
        log.info(f"READY {role['role_arn']} — 14 days elapsed, ready for PR")

    return ready


def mark_pr_open(role_arn: str, pr_url: str, pr_number: int, commit_sha: str = "") -> None:
    """Called after CLI opens a PR for a REDUCTION_READY role."""
    role = get_role(role_arn)
    if role is None:
        log.error(f"mark_pr_open: get_role returned None for {role_arn} — skipping notify")
        transition(
            role_arn=role_arn,
            to_state="PR_OPEN",
            reason=f"PR opened: {pr_url}",
            extra_fields={"pr_url": pr_url, "pr_number": pr_number},
        )
        return

    transition(
        role_arn=role_arn,
        to_state="PR_OPEN",
        reason=f"PR opened: {pr_url}",
        extra_fields={"pr_url": pr_url, "pr_number": pr_number},
    )
    notify_pr_opened(
        role_arn=role_arn,
        role_name=role.get("role_name", role_arn),
        owner_slack_id=role.get("owner_slack_id"),
        pr_url=pr_url,
        commit_sha=commit_sha,
    )


def mark_pr_closed(role_arn: str, merged: bool) -> None:
    """Called when a PR is merged or closed."""
    reason = "PR merged — role permissions reduced" if merged else "PR closed without merge"
    transition(
        role_arn=role_arn,
        to_state="ACTIVE",
        reason=reason,
        extra_fields={"pr_url": None, "pr_number": None},
    )