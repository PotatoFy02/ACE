"""
sweeper/db.py — Supabase reads/writes for sweeper state machine.
Uses service role key — RLS blocks anon key on sweeper_roles table.
"""

import os
import logging
from typing import Any, cast
from datetime import datetime, timezone, timedelta
from supabase import create_client

log = logging.getLogger("sweeper.db")

COOLING_OFF_DAYS = 14


def _client():
    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_KEY"]
    return create_client(url, key)


def upsert_role(
    role_arn: str,
    role_name: str,
    repo: str,
    tf_file_path: str,
    owner_slack_id: str | None,
    ignore_dormancy: bool = False,
    ignore_reason: str | None = None,
) -> dict[str, Any]:
    existing = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("role_arn", role_arn)
        .maybe_single()
        .execute()
    )

    now = datetime.now(timezone.utc).isoformat()

    if existing and existing.data:
        _client().table("sweeper_roles").update({
            "role_name": role_name,
            "repo": repo,
            "tf_file_path": tf_file_path,
            "owner_slack_id": owner_slack_id,
            "ignore_dormancy": ignore_dormancy,
            "ignore_reason": ignore_reason,
            "last_checked_at": now,
            "updated_at": now,
        }).eq("role_arn", role_arn).execute()
        return cast(dict[str, Any], existing.data)  # type: ignore[union-attr]

    result = _client().table("sweeper_roles").insert({
        "role_arn": role_arn,
        "role_name": role_name,
        "repo": repo,
        "tf_file_path": tf_file_path,
        "owner_slack_id": owner_slack_id,
        "state": "ACTIVE",
        "ignore_dormancy": ignore_dormancy,
        "ignore_reason": ignore_reason,
        "last_checked_at": now,
    }).execute()
    return cast(dict[str, Any], result.data[0])  # type: ignore[union-attr]


def get_role(role_arn: str) -> dict[str, Any] | None:
    result = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("role_arn", role_arn)
        .maybe_single()
        .execute()
    )
    return cast(dict[str, Any] | None, result.data)  # type: ignore[union-attr]


def transition(
    role_arn: str,
    to_state: str,
    reason: str,
    actor: str = "ace-sweeper",
    extra_fields: dict[str, Any] | None = None,
) -> None:
    role = get_role(role_arn)
    if not role:
        raise ValueError(f"Role not found: {role_arn}")

    from_state = role["state"]
    now = datetime.now(timezone.utc).isoformat()

    update: dict[str, Any] = {"state": to_state, "updated_at": now}
    if extra_fields:
        update.update(extra_fields)

    _client().table("sweeper_roles").update(update).eq("role_arn", role_arn).execute()

    _client().table("sweeper_events").insert({
        "role_arn": role_arn,
        "from_state": from_state,
        "to_state": to_state,
        "reason": reason,
        "actor": actor,
    }).execute()

    log.info(f"Transition: {role_arn} {from_state} → {to_state} ({reason})")


def get_pending_roles_past_cooling_off() -> list[dict[str, Any]]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=COOLING_OFF_DAYS)).isoformat()

    result = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("state", "PENDING_REDUCTION")
        .lt("dormancy_detected_at", cutoff)
        .execute()
    )
    return cast(list[dict[str, Any]], result.data or [])


def get_roles_by_state(state: str) -> list[dict[str, Any]]:
    result = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("state", state)
        .execute()
    )
    return cast(list[dict[str, Any]], result.data or [])


def get_sweeper_status() -> list[dict[str, Any]]:
    """
    Returns countdown and state for every tracked role.
    Used by GET /api/ace/sweeper-status.

    For PENDING_REDUCTION roles, calculates days remaining in the cooling-off
    period so customers can see exactly when a PR will be opened.
    """
    result = (
        _client()
        .table("sweeper_roles")
        .select("role_arn, role_name, repo, state, dormancy_detected_at, pr_url, pr_number, ignore_dormancy, last_checked_at")
        .execute()
    )
    roles = cast(list[dict[str, Any]], result.data or [])

    now = datetime.now(timezone.utc)
    output: list[dict[str, Any]] = []

    for role in roles:
        entry: dict[str, Any] = {
            "role_arn": role["role_arn"],
            "role_name": role["role_name"],
            "repo": role["repo"],
            "state": role["state"],
            "ignore_dormancy": role.get("ignore_dormancy", False),
            "last_checked_at": role.get("last_checked_at"),
            "pr_url": role.get("pr_url"),
            "pr_number": role.get("pr_number"),
            "days_until_pr": None,
            "cooling_off_started_at": None,
        }

        if role["state"] == "PENDING_REDUCTION" and role.get("dormancy_detected_at"):
            detected_str = str(role["dormancy_detected_at"]).replace("Z", "+00:00")
            detected_at = datetime.fromisoformat(detected_str)
            elapsed = (now - detected_at).days
            days_remaining = max(0, COOLING_OFF_DAYS - elapsed)
            entry["days_until_pr"] = days_remaining
            entry["cooling_off_started_at"] = role["dormancy_detected_at"]

        output.append(entry)

    return output
