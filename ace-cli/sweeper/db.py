"""
sweeper/db.py — Supabase reads/writes for sweeper state machine.
Uses service role key — RLS blocks anon key on sweeper_roles table.
"""

import os
import logging
from datetime import datetime, timezone
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
    created_by_email: str | None,
    ignore_dormancy: bool = False,
    ignore_reason: str | None = None,
) -> dict:
    """
    Inserts role if not seen before, updates metadata if already exists.
    Never downgrades state — only the state machine transitions do that.
    """
    existing = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("role_arn", role_arn)
        .maybe_single()
        .execute()
    )

    now = datetime.now(timezone.utc).isoformat()

    if existing.data:
        _client().table("sweeper_roles").update({
            "role_name": role_name,
            "repo": repo,
            "tf_file_path": tf_file_path,
            "created_by_email": created_by_email,
            "ignore_dormancy": ignore_dormancy,
            "ignore_reason": ignore_reason,
            "last_checked_at": now,
            "updated_at": now,
        }).eq("role_arn", role_arn).execute()
        return existing.data

    result = _client().table("sweeper_roles").insert({
        "role_arn": role_arn,
        "role_name": role_name,
        "repo": repo,
        "tf_file_path": tf_file_path,
        "created_by_email": created_by_email,
        "state": "ACTIVE",
        "ignore_dormancy": ignore_dormancy,
        "ignore_reason": ignore_reason,
        "last_checked_at": now,
    }).execute()
    return result.data[0]


def get_role(role_arn: str) -> dict | None:
    result = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("role_arn", role_arn)
        .maybe_single()
        .execute()
    )
    return result.data


def transition(
    role_arn: str,
    to_state: str,
    reason: str,
    actor: str = "ace-sweeper",
    extra_fields: dict | None = None,
) -> None:
    """
    Moves a role to a new state and writes the transition to sweeper_events.
    This is the only place state changes happen — never update state directly.
    """
    role = get_role(role_arn)
    if not role:
        raise ValueError(f"Role not found: {role_arn}")

    from_state = role["state"]
    now = datetime.now(timezone.utc).isoformat()

    update = {"state": to_state, "updated_at": now}
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


def get_pending_roles_past_cooling_off() -> list[dict]:
    """
    Returns all roles in PENDING_REDUCTION where 14 days have elapsed.
    Called by the sweep command to advance stale pending roles to REDUCTION_READY.
    """
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=COOLING_OFF_DAYS)).isoformat()

    result = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("state", "PENDING_REDUCTION")
        .lt("dormancy_detected_at", cutoff)
        .execute()
    )
    return result.data or []


def get_roles_by_state(state: str) -> list[dict]:
    result = (
        _client()
        .table("sweeper_roles")
        .select("*")
        .eq("state", state)
        .execute()
    )
    return result.data or []