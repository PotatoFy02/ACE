# audit/store.py
"""
All DB writes are fire-and-forget (asyncio.create_task).
Never called in the delta calculation hot path.
"""
import asyncio
import json
import logging
from typing import Optional
from uuid import UUID

from audit.db import get_pool
from audit.models import AuditEvent, PatchRecord, ScanRecord

log = logging.getLogger("ace.audit")


# ── JSON helper ───────────────────────────────────────────────────────────────

def _parse_row(row: dict) -> dict:
    """
    asyncpg returns JSONB columns as raw strings when cast via dict(row).
    This deserializes any metadata field that came back as a string.
    """
    if row.get("metadata") and isinstance(row["metadata"], str):
        row["metadata"] = json.loads(row["metadata"])
    return row


def _parse_rows(rows) -> list[dict]:
    return [_parse_row(dict(r)) for r in rows]


# ── Scans ─────────────────────────────────────────────────────────────────────

async def insert_scan(scan: ScanRecord) -> UUID:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO scans
                (repo, commit_sha, branch, actor,
                 unknown_rate, patch_blocked, file_count, sdk_call_count)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            RETURNING id, scanned_at
            """,
            scan.repo,
            scan.commit_sha,
            scan.branch,
            scan.actor,
            scan.unknown_rate,
            scan.patch_blocked,
            scan.file_count,
            scan.sdk_call_count,
        )
    scan.id = row["id"]
    scan.scanned_at = row["scanned_at"]
    return scan.id


async def get_scan(scan_id: UUID) -> Optional[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM scans WHERE id = $1", scan_id)
    return dict(row) if row else None


async def get_scans_for_commit(commit_sha: str) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM scans WHERE commit_sha = $1 ORDER BY scanned_at DESC",
            commit_sha,
        )
    return [dict(r) for r in rows]


# ── Patches ───────────────────────────────────────────────────────────────────

async def insert_patch(patch: PatchRecord) -> UUID:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO patches
                (scan_id, role_arn, actions_removed, actions_added,
                 risk_level, patch_blocked, block_reason, blast_radius_summary)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            RETURNING id, created_at
            """,
            patch.scan_id,
            patch.role_arn,
            patch.actions_removed,
            patch.actions_added,
            patch.risk_level,
            patch.patch_blocked,
            patch.block_reason,
            patch.blast_radius_summary,
        )
    patch.id = row["id"]
    patch.created_at = row["created_at"]
    return patch.id


async def get_patches_for_scan(scan_id: UUID) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM patches WHERE scan_id = $1 ORDER BY created_at",
            scan_id,
        )
    return [dict(r) for r in rows]


async def get_patches_for_role(role_arn: str, limit: int = 20) -> list[dict]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM patches
            WHERE role_arn = $1
            ORDER BY created_at DESC
            LIMIT $2
            """,
            role_arn,
            limit,
        )
    return [dict(r) for r in rows]


# ── Audit log ─────────────────────────────────────────────────────────────────

async def log_event(event: AuditEvent) -> UUID:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO ace_audit_log
                (event_type, actor, scan_id, patch_id, metadata)
            VALUES ($1,$2,$3,$4,$5::jsonb)
            RETURNING id, created_at
            """,
            event.event_type,
            event.actor,
            event.scan_id,
            event.patch_id,
            json.dumps(event.metadata) if event.metadata else None,
        )
    event.id = row["id"]
    event.created_at = row["created_at"]
    return event.id


async def get_audit_trail(
    scan_id: Optional[UUID] = None,
    event_type: Optional[str] = None,
    limit: int = 50,
) -> list[dict]:
    pool = await get_pool()
    conditions = []
    params = []

    if scan_id:
        params.append(scan_id)
        conditions.append(f"scan_id = ${len(params)}")
    if event_type:
        params.append(event_type)
        conditions.append(f"event_type = ${len(params)}")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM ace_audit_log {where} ORDER BY created_at DESC LIMIT ${len(params)}",
            *params,
        )

    return _parse_rows(rows)


# ── Sweeper helpers ───────────────────────────────────────────────────────────

async def flag_dormant_role(role_arn: str, owner_email: str, last_active_iso: str) -> UUID:
    """Week 8 Sweeper calls this. Cooling-off clock starts here."""
    event = AuditEvent(
        event_type="sweeper_flagged",
        actor="system",
        metadata={
            "role_arn": role_arn,
            "owner_email": owner_email,
            "last_active": last_active_iso,
            "cooling_off_expires": None,
        },
    )
    return await log_event(event)


async def get_flagged_roles_past_cooling_off(cooling_off_days: int = 14) -> list[dict]:
    """Returns roles flagged > N days ago with no acknowledgement since."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (metadata->>'role_arn')
                id, metadata, created_at
            FROM ace_audit_log
            WHERE event_type = 'sweeper_flagged'
              AND created_at < now() - ($1 || ' days')::INTERVAL
              AND NOT EXISTS (
                  SELECT 1 FROM ace_audit_log ack
                  WHERE ack.event_type    = 'sweeper_acknowledged'
                    AND ack.metadata->>'role_arn' = ace_audit_log.metadata->>'role_arn'
                    AND ack.created_at    > ace_audit_log.created_at
              )
            ORDER BY metadata->>'role_arn', created_at DESC
            """,
            str(cooling_off_days),
        )

    return _parse_rows(rows)


# ── Fire-and-forget wrapper ───────────────────────────────────────────────────

def fire_audit(coro):
    """
    Schedules an audit coroutine without blocking the caller.

    From async context (CI, webhook):
        fire_audit(log_event(...))   — schedules as a task, returns immediately

    From sync context (CLI):
        fire_audit(log_event(...))   — runs via asyncio.run(), blocks briefly
        This is acceptable: CLI audit writes happen after all output is printed.

    Audit failure is always swallowed — never crashes the caller.
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(coro)
    except RuntimeError:
        # No running loop — sync CLI context
        try:
            asyncio.run(coro)
        except Exception as e:
            log.warning("Audit write failed (sync): %s", e)