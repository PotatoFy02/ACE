# tests/test_audit.py
import asyncio
import json
import os
import uuid
from uuid import UUID

import asyncpg
import pytest

from audit.models import MIGRATION_SQL, ROLLBACK_SQL, AuditEvent, PatchRecord, ScanRecord

# ── Skip entire module if no DB ───────────────────────────────────────────────

if not os.environ.get("ACE_DATABASE_URL"):
    pytest.skip("ACE_DATABASE_URL not set", allow_module_level=True)

DSN = os.environ["ACE_DATABASE_URL"]


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop():
    """Single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
async def setup_schema():
    """Run migration once. Rollback after all tests finish."""
    conn = await asyncpg.connect(DSN)
    await conn.execute(ROLLBACK_SQL)
    await conn.execute(MIGRATION_SQL)
    await conn.close()
    yield
    conn = await asyncpg.connect(DSN)
    await conn.execute(ROLLBACK_SQL)
    await conn.close()


@pytest.fixture(autouse=True)
async def clean_tables():
    """Wipe rows between every test. Keep schema."""
    yield
    conn = await asyncpg.connect(DSN)
    await conn.execute(
        "DELETE FROM ace_audit_log; DELETE FROM patches; DELETE FROM scans;"
    )
    await conn.close()


@pytest.fixture(autouse=True)
async def reset_pool():
    """Close the shared asyncpg pool between tests so it doesn't carry state."""
    from audit import db
    yield
    if db._pool is not None:
        await db._pool.close()
        db._pool = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_scan(**kwargs) -> ScanRecord:
    defaults: dict = dict(
        repo="test-org/repo",
        commit_sha=str(uuid.uuid4())[:8],
        unknown_rate=0.0,
        patch_blocked=False,
    )
    defaults.update(kwargs)
    return ScanRecord(**defaults)


# ── Schema ────────────────────────────────────────────────────────────────────

async def test_migration_creates_tables():
    conn = await asyncpg.connect(DSN)
    rows = await conn.fetch(
        """
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename IN ('scans', 'patches', 'ace_audit_log')
        ORDER BY tablename
        """
    )
    await conn.close()
    assert {r["tablename"] for r in rows} == {"ace_audit_log", "patches", "scans"}


# ── Scans ─────────────────────────────────────────────────────────────────────

async def test_insert_and_get_scan():
    from audit.store import insert_scan, get_scan

    scan = make_scan(
        repo="test-org/test-repo",
        commit_sha="abc123",
        branch="main",
        actor="dev-user",
        unknown_rate=6.3,
        sdk_call_count=42,
    )
    scan_id = await insert_scan(scan)
    assert isinstance(scan_id, UUID)

    fetched = await get_scan(scan_id)
    assert fetched is not None
    assert fetched["repo"] == "test-org/test-repo"
    assert fetched["commit_sha"] == "abc123"
    assert float(fetched["unknown_rate"]) == 6.3
    assert fetched["patch_blocked"] is False


async def test_get_scans_for_commit():
    from audit.store import insert_scan, get_scans_for_commit

    for i in range(3):
        await insert_scan(make_scan(repo=f"repo-{i}", commit_sha="shared-sha"))

    results = await get_scans_for_commit("shared-sha")
    assert len(results) == 3


async def test_scan_not_found_returns_none():
    from audit.store import get_scan

    result = await get_scan(uuid.uuid4())
    assert result is None


# ── Patches ───────────────────────────────────────────────────────────────────

async def test_insert_and_get_patch():
    from audit.store import insert_scan, insert_patch, get_patches_for_scan

    scan_id = await insert_scan(make_scan())

    patch = PatchRecord(
        scan_id=scan_id,
        role_arn="arn:aws:iam::123:role/my-role",
        risk_level="red",
        actions_removed=["s3:DeleteBucket", "iam:*"],
        actions_added=[],
        patch_blocked=True,
        block_reason="LOW_CONFIDENCE_CALLS_DETECTED",
    )
    patch_id = await insert_patch(patch)
    assert isinstance(patch_id, UUID)

    patches = await get_patches_for_scan(scan_id)
    assert len(patches) == 1
    assert patches[0]["risk_level"] == "red"
    assert patches[0]["patch_blocked"] is True
    assert "s3:DeleteBucket" in patches[0]["actions_removed"]


async def test_patch_invalid_risk_level_rejected():
    from audit.store import insert_scan

    scan_id = await insert_scan(make_scan())
    conn = await asyncpg.connect(DSN)
    try:
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO patches (scan_id, role_arn, risk_level)
                VALUES ($1, 'arn:aws:iam::123:role/r', 'critical')
                """,
                scan_id,
            )
    finally:
        await conn.close()


async def test_get_patches_for_role():
    from audit.store import insert_scan, insert_patch, get_patches_for_role

    role = "arn:aws:iam::123:role/payments-role"
    for _ in range(3):
        scan_id = await insert_scan(make_scan())
        await insert_patch(PatchRecord(
            scan_id=scan_id,
            role_arn=role,
            risk_level="green",
        ))

    results = await get_patches_for_role(role)
    assert len(results) == 3
    assert all(r["role_arn"] == role for r in results)


# ── Audit log ─────────────────────────────────────────────────────────────────

async def test_log_event_and_retrieve():
    from audit.store import insert_scan, log_event, get_audit_trail

    scan_id = await insert_scan(make_scan())

    await log_event(AuditEvent(
        event_type="scan_completed",
        actor="ci-bot",
        scan_id=scan_id,
        metadata={"sdk_call_count": 10},
    ))

    trail = await get_audit_trail(scan_id=scan_id)
    assert len(trail) == 1
    assert trail[0]["event_type"] == "scan_completed"
    assert trail[0]["actor"] == "ci-bot"
    assert trail[0]["metadata"]["sdk_call_count"] == 10


async def test_audit_filter_by_event_type():
    from audit.store import insert_scan, log_event, get_audit_trail

    scan_id = await insert_scan(make_scan())

    for event_type in ["scan_completed", "patch_generated", "approved"]:
        await log_event(AuditEvent(event_type=event_type, scan_id=scan_id))

    approved_only = await get_audit_trail(event_type="approved")
    assert all(e["event_type"] == "approved" for e in approved_only)


async def test_audit_event_without_scan_id():
    from audit.store import log_event

    event_id = await log_event(AuditEvent(
        event_type="system_startup",
        actor="system",
        metadata={"version": "5.0"},
    ))
    assert isinstance(event_id, UUID)


# ── Sweeper ───────────────────────────────────────────────────────────────────

async def test_flag_dormant_role():
    from audit.store import flag_dormant_role, get_audit_trail

    role_arn = "arn:aws:iam::123:role/dormant-role"
    event_id = await flag_dormant_role(
        role_arn=role_arn,
        owner_email="owner@example.com",
        last_active_iso="2026-01-01T00:00:00Z",
    )
    assert isinstance(event_id, UUID)

    trail = await get_audit_trail(event_type="sweeper_flagged")
    assert len(trail) == 1
    assert trail[0]["metadata"]["role_arn"] == role_arn
    assert trail[0]["metadata"]["owner_email"] == "owner@example.com"


async def test_cooling_off_query_returns_nothing_before_14_days():
    from audit.store import flag_dormant_role, get_flagged_roles_past_cooling_off

    await flag_dormant_role(
        role_arn="arn:aws:iam::123:role/new-flag",
        owner_email="owner@example.com",
        last_active_iso="2026-07-01T00:00:00Z",
    )

    results = await get_flagged_roles_past_cooling_off(cooling_off_days=14)
    role_arns = [r["metadata"]["role_arn"] for r in results]
    assert "arn:aws:iam::123:role/new-flag" not in role_arns


# ── fire_audit ────────────────────────────────────────────────────────────────

async def test_fire_audit_does_not_block():
    import time
    from audit.store import fire_audit, log_event, get_audit_trail
    from audit.models import AuditEvent

    start = time.monotonic()
    fire_audit(log_event(AuditEvent(
        event_type="scan_completed",
        actor="test",
        metadata={"note": "fire-and-forget test"},
    )))
    elapsed = time.monotonic() - start
    assert elapsed < 0.05

    await asyncio.sleep(0.2)

    trail = await get_audit_trail(event_type="scan_completed", limit=5)
    assert any(
        e["metadata"] and e["metadata"].get("note") == "fire-and-forget test"
        for e in trail
    )