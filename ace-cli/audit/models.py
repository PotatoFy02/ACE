# audit/models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID


MIGRATION_SQL = """
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS scans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo        TEXT NOT NULL,
    commit_sha  TEXT NOT NULL,
    branch      TEXT,
    actor       TEXT,
    scanned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    unknown_rate NUMERIC(5, 2),
    patch_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    file_count  INTEGER DEFAULT 0,
    sdk_call_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS patches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    role_arn        TEXT NOT NULL,
    actions_removed TEXT[] NOT NULL DEFAULT '{}',
    actions_added   TEXT[] NOT NULL DEFAULT '{}',
    risk_level      TEXT NOT NULL CHECK (risk_level IN ('green', 'yellow', 'red')),
    patch_blocked   BOOLEAN NOT NULL DEFAULT FALSE,
    block_reason    TEXT,
    blast_radius_summary TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT NOT NULL,
    actor       TEXT,
    scan_id     UUID REFERENCES scans(id) ON DELETE SET NULL,
    patch_id    UUID REFERENCES patches(id) ON DELETE SET NULL,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_commit    ON scans(commit_sha);
CREATE INDEX IF NOT EXISTS idx_scans_repo      ON scans(repo);
CREATE INDEX IF NOT EXISTS idx_patches_scan    ON patches(scan_id);
CREATE INDEX IF NOT EXISTS idx_patches_role    ON patches(role_arn);
CREATE INDEX IF NOT EXISTS idx_audit_event     ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_scan      ON audit_log(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_created   ON audit_log(created_at DESC);
"""

ROLLBACK_SQL = """
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS patches   CASCADE;
DROP TABLE IF EXISTS scans     CASCADE;
"""


# ── Python dataclasses (mirrors DB rows) ──────────────────────────────────────

@dataclass
class ScanRecord:
    repo: str
    commit_sha: str
    branch: Optional[str] = None
    actor: Optional[str] = None
    unknown_rate: Optional[float] = None
    patch_blocked: bool = False
    file_count: int = 0
    sdk_call_count: int = 0
    # filled after insert
    id: Optional[UUID] = None
    scanned_at: Optional[datetime] = None


@dataclass
class PatchRecord:
    scan_id: UUID
    role_arn: str
    risk_level: str                          # 'green' | 'yellow' | 'red'
    actions_removed: list = field(default_factory=list)
    actions_added: list = field(default_factory=list)
    patch_blocked: bool = False
    block_reason: Optional[str] = None
    blast_radius_summary: Optional[str] = None
    # filled after insert
    id: Optional[UUID] = None
    created_at: Optional[datetime] = None


@dataclass
class AuditEvent:
    event_type: str     # scan_completed | patch_generated | patch_blocked
                        # approved | sweeper_flagged | sweeper_acknowledged
    actor: Optional[str] = None
    scan_id: Optional[UUID] = None
    patch_id: Optional[UUID] = None
    metadata: Optional[dict] = None
    # filled after insert
    id: Optional[UUID] = None
    created_at: Optional[datetime] = None