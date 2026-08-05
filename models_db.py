# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE - Automated Cybersecurity Engine
# Typed Pydantic models mirroring Supabase table rows.
from pydantic import BaseModel, ConfigDict
from typing import Optional, Any
from datetime import datetime


class ProjectRow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    user_id: str
    name: str
    system_summary: Optional[str] = None
    architecture_description: Optional[str] = None
    model_json: Optional[Any] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ThreatRow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    project_id: str
    title: str
    category: str
    severity: str
    affected_component: str
    description: str
    soc2_control: str
    frameworks: Optional[dict[str, Any]] = None
    status: str = "pending"
    remediation_status: str = "not_started"
    ace_patch_commit_sha: Optional[str] = None
    ace_patch_pr_url: Optional[str] = None
    ace_role_arn: Optional[str] = None
    ace_mitigated_at: Optional[datetime] = None
    mitigations: Optional[list[Any]] = None

    # Derived fields populated by get_project()
    iso27001_control: str = ""
    nist_control: str = ""


class MitigationRow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    threat_id: str
    description: str


class EvidenceRow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    threat_id: Optional[str] = None
    title: str
    category: str
    severity: str
    soc2_control: str
    remediation_status: str
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    ace_role_arn: str
    sweeper_state: Optional[str] = None
    ace_patch_pr_url: str
    ace_patch_commit_sha: str
    ace_mitigated_at: datetime
    approver_github_login: str
    approved_at: Optional[datetime] = None


class StatsRow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total_threats: int = 0
    pending: int = 0
    accepted: int = 0
    rejected: int = 0
    resolved: int = 0
    severity: dict[str, int] = {}
    open_risk: dict[str, int] = {}
    soc2_controls_covered: list[str] = []
    readiness_score: int = 0


class SweeperRoleRow(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role_arn: str
    role_name: str
    repo: str
    tf_file_path: str = ""
    owner_slack_id: str | None = None
    state: str = "ACTIVE"
    ignore_dormancy: bool = False
    ignore_reason: str | None = None
    last_checked_at: str | None = None
    updated_at: str | None = None
    dormancy_detected_at: str | None = None
    iam_last_used_at: str | None = None
    last_activity_at: str | None = None
    reduction_ready_at: str | None = None
    pr_url: str | None = None
    pr_number: int | None = None