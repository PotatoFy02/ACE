# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE — Automated Cybersecurity Engine
# Typed Pydantic models mirroring Supabase table rows.
from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime


class ProjectRow(BaseModel):
    id: str
    user_id: str
    name: str
    system_summary: Optional[str] = None
    architecture_description: Optional[str] = None
    model_json: Optional[Any] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        extra = "ignore"


class ThreatRow(BaseModel):
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

    class Config:
        extra = "ignore"


class MitigationRow(BaseModel):
    id: str
    threat_id: str
    description: str

    class Config:
        extra = "ignore"


class EvidenceRow(BaseModel):
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

    class Config:
        extra = "ignore"


class StatsRow(BaseModel):
    total_threats: int = 0
    pending: int = 0
    accepted: int = 0
    rejected: int = 0
    resolved: int = 0
    severity: dict[str, int] = {}
    open_risk: dict[str, int] = {}
    soc2_controls_covered: list[str] = []
    readiness_score: int = 0
