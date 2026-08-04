# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE � Automated Cybersecurity Engine
import logging
from typing import Any
from config import settings
from db_helpers import make_client, parse_rows, parse_row, safe_id
from models_db import ProjectRow, ThreatRow, MitigationRow, EvidenceRow, StatsRow
from generate import ThreatModel

log = logging.getLogger("db")


def _c(user_jwt: str):
    return make_client(settings.supabase_url, settings.supabase_anon_key, user_jwt)


def save_threat_model(user_jwt: str, user_id: str, name: str, desc: str, model: ThreatModel) -> str:
    c = _c(user_jwt)
    project_res = c.table("projects").insert({
        "user_id": user_id,
        "name": name,
        "architecture_description": desc,
        "system_summary": model.system_summary,
        "model_json": model.model_dump(mode="json"),
    }).execute()

    pid = safe_id(project_res.data)
    if not pid:
        raise ValueError("Failed to save project � no id returned")

    for t in model.threats:
        threat_res = c.table("threats").insert({
            "project_id": pid,
            "category": t.category.value,
            "title": t.title,
            "description": t.description,
            "affected_component": t.affected_component,
            "severity": t.severity.value,
            "soc2_control": t.soc2_control,
            "frameworks": {"iso27001": t.iso27001_control, "nist": t.nist_control},
            "status": "pending",
        }).execute()

        tid = safe_id(threat_res.data)
        if tid and t.mitigations:
            c.table("mitigations").insert(
                [{"threat_id": tid, "description": m.description} for m in t.mitigations]
            ).execute()

    c.table("audit_log").insert(
        {"user_id": user_id, "action": "create_project", "target_id": pid}
    ).execute()
    return pid


def count_projects(user_jwt: str) -> int:
    result = (
        _c(user_jwt)
        .table("projects")
        .select("id", count="exact")  # type: ignore[call-overload] � supabase-py CountMethod typing incomplete
        .execute()
    )
    return result.count or 0


def list_projects(user_jwt: str) -> list[dict[str, Any]]:
    result = (
        _c(user_jwt)
        .table("projects")
        .select("id, name, created_at, system_summary")
        .order("created_at", desc=True)
        .limit(100)
        .execute()
    )
    projects = parse_rows(result.data, ProjectRow)
    return [p.model_dump() for p in projects]


def get_project(user_jwt: str, pid: str) -> dict[str, Any]:
    c = _c(user_jwt)
    p_res = c.table("projects").select("*").eq("id", pid).maybe_single().execute()
    project = parse_row(p_res.data if p_res else None, ProjectRow)
    if not project:
        return {"project": None, "threats": []}

    t_res = c.table("threats").select("*").eq("project_id", pid).execute()
    threats = parse_rows(t_res.data, ThreatRow)

    threat_dicts = []
    for t in threats:
        td = t.model_dump()
        m_res = c.table("mitigations").select("*").eq("threat_id", t.id).execute()
        mitigations = parse_rows(m_res.data, MitigationRow)
        td["mitigations"] = [m.model_dump() for m in mitigations]
        fw: dict[str, Any] = td.get("frameworks") or {}
        td["iso27001_control"] = fw.get("iso27001", "")
        td["nist_control"] = fw.get("nist", "")
        threat_dicts.append(td)

    return {"project": project.model_dump(), "threats": threat_dicts}


def delete_project(user_jwt: str, user_id: str, pid: str) -> None:
    c = _c(user_jwt)
    c.table("projects").delete().eq("id", pid).execute()
    c.table("audit_log").insert(
        {"user_id": user_id, "action": "delete_project", "target_id": pid}
    ).execute()


def _freeze_check(c: Any, threat_id: str) -> None:
    """Raises ValueError if this threat is part of a generated evidence PDF."""
    existing_res = (
        c.table("threats")
        .select("ace_patch_commit_sha")
        .eq("id", threat_id)
        .maybe_single()
        .execute()
    )
    row = parse_row(existing_res.data, ThreatRow)
    if row and row.ace_patch_commit_sha:
        raise ValueError(
            "This threat is part of an evidence PDF and cannot be modified. "
            "The evidence record is immutable once a commit SHA is recorded."
        )


def update_threat_status(user_jwt: str, user_id: str, threat_id: str, status: str) -> None:
    if status not in ("pending", "accepted", "rejected"):
        raise ValueError("Invalid status")
    c = _c(user_jwt)
    _freeze_check(c, threat_id)
    c.table("threats").update(
        {"status": status, "updated_at": "now()"}
    ).eq("id", threat_id).execute()
    c.table("audit_log").insert(
        {"user_id": user_id, "action": f"threat_{status}", "target_id": threat_id}
    ).execute()


def update_remediation(user_jwt: str, user_id: str, threat_id: str, status: str) -> None:
    if status not in ("not_started", "in_progress", "resolved"):
        raise ValueError("Invalid remediation status")
    c = _c(user_jwt)
    _freeze_check(c, threat_id)
    c.table("threats").update(
        {"remediation_status": status, "updated_at": "now()"}
    ).eq("id", threat_id).execute()
    c.table("audit_log").insert(
        {"user_id": user_id, "action": f"remediation_{status}", "target_id": threat_id}
    ).execute()


def project_stats(user_jwt: str, pid: str) -> dict[str, Any]:
    result = (
        _c(user_jwt)
        .table("threats")
        .select("severity, status, remediation_status, soc2_control")
        .eq("project_id", pid)
        .execute()
    )
    threats = parse_rows(result.data, ThreatRow)

    accepted = [t for t in threats if t.status == "accepted"]
    resolved  = [t for t in accepted if t.remediation_status == "resolved"]

    sev: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    open_risk: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in accepted:
        if t.severity in sev:
            sev[t.severity] += 1
        if t.remediation_status != "resolved" and t.severity in open_risk:
            open_risk[t.severity] += 1

    controls = sorted({t.soc2_control for t in accepted if t.soc2_control})
    readiness = round((len(resolved) / len(accepted)) * 100) if accepted else 0

    return StatsRow(
        total_threats=len(threats),
        pending=sum(1 for t in threats if t.status == "pending"),
        accepted=len(accepted),
        rejected=sum(1 for t in threats if t.status == "rejected"),
        resolved=len(resolved),
        severity=sev,
        open_risk=open_risk,
        soc2_controls_covered=controls,
        readiness_score=readiness,
    ).model_dump()


def get_evidence_rows(user_jwt: str, pid: str) -> list[dict[str, Any]]:
    """
    Query ace_unified_view for all fully-remediated IAM findings.
    All four merge columns must be non-null.
    Deduplicated by role_arn to prevent PDF fan-out from JOIN.
    """
    result = (
        _c(user_jwt)
        .table("ace_unified_view")
        .select(
            "threat_id, title, category, severity, soc2_control,"
            "remediation_status, project_id, project_name,"
            "ace_role_arn, sweeper_state, ace_patch_pr_url,"
            "ace_patch_commit_sha, ace_mitigated_at,"
            "approver_github_login, approved_at"
        )
        .eq("project_id", pid)
        .eq("remediation_status", "resolved")
        .not_.is_("ace_patch_commit_sha", "null")
        .not_.is_("ace_patch_pr_url", "null")
        .not_.is_("ace_mitigated_at", "null")
        .not_.is_("approver_github_login", "null")
        .order("ace_mitigated_at", desc=False)
        .execute()
    )

    rows = parse_rows(result.data, EvidenceRow)

    # Fan-out guard � deduplicate by role_arn before building PDF
    seen: set[str] = set()
    deduped: list[EvidenceRow] = []
    for row in rows:
        if row.ace_role_arn in seen:
            log.error(
                "Fan-out detected for role %s � skipping duplicate. "
                "Check approvals UNIQUE constraint.",
                row.ace_role_arn,
            )
            continue
        seen.add(row.ace_role_arn)
        deduped.append(row)

    return [r.model_dump() for r in deduped]
