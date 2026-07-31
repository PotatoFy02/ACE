import os
from dotenv import load_dotenv
from supabase import create_client, Client
from generate import ThreatModel

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
if not (SUPABASE_URL and SUPABASE_ANON_KEY):
    raise RuntimeError("Supabase env vars not set")


def client_for(user_jwt: str) -> Client:
    c = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    c.postgrest.auth(user_jwt)
    return c


def save_threat_model(user_jwt, user_id, name, desc, model: ThreatModel) -> str:
    c = client_for(user_jwt)
    project = c.table("projects").insert({
        "user_id": user_id,
        "name": name,
        "architecture_description": desc,
        "system_summary": model.system_summary,
        "model_json": model.model_dump(mode="json"),
    }).execute()
    pid = project.data[0]["id"]

    for t in model.threats:
        threat = c.table("threats").insert({
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
        tid = threat.data[0]["id"]
        if t.mitigations:
            c.table("mitigations").insert(
                [{"threat_id": tid, "description": m.description} for m in t.mitigations]
            ).execute()

    c.table("audit_log").insert(
        {"user_id": user_id, "action": "create_project", "target_id": pid}
    ).execute()
    return pid


def count_projects(user_jwt) -> int:
    c = client_for(user_jwt)
    return c.table("projects").select("id", count="exact").execute().count or 0


def list_projects(user_jwt) -> list:
    c = client_for(user_jwt)
    return c.table("projects").select(
        "id, name, created_at, system_summary"
    ).order("created_at", desc=True).limit(100).execute().data


def get_project(user_jwt, pid) -> dict:
    c = client_for(user_jwt)
    project = c.table("projects").select("*").eq("id", pid).maybe_single().execute()
    if not project.data:
        return {"project": None, "threats": []}
    threats = c.table("threats").select("*").eq("project_id", pid).execute()
    for t in threats.data:
        m = c.table("mitigations").select("*").eq("threat_id", t["id"]).execute()
        t["mitigations"] = m.data
        fw = t.get("frameworks") or {}
        t["iso27001_control"] = fw.get("iso27001", "")
        t["nist_control"] = fw.get("nist", "")
    return {"project": project.data, "threats": threats.data}


def delete_project(user_jwt, user_id, pid):
    c = client_for(user_jwt)
    c.table("projects").delete().eq("id", pid).execute()
    c.table("audit_log").insert(
        {"user_id": user_id, "action": "delete_project", "target_id": pid}
    ).execute()


def update_threat_status(user_jwt, user_id, threat_id, status):
    if status not in ("pending", "accepted", "rejected"):
        raise ValueError("Invalid status")
    c = client_for(user_jwt)
    c.table("threats").update({"status": status, "updated_at": "now()"}).eq("id", threat_id).execute()
    c.table("audit_log").insert(
        {"user_id": user_id, "action": f"threat_{status}", "target_id": threat_id}
    ).execute()


def update_remediation(user_jwt, user_id, threat_id, status):
    if status not in ("not_started", "in_progress", "resolved"):
        raise ValueError("Invalid remediation status")
    c = client_for(user_jwt)
    c.table("threats").update({"remediation_status": status, "updated_at": "now()"}).eq("id", threat_id).execute()
    c.table("audit_log").insert(
        {"user_id": user_id, "action": f"remediation_{status}", "target_id": threat_id}
    ).execute()


def project_stats(user_jwt, pid) -> dict:
    c = client_for(user_jwt)
    threats = c.table("threats").select(
        "severity, status, remediation_status, soc2_control"
    ).eq("project_id", pid).execute().data

    total = len(threats)
    pending = [t for t in threats if t["status"] == "pending"]
    accepted = [t for t in threats if t["status"] == "accepted"]
    rejected = [t for t in threats if t["status"] == "rejected"]
    resolved = [t for t in accepted if t["remediation_status"] == "resolved"]

    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    open_risk = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in accepted:
        sev[t["severity"]] = sev.get(t["severity"], 0) + 1
        if t["remediation_status"] != "resolved":
            open_risk[t["severity"]] = open_risk.get(t["severity"], 0) + 1

    controls = sorted({t["soc2_control"] for t in accepted if t.get("soc2_control")})
    readiness = round((len(resolved) / len(accepted)) * 100) if accepted else 0

    return {
        "total_threats": total,
        "pending": len(pending),
        "accepted": len(accepted),
        "rejected": len(rejected),
        "resolved": len(resolved),
        "severity": sev,
        "open_risk": open_risk,
        "soc2_controls_covered": controls,
        "readiness_score": readiness,
    }


def get_evidence_rows(user_jwt: str, pid: str) -> list[dict]:
    """
    Query ace_unified_view for all fully-remediated IAM findings
    belonging to this project.

    A row is included only when ALL of these are true:
      - remediation_status = 'resolved'
      - ace_patch_commit_sha is not null  (cryptographic proof exists)
      - ace_patch_pr_url is not null      (PR is traceable)
      - ace_mitigated_at is not null      (close timestamp exists)
      - approver_github_login is not null (human approval is recorded)

    Column names match ace_unified_view exactly:
      - title          (not threat_title)
      - category       (not threat_category)
      - severity       (not threat_severity)
      - approved_at    (not approval_created_at)

    Returns an empty list if no rows qualify — callers handle that as a
    404 or informational response, not an error.
    """
    c = client_for(user_jwt)

    result = (
        c.table("ace_unified_view")
        .select(
            "threat_id,"
            "title,"
            "category,"
            "severity,"
            "soc2_control,"
            "remediation_status,"
            "project_id,"
            "project_name,"
            "ace_role_arn,"
            "sweeper_state,"
            "ace_patch_pr_url,"
            "ace_patch_commit_sha,"
            "ace_mitigated_at,"
            "approver_github_login,"
            "approved_at"
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

    return result.data or []