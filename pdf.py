from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)

SEV_COLORS = {
    "Critical": colors.HexColor("#c0392b"),
    "High":     colors.HexColor("#e67e22"),
    "Medium":   colors.HexColor("#f1c40f"),
    "Low":      colors.HexColor("#27ae60"),
}

_SEV = SEV_COLORS


def _e(s):
    return escape(str(s or ""))


# ── V1: STRIDE Threat Model PDF ───────────────────────────────────────────────
# Unchanged from original. V1 customers depend on this exact output.

def build_pdf(project_name: str, model_json: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title="STRIDE Threat Model")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("STRIDE Threat Model", styles["Title"]),
        Paragraph(_e(project_name), styles["Heading2"]),
        Spacer(1, 10),
        Paragraph("<b>System Summary</b>", styles["Heading3"]),
        Paragraph(_e(model_json.get("system_summary", "")), styles["Normal"]),
        Spacer(1, 14),
    ]

    all_threats = model_json.get("threats", [])
    threats = [t for t in all_threats if t.get("status") == "accepted"]

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in threats:
        sev = t.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1

    table = Table(
        [["Critical", "High", "Medium", "Low", "Total (Approved)"],
         [counts["Critical"], counts["High"], counts["Medium"], counts["Low"], len(threats)]],
        colWidths=[80, 80, 80, 80, 110],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story += [table, Spacer(1, 16),
              Paragraph("<b>Approved Threats</b>", styles["Heading3"])]

    if not threats:
        story.append(Paragraph(
            "No threats have been approved yet. Approve threats in the app to include them "
            "in the compliance evidence report.", styles["Italic"]))

    for i, t in enumerate(threats, 1):
        color = _SEV.get(t.get("severity"), colors.black)
        header = ParagraphStyle("h", parent=styles["Heading4"], textColor=color)
        story.append(Paragraph(
            f"[{i}] {_e(t.get('title'))} ({_e(t.get('category'))} | {_e(t.get('severity'))})", header))
        story.append(Paragraph(f"<b>Component:</b> {_e(t.get('affected_component'))}", styles["Normal"]))
        story.append(Paragraph(f"<b>SOC2:</b> {_e(t.get('soc2_control'))}", styles["Normal"]))
        if t.get("iso27001_control"):
            story.append(Paragraph(f"<b>ISO 27001:</b> {_e(t.get('iso27001_control'))}", styles["Normal"]))
        if t.get("nist_control"):
            story.append(Paragraph(f"<b>NIST:</b> {_e(t.get('nist_control'))}", styles["Normal"]))
        story.append(Paragraph(_e(t.get("description")), styles["Normal"]))
        story.append(Paragraph("<b>Mitigations:</b>", styles["Normal"]))
        for m in t.get("mitigations", []):
            story.append(Paragraph(f"• {_e(m.get('description'))}", styles["Normal"]))
        story.append(Spacer(1, 10))

    story += [
        Spacer(1, 20),
        Paragraph(
            "<i>Human-reviewed threat model. Only threats explicitly approved by an "
            "authorized user are included as compliance evidence.</i>",
            styles["Italic"]),
    ]
    doc.build(story)
    return buf.getvalue()


# ── V2: SOC2 CC6.3 Auditor Evidence PDF ──────────────────────────────────────
# Generates the IAM remediation evidence package for SOC2 CC6.3.
# Input: rows from ace_unified_view where remediation_status='resolved'.
# Column names match ace_unified_view exactly — do not rename without
# updating the view to match.

def build_evidence_pdf(project_name: str, rows: list[dict]) -> bytes:
    """
    Build the SOC2 CC6.3 auditor evidence PDF.

    Args:
        project_name: The name of the project (appears in the header).
        rows: List of rows from ace_unified_view where remediation_status='resolved'
              and all four merge columns are populated.

    Returns:
        PDF bytes ready to stream as a response.

    Raises:
        ValueError: If rows is empty — callers should check before calling.
    """
    if not rows:
        raise ValueError("build_evidence_pdf called with empty rows — nothing to render.")

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        title=f"IAM Remediation Evidence — {project_name}",
        topMargin=40,
        bottomMargin=40,
        leftMargin=50,
        rightMargin=50,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "EvidenceTitle",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#2c3e50"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "EvidenceSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#7f8c8d"),
        spaceAfter=16,
    )
    section_label_style = ParagraphStyle(
        "SectionLabel",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#7f8c8d"),
        fontName="Helvetica",
        spaceBefore=8,
        spaceAfter=2,
    )
    section_value_style = ParagraphStyle(
        "SectionValue",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#2c3e50"),
        fontName="Helvetica",
        spaceAfter=6,
    )
    monospace_style = ParagraphStyle(
        "Monospace",
        parent=styles["Normal"],
        fontSize=9,
        fontName="Courier",
        textColor=colors.HexColor("#2c3e50"),
        backColor=colors.HexColor("#f5f6fa"),
        borderPadding=(4, 6, 4, 6),
        spaceAfter=6,
    )
    footer_style = ParagraphStyle(
        "EvidenceFooter",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#7f8c8d"),
        fontName="Helvetica-Oblique",
        spaceAfter=4,
    )
    finding_header_style = ParagraphStyle(
        "FindingHeader",
        parent=styles["Heading3"],
        fontSize=13,
        textColor=colors.HexColor("#2c3e50"),
        spaceBefore=16,
        spaceAfter=4,
    )

    def _severity_color(sev: str) -> colors.Color:
        return SEV_COLORS.get(
            sev.capitalize() if sev else "Low",
            colors.HexColor("#27ae60")
        )

    def _format_dt(dt_str: str | None) -> str:
        if not dt_str:
            return "—"
        try:
            dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return str(dt_str)

    def _label(text: str) -> Paragraph:
        return Paragraph(text.upper(), section_label_style)

    def _value(text: str) -> Paragraph:
        return Paragraph(_e(text), section_value_style)

    def _mono(text: str) -> Paragraph:
        return Paragraph(_e(text), monospace_style)

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    story = [
        Paragraph("IAM Remediation Evidence", title_style),
        Paragraph(
            f"SOC2 Trust Services Criteria — CC6.3 Logical Access Controls  |  "
            f"Project: {_e(project_name)}  |  Generated: {generated_at}",
            subtitle_style
        ),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2c3e50")),
        Spacer(1, 12),
        Paragraph(
            f"This document contains {len(rows)} IAM remediation "
            f"{'record' if len(rows) == 1 else 'records'} for project <b>{_e(project_name)}</b>. "
            "Each record proves that an IAM over-privilege finding was identified, "
            "reviewed by an authorized human, and fixed via a Terraform PR tied to "
            "a cryptographic commit SHA that cannot be backdated.",
            styles["Normal"]
        ),
        Spacer(1, 20),
    ]

    # ── Summary Table ─────────────────────────────────────────────────────────

    summary_data = [["#", "IAM Role", "Severity", "Approver", "Mitigated At"]]
    for i, row in enumerate(rows, 1):
        summary_data.append([
            str(i),
            _e(row.get("ace_role_arn", "").split("/")[-1]),
            _e(row.get("severity", "—")),
            _e(row.get("approver_github_login", "—")),
            _format_dt(row.get("ace_mitigated_at")),
        ])

    summary_table = Table(
        summary_data,
        colWidths=[25, 200, 65, 100, 120],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (2, 0), (2, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f5f6fa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))

    story += [
        Paragraph("<b>Summary of Remediated Findings</b>", styles["Heading3"]),
        Spacer(1, 6),
        summary_table,
        Spacer(1, 24),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#bdc3c7")),
        Paragraph(
            "<b>Individual Evidence Records</b>  —  "
            "Each block below constitutes a complete remediation proof for one IAM role.",
            styles["Normal"]
        ),
        Spacer(1, 8),
    ]

    # ── Individual Evidence Blocks ────────────────────────────────────────────

    for i, row in enumerate(rows, 1):
        sev = row.get("severity", "low")
        sev_color = _severity_color(sev)

        sev_style = ParagraphStyle(
            f"SevBadge_{i}",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.white,
            backColor=sev_color,
            borderPadding=(3, 8, 3, 8),
        )

        block = [
            Paragraph(
                f"Evidence Record #{i} — {_e(row.get('title', 'IAM Over-Privilege Finding'))}",
                finding_header_style
            ),
            HRFlowable(width="100%", thickness=1, color=sev_color),
            Spacer(1, 8),

            Table(
                [[
                    Paragraph(
                        f"SOC2 Control: <b>{_e(row.get('soc2_control', 'CC6.3'))}</b>",
                        ParagraphStyle(
                            f"ctrl_{i}",
                            parent=styles["Normal"],
                            fontSize=10,
                            textColor=colors.white,
                            backColor=colors.HexColor("#2c3e50"),
                            borderPadding=(4, 8, 4, 8),
                        )
                    ),
                    Paragraph(
                        f"Severity: <b>{_e(sev.upper())}</b>",
                        sev_style
                    )
                ]],
                colWidths=[260, 200],
            ),
            Spacer(1, 12),

            _label("Threat Identified"),
            _value(
                f"{_e(row.get('category', '—'))}  ·  "
                f"{_e(row.get('title', '—'))}"
            ),

            _label("Affected IAM Role"),
            _mono(row.get("ace_role_arn", "—")),

            _label("Project"),
            _value(row.get("project_name", "—")),

            Spacer(1, 8),

            _label("Remediation PR"),
            Paragraph(
                f'<link href="{_e(row.get("ace_patch_pr_url", ""))}">'
                f'{_e(row.get("ace_patch_pr_url", "—"))}</link>',
                section_value_style
            ),

            _label("Commit SHA (tamper-proof anchor)"),
            _mono(row.get("ace_patch_commit_sha", "—")),

            _label("Remediation Closed At"),
            _value(_format_dt(row.get("ace_mitigated_at"))),

            Spacer(1, 8),

            # CC6.3 requires a named human reviewer — this is the proof.
            _label("Approved By (GitHub Login)"),
            _value(row.get("approver_github_login", "—")),

            _label("Approval Recorded At"),
            _value(_format_dt(row.get("approved_at"))),  # fixed: was approval_created_at

            Spacer(1, 12),

            Paragraph(
                f"<i>This remediation is cryptographically bound to commit "
                f"<b>{_e(row.get('ace_patch_commit_sha', '—'))}</b>. "
                f"The commit SHA is immutable in Git history and cannot be backdated. "
                f"The approval by <b>{_e(row.get('approver_github_login', '—'))}</b> "
                f"was recorded at <b>{_format_dt(row.get('approved_at'))}</b> "
                f"and is stored in the ACE audit log independently of this document.</i>",
                footer_style
            ),
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7")),
            Spacer(1, 20),
        ]

        story.append(KeepTogether(block))

    # ── Document Footer ───────────────────────────────────────────────────────

    story += [
        Spacer(1, 16),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2c3e50")),
        Spacer(1, 8),
        Paragraph(
            f"<b>ACE — Automated IAM Remediation Evidence</b>  ·  "
            f"Generated {generated_at}  ·  {len(rows)} finding(s) included",
            footer_style
        ),
        Paragraph(
            "This document was generated automatically by ACE. All remediation records "
            "reference real Git commits and real human approvals stored in the ACE audit log. "
            "This document satisfies SOC2 Trust Services Criteria CC6.3: "
            "Logical and Physical Access Controls — access restriction.",
            footer_style
        ),
    ]

    doc.build(story)
    return buf.getvalue()