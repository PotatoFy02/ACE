from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

SEV_COLORS = {
    "Critical": colors.HexColor("#c0392b"),
    "High": colors.HexColor("#e67e22"),
    "Medium": colors.HexColor("#f1c40f"),
    "Low": colors.HexColor("#27ae60"),
}


def _e(s):
    return escape(str(s or ""))


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
        color = SEV_COLORS.get(t.get("severity"), colors.black)
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