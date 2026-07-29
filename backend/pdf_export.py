"""PDF export of a compiled passport — for handing to a contracting
officer, alongside the existing JSON API response for programmatic buyer
integration (spec section 4.4). Mirrors passport.html's layout: verdict
badge, reasons, credential-graph table.
"""
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

VERDICT_COLORS = {
    "pass": colors.HexColor("#1e7d34"),
    "fail": colors.HexColor("#b3261e"),
    "insufficient_data": colors.HexColor("#9a6700"),
}

VERDICT_LABELS = {
    "pass": "PASS",
    "fail": "FAIL",
    "insufficient_data": "INSUFFICIENT DATA",
}


def render_passport_pdf(result: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title=f"Passport {result['credential_id']}")
    styles = getSampleStyleSheet()
    verdict_style = ParagraphStyle(
        "Verdict",
        parent=styles["Heading1"],
        textColor=VERDICT_COLORS.get(result["verdict"], colors.black),
    )
    # Plain strings in a Table don't wrap — they overflow into neighboring
    # cells once the text is longer than the column. Every data cell (not
    # just the "Reasons" column) needs to be a Paragraph so reportlab
    # actually wraps it to the column width instead of overflowing.
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=7, leading=9)
    header_style = ParagraphStyle("CellHeader", parent=cell_style, fontName="Helvetica-Bold")

    def cell(text: str, style: ParagraphStyle = cell_style) -> Paragraph:
        return Paragraph(text, style)

    story = [
        Paragraph("FEOC Compliance Passport", styles["Title"]),
        Paragraph(f"Credential: {result['credential_id']}", styles["Normal"]),
        Spacer(1, 0.15 * inch),
        Paragraph(VERDICT_LABELS.get(result["verdict"], result["verdict"]), verdict_style),
        Spacer(1, 0.1 * inch),
        Paragraph("Why", styles["Heading2"]),
        ListFlowable(
            [ListItem(Paragraph(reason, styles["Normal"])) for reason in result["reasons"]],
            bulletType="bullet",
        ),
        Spacer(1, 0.2 * inch),
        Paragraph("Credential graph", styles["Heading2"]),
    ]

    table_data = [[cell(h, header_style) for h in ("Credential", "Type", "Material", "Origin", "Status", "Reasons")]]
    for node in result["nodes"]:
        table_data.append(
            [
                cell(node["credential_id"][:12] + "…"),
                cell(node["credential_type"]),
                cell(node["material_type"] or "—"),
                cell(node["origin_country"] or "—"),
                cell(VERDICT_LABELS.get(node["node_status"], node["node_status"])),
                cell("; ".join(node["reasons"])),
            ]
        )

    table = Table(
        table_data,
        repeatRows=1,
        colWidths=[0.8 * inch, 1.0 * inch, 1.2 * inch, 0.8 * inch, 0.9 * inch, 1.6 * inch],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)

    doc.build(story)
    return buffer.getvalue()
