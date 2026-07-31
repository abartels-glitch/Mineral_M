"""PDF export of a compiled passport — for handing to a contracting
officer, alongside the existing JSON API response for programmatic buyer
integration (spec section 4.4). Mirrors passport.html's layout: verdict
badge, reasons, credential-graph table.
"""
import io
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

VERDICT_COLORS = {
    "pass": colors.HexColor("#1e7d34"),
    "fail": colors.HexColor("#b3261e"),
    "insufficient_data": colors.HexColor("#9a6700"),
    # Same slate as style.css's --revoked — deliberately not a shade of
    # fail's red, see that file's comment: revoked is a provenance fact
    # (the credential was retracted), not a compliance finding.
    "revoked": colors.HexColor("#4b4f5a"),
}

VERDICT_LABELS = {
    "pass": "PASS",
    "fail": "FAIL",
    "insufficient_data": "INSUFFICIENT DATA",
    "revoked": "REVOKED",
}


def render_passport_pdf(
    result: dict,
    uii_codes: Optional[dict[str, str]] = None,
    credential_provenance: Optional[dict[str, dict]] = None,
    passport_url: Optional[str] = None,
) -> bytes:
    """`uii_codes` maps a node's credential_id -> its uii_bindings.uii_code
    (bare canonical MIL-STD-130 UII, not the ISO 15434 scan envelope —
    that envelope contains raw control characters and would render as
    garbage, not "clearly legible").

    `credential_provenance` maps a node's credential_id -> {issuer_id,
    issued_at, revoked_at, superseded_by, issuer, revocation_reason} —
    issuer identity and issuance/revocation timestamps for the compact
    chain-of-custody section, deliberately NOT the full audit Timeline:
    no reviewer names, no field-level correction history, nothing from
    the pre-issuance review layer (document_heats/heat_sublots). That
    stays behind the authenticated passport lookup `passport_url` points
    to in the closing footer line.

    Both are passed in by the caller rather than read from `result` —
    compile_passport's return shape is untouched by any of this, so the
    JSON /passport API response is unaffected."""
    uii_codes = uii_codes or {}
    credential_provenance = credential_provenance or {}
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
    uii_label_style = ParagraphStyle(
        "UIILabel", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9, spaceBefore=6, spaceAfter=1
    )
    # Courier/11pt, well above the graph table's 7pt cells — the whole
    # point of this section is that the UII reads directly off the page,
    # not squeezed into a truncated table column like credential_id is.
    uii_value_style = ParagraphStyle(
        "UIIValue", parent=styles["Normal"], fontName="Courier", fontSize=11, leading=14, spaceAfter=4
    )
    uii_missing_style = ParagraphStyle(
        "UIIMissing",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=9,
        textColor=colors.HexColor("#6b6b74"),
        spaceAfter=4,
    )
    provenance_style = ParagraphStyle("Provenance", parent=styles["Normal"], fontSize=9, spaceAfter=2)
    revoked_style = ParagraphStyle(
        "Revoked", parent=provenance_style, textColor=VERDICT_COLORS["revoked"], fontName="Helvetica-Bold"
    )
    footer_style = ParagraphStyle(
        "Footer", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#6b6b74"), spaceBefore=4
    )

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
        Paragraph("Item Identifiers (MIL-STD-130 UII)", styles["Heading2"]),
    ]

    for node in result["nodes"]:
        uii_code = uii_codes.get(node["credential_id"])
        # A legacy binding (issuer has no iac/enterprise_id registered)
        # stores the raw credential_id as uii_code — that's not a real
        # Construct #1 UII, so it's called out as absent rather than
        # displayed as if it were one. See main.py's _scan_payload_for_binding
        # for the same equality check used to tell the two apart.
        is_real_uii = bool(uii_code) and uii_code != node["credential_id"]
        story.append(Paragraph(f"{node['credential_type']} — {node['credential_id'][:12]}…", uii_label_style))
        if is_real_uii:
            story.append(Paragraph(uii_code, uii_value_style))
        else:
            story.append(Paragraph("No UII registered (issuing enterprise has no IAC/EID on file)", uii_missing_style))

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Chain of Custody", styles["Heading2"]))

    for node in result["nodes"]:
        cred = credential_provenance.get(node["credential_id"])
        story.append(Paragraph(f"{node['credential_type']} — {node['credential_id'][:12]}…", uii_label_style))
        if cred is None:
            story.append(Paragraph("Credential record not found — provenance unavailable.", uii_missing_style))
            continue

        issuer = cred.get("issuer")
        if issuer:
            registration = (
                f" (IAC {issuer['iac']}, Enterprise ID {issuer['enterprise_id']})"
                if issuer.get("iac") and issuer.get("enterprise_id")
                else ""
            )
            story.append(
                Paragraph(f"Issued by {issuer['name']}{registration} on {cred['issued_at']}.", provenance_style)
            )
        else:
            story.append(Paragraph(f"Issued on {cred['issued_at']} (issuer record unavailable).", provenance_style))

        if cred.get("revoked_at"):
            reason = cred.get("revocation_reason") or "reason not recorded"
            story.append(Paragraph(f"REVOKED on {cred['revoked_at']}: {reason}", revoked_style))
            successor_id = cred.get("superseded_by")
            if successor_id:
                successor_uii = uii_codes.get(successor_id)
                uii_note = f"UII {successor_uii}" if successor_uii and successor_uii != successor_id else "no UII on file"
                story.append(
                    Paragraph(
                        f"Superseded by credential {successor_id[:12]}… ({uii_note}) — "
                        "see that credential for the current valid record.",
                        provenance_style,
                    )
                )
            else:
                story.append(Paragraph("No superseding credential has been issued yet.", provenance_style))

    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Credential graph", styles["Heading2"]))

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

    if passport_url:
        story.append(Spacer(1, 0.25 * inch))
        story.append(
            Paragraph(
                "Full audit history, including reviewer actions and field corrections, is available via "
                f"passport lookup at {passport_url}.",
                footer_style,
            )
        )

    doc.build(story)
    return buffer.getvalue()
