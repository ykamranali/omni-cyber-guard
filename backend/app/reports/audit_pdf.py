"""
Audit log PDF export.

An audit export is evidence, so the document records its own provenance: who
ran it, when, and exactly which filters were applied. A page of rows with no
statement of scope proves nothing — a reader cannot tell whether they are
looking at everything or at a slice someone chose.

If the result set hits the row cap the document says so on the first page,
because a truncated export that looks complete is worse than no export.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
RULE = colors.HexColor("#e2e8f0")
HEADER_BG = colors.HexColor("#0f172a")
ZEBRA = colors.HexColor("#f8fafc")
ACCENT = colors.HexColor("#0ea5e9")
WARN_BG = colors.HexColor("#fef3c7")
WARN_INK = colors.HexColor("#92400e")

FILTER_LABELS = {
    "search": "Search",
    "action": "Action",
    "resource_type": "Resource type",
    "actor_user_id": "Actor",
    "date_from": "From",
    "date_to": "To",
}


def _styles():
    sheet = getSampleStyleSheet()
    sheet.add(ParagraphStyle(
        name="DocTitle", parent=sheet["Heading1"], fontSize=20, leading=24,
        textColor=INK, spaceAfter=2,
    ))
    sheet.add(ParagraphStyle(
        name="DocSubtitle", parent=sheet["Normal"], fontSize=10, leading=14,
        textColor=MUTED, spaceAfter=14,
    ))
    sheet.add(ParagraphStyle(
        name="SectionHeading", parent=sheet["Heading2"], fontSize=11, leading=14,
        textColor=INK, spaceBefore=10, spaceAfter=6,
    ))
    sheet.add(ParagraphStyle(
        name="Cell", parent=sheet["Normal"], fontSize=7.5, leading=9.5,
        textColor=INK, alignment=TA_LEFT,
    ))
    sheet.add(ParagraphStyle(
        name="CellMuted", parent=sheet["Normal"], fontSize=7, leading=9,
        textColor=MUTED,
    ))
    sheet.add(ParagraphStyle(
        name="Warning", parent=sheet["Normal"], fontSize=9, leading=12,
        textColor=WARN_INK,
    ))
    return sheet


def _page_furniture(canvas, doc):
    canvas.saveState()
    width, height = doc.pagesize

    canvas.setFillColor(HEADER_BG)
    canvas.rect(0, height - 14 * mm, width, 14 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(14 * mm, height - 9.5 * mm, "OMNI CYBER GUARD")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 14 * mm, height - 9.5 * mm, "Audit log export")

    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.5)
    canvas.line(14 * mm, 12 * mm, width - 14 * mm, 12 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(14 * mm, 8 * mm, "Powered by Omni Digital Solution")
    canvas.drawRightString(width - 14 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _describe_filters(filters: dict) -> str:
    applied = [
        f"{FILTER_LABELS.get(key, key)}: {value}"
        for key, value in filters.items()
        if value not in (None, "")
    ]
    return " · ".join(applied) if applied else "None — the full log for this organization."


def render_audit_log_pdf(
    *,
    organization_name: str,
    entries: list[dict],
    total_matching: int,
    exported_by: str,
    filters: dict,
    row_cap: int,
) -> bytes:
    sheet = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(letter),
        leftMargin=14 * mm, rightMargin=14 * mm,
        topMargin=20 * mm, bottomMargin=16 * mm,
        title="Omni Cyber Guard — Audit log export",
        author="Omni Cyber Guard",
    )

    story: list = []
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(Paragraph("Audit log export", sheet["DocTitle"]))
    story.append(Paragraph(
        f"{organization_name or 'Organization'} &nbsp;·&nbsp; generated {generated} "
        f"&nbsp;·&nbsp; exported by {exported_by}",
        sheet["DocSubtitle"],
    ))

    provenance = Table(
        [
            ["Filters applied", Paragraph(_describe_filters(filters), sheet["Cell"])],
            ["Entries matching", f"{total_matching:,}"],
            ["Entries in this document", f"{len(entries):,}"],
        ],
        colWidths=[45 * mm, None],
        hAlign="LEFT",
    )
    provenance.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE),
    ]))
    story.append(provenance)
    story.append(Spacer(1, 8))

    if total_matching > len(entries):
        story.append(Table(
            [[Paragraph(
                f"<b>This export is truncated.</b> {total_matching:,} entries match the "
                f"filters above; the first {row_cap:,} are included, newest first. "
                f"Narrow the date range to export the remainder.",
                sheet["Warning"],
            )]],
            colWidths=[None],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), WARN_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, WARN_INK),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]),
        ))
        story.append(Spacer(1, 10))

    if not entries:
        story.append(Paragraph(
            "No entries match these filters. This reflects what the log holds; "
            "it is not an assertion that nothing happened.",
            sheet["Cell"],
        ))
        doc.build(story, onFirstPage=_page_furniture, onLaterPages=_page_furniture)
        rendered = buffer.getvalue()
        buffer.close()
        return rendered

    header = ["Timestamp (UTC)", "Actor", "Action", "Resource", "Source IP", "Detail"]
    data: list[list] = [[Paragraph(f"<b>{column}</b>", sheet["Cell"]) for column in header]]

    for entry in entries:
        actor = entry.get("actor_name") or entry.get("actor_email") or "—"
        if entry.get("actor_email") and entry.get("actor_name"):
            actor = f"{entry['actor_name']}<br/><font size=6.5 color='#64748b'>{entry['actor_email']}</font>"

        resource = entry.get("resource_type") or "—"
        if entry.get("resource_id"):
            resource += f"<br/><font size=6.5 color='#64748b'>{entry['resource_id']}</font>"

        metadata = entry.get("metadata") or {}
        detail = " · ".join(
            f"{key}={value}" for key, value in list(metadata.items())[:6]
        )

        data.append([
            Paragraph((entry.get("created_at") or "").replace("T", " ")[:19], sheet["Cell"]),
            Paragraph(actor, sheet["Cell"]),
            Paragraph(entry.get("action") or "—", sheet["Cell"]),
            Paragraph(resource, sheet["Cell"]),
            Paragraph(entry.get("ip_address") or "—", sheet["Cell"]),
            Paragraph(detail[:400] or "—", sheet["CellMuted"]),
        ])

    table = Table(
        data,
        colWidths=[33 * mm, 45 * mm, 38 * mm, 45 * mm, 26 * mm, None],
        repeatRows=1,
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, RULE),
        ("LINEBELOW", (0, 0), (-1, 0), 1, ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for index in range(1, len(data)):
        if index % 2 == 0:
            style.append(("BACKGROUND", (0, index), (-1, index), ZEBRA))
    table.setStyle(TableStyle(style))

    story.append(KeepTogether([Paragraph("Entries", sheet["SectionHeading"])]))
    story.append(table)

    doc.build(story, onFirstPage=_page_furniture, onLaterPages=_page_furniture)
    rendered = buffer.getvalue()
    buffer.close()
    return rendered
