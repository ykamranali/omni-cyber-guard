"""
PDF report generation.

Both reports read live figures out of the database. Two defects were fixed
here, and both produced a file that looked like a report and was not one:

* `generate_executive_report` was annotated `-> bytes`, assembled its elements,
  and then simply ended. There was no `doc.build(...)` and no `return`, so it
  returned `None` and the endpoint served an HTTP 200 with a PDF filename, a
  PDF content type, and an empty body. The download reported success and
  delivered nothing.

* Both methods filtered findings with `Finding.status == "open"`. The column is
  an enum whose stored values are the member *names* (`OPEN`), so the predicate
  matched no rows. Every report therefore stated zero open findings regardless
  of what the estate actually held — a fabricated all-clear, which is the worst
  possible direction for that error.

A report that has nothing to report says so explicitly rather than printing
zeros, because a zero next to "Critical Vulnerabilities" reads as an assessed
result.
"""
from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import CLOSED_STATUSES, Finding, Severity
from app.models.scan_job import ScanJob, ScanStatus

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]

NO_ASSESSMENT_NOTICE = (
    "No completed assessment has been recorded for this organization. The "
    "figures below would otherwise read as zero findings, which is not the "
    "same statement as a clean estate — nothing has been assessed yet."
)


class PDFReportGenerator:
    def __init__(self, db: Session, org_id) -> None:
        self.db = db
        self.org_id = org_id
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(
            name="CustomTitle", parent=self.styles["Heading1"], fontSize=24,
            spaceAfter=20, textColor=colors.HexColor("#1f2937"),
        ))
        self.styles.add(ParagraphStyle(
            name="Subtitle", parent=self.styles["Heading2"], fontSize=14,
            spaceAfter=20, textColor=colors.HexColor("#4b5563"),
        ))
        self.styles.add(ParagraphStyle(
            name="Caveat", parent=self.styles["Normal"], fontSize=9,
            textColor=colors.HexColor("#92400e"),
        ))

    # -- shared -----------------------------------------------------------

    def _header(self, elements: list, subtitle: str) -> None:
        elements.append(Paragraph("OMNI CYBER GUARD", self.styles["CustomTitle"]))
        elements.append(Paragraph(subtitle, self.styles["Subtitle"]))
        elements.append(Paragraph(
            f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            self.styles["Normal"],
        ))
        elements.append(Spacer(1, 24))

    def _footer(self, elements: list) -> None:
        elements.append(Spacer(1, 24))
        elements.append(Paragraph(
            "Powered by Omni Digital Solution", self.styles["Italic"]
        ))

    def _open_findings(self):
        return self.db.execute(
            select(Finding).where(
                Finding.organization_id == self.org_id,
                Finding.status.notin_(list(CLOSED_STATUSES)),
            )
        ).scalars().all()

    def _completed_scan_count(self) -> int:
        return self.db.execute(
            select(func.count(ScanJob.id)).where(
                ScanJob.organization_id == self.org_id,
                ScanJob.status == ScanStatus.COMPLETED,
            )
        ).scalar_one()

    @staticmethod
    def _render(doc: SimpleDocTemplate, buffer: io.BytesIO, elements: list) -> bytes:
        doc.build(elements)
        rendered = buffer.getvalue()
        buffer.close()
        return rendered

    # -- reports ----------------------------------------------------------

    def generate_executive_report(self) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter, rightMargin=72, leftMargin=72,
            topMargin=72, bottomMargin=18,
        )
        elements: list = []
        self._header(elements, "Executive Security Report")

        completed_scans = self._completed_scan_count()
        if completed_scans == 0:
            elements.append(Paragraph(NO_ASSESSMENT_NOTICE, self.styles["Caveat"]))
            elements.append(Spacer(1, 20))

        total_assets = self.db.execute(
            select(func.count(Asset.id)).where(Asset.organization_id == self.org_id)
        ).scalar_one()

        findings = self._open_findings()
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        elements.append(Paragraph("Executive Summary", self.styles["Heading2"]))
        elements.append(Spacer(1, 10))

        rows = [
            ["Metric", "Value"],
            ["Completed assessments", str(completed_scans)],
            ["Assets in inventory", str(total_assets)],
            ["Open findings", str(len(findings))],
            ["Critical", str(counts[Severity.CRITICAL])],
            ["High", str(counts[Severity.HIGH])],
            ["Medium", str(counts[Severity.MEDIUM])],
            ["Low", str(counts[Severity.LOW])],
        ]
        table = Table(rows, colWidths=[240, 120])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#d1d5db")),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(
            "Counts cover findings that are open, acknowledged or in progress. "
            "Remediated, accepted-risk and false-positive findings are "
            "excluded. Coverage is limited to what the completed assessments "
            "above actually targeted; anything outside their scope is "
            "unassessed, not clean.",
            self.styles["Normal"],
        ))

        self._footer(elements)
        return self._render(doc, buffer, elements)

    def generate_technical_report(self, scan_id: str | None = None) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter, rightMargin=72, leftMargin=72,
            topMargin=72, bottomMargin=18,
        )
        elements: list = []
        self._header(elements, "Technical Vulnerability Report")

        if scan_id:
            elements.append(Paragraph(
                f"Filtered to scan {scan_id}", self.styles["Normal"]
            ))
            elements.append(Spacer(1, 12))

        statement = select(Finding).where(
            Finding.organization_id == self.org_id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
        )
        if scan_id:
            # Raises ValueError on a malformed id; the endpoint turns that into
            # a 400 rather than a 500.
            statement = statement.where(Finding.scan_job_id == uuid.UUID(scan_id))

        findings = self.db.execute(statement).scalars().all()
        findings.sort(key=lambda item: SEVERITY_ORDER.index(item.severity))

        if not findings:
            elements.append(Paragraph(
                "No open findings match this filter. This reflects what the "
                "database holds; it is not an assertion that the estate is "
                "free of vulnerabilities.",
                self.styles["Normal"],
            ))
        else:
            elements.append(Paragraph(
                f"Open findings ({len(findings)})", self.styles["Heading2"]
            ))
            elements.append(Spacer(1, 10))

            for finding in findings:
                elements.append(Paragraph(
                    f"{finding.severity.value.upper()} — {finding.title}",
                    self.styles["Heading3"],
                ))
                elements.append(Paragraph(
                    f"Class: {finding.finding_class.value} &nbsp;|&nbsp; "
                    f"Confidence: {finding.confidence.value} &nbsp;|&nbsp; "
                    f"Source: {finding.source}"
                    + (f" &nbsp;|&nbsp; {finding.cve_id}" if finding.cve_id else ""),
                    self.styles["Normal"],
                ))
                elements.append(Spacer(1, 4))
                if finding.description:
                    elements.append(Paragraph(finding.description, self.styles["Normal"]))
                    elements.append(Spacer(1, 4))
                if finding.evidence:
                    # Verbatim scanner output, labelled as such so a reader can
                    # tell an observation from a summary of one.
                    elements.append(Paragraph(
                        f"<b>Evidence (verbatim):</b> {finding.evidence[:1500]}",
                        self.styles["Normal"],
                    ))
                    elements.append(Spacer(1, 4))
                elements.append(Paragraph(
                    f"<i>Remediation: "
                    f"{finding.remediation_guidance or 'None recorded.'}</i>",
                    self.styles["Normal"],
                ))
                elements.append(Spacer(1, 14))

        self._footer(elements)
        return self._render(doc, buffer, elements)
