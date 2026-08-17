import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding

class PDFReportGenerator:
    def __init__(self, db: Session, org_id: str):
        self.db = db
        self.org_id = org_id
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name='CustomTitle', parent=self.styles['Heading1'], fontSize=24, spaceAfter=20, textColor=colors.HexColor('#1f2937')))
        self.styles.add(ParagraphStyle(name='Subtitle', parent=self.styles['Heading2'], fontSize=14, spaceAfter=20, textColor=colors.HexColor('#4b5563')))

    def generate_executive_report(self) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        elements = []

        # Title
        elements.append(Paragraph("OMNI CYBER GUARD", self.styles['CustomTitle']))
        elements.append(Paragraph("Executive Security Report", self.styles['Subtitle']))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}", self.styles['Normal']))
        elements.append(Spacer(1, 30))

        # Fetch basic stats
        total_assets = self.db.query(Asset).filter(Asset.organization_id == self.org_id).count()
        findings = self.db.query(Finding).filter(Finding.organization_id == self.org_id, Finding.status == "open").all()
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity.value.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Summary Table
        elements.append(Paragraph("Executive Summary", self.styles['Heading2']))
        elements.append(Spacer(1, 10))
        
        data = [
            ["Metric", "Value"],
            ["Total Assets Scanned", str(total_assets)],
            ["Total Open Findings", str(len(findings))],
            ["Critical Vulnerabilities", str(severity_counts["CRITICAL"])],
            ["High Vulnerabilities", str(severity_counts["HIGH"])],
        ]
        
        t = Table(data, colWidths=[200, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#374151')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9fafb')),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#d1d5db')),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 30))

        # Footer
        elements.append(Paragraph("Powered by Omni Digital Solution", self.styles['Italic']))

        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
