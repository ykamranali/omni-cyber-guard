"""
PDF report downloads.

Guarded by VIEW_REPORTS: these documents carry the organization's full open
finding list, including verbatim scanner evidence, and were previously
downloadable by any authenticated account regardless of role.
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.reports.pdf_generator import PDFReportGenerator
from app.services.audit import log_action

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/executive/pdf")
def download_executive_report_pdf(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_REPORTS)),
):
    """Executive summary, built from live figures."""
    generator = PDFReportGenerator(db=db, org_id=current_user.organization_id)
    pdf_bytes = generator.generate_executive_report()
    if not pdf_bytes:
        # Belt and braces after the defect where this method returned None and
        # the endpoint happily served an empty body with a PDF filename.
        raise HTTPException(
            status_code=500,
            detail="The report renderer produced no output; nothing was downloaded.",
        )

    log_action(
        db, "export_report", "report", current_user.organization_id, current_user.id,
        "executive", metadata={"format": "pdf", "bytes": len(pdf_bytes)},
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Executive_Security_Report.pdf"'
        },
    )


@router.get("/technical/pdf")
def download_technical_report_pdf(
    scan_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_REPORTS)),
):
    """Full technical findings, optionally narrowed to one scan."""
    generator = PDFReportGenerator(db=db, org_id=current_user.organization_id)
    try:
        pdf_bytes = generator.generate_technical_report(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="scan_id is not a valid identifier.")

    if not pdf_bytes:
        raise HTTPException(
            status_code=500,
            detail="The report renderer produced no output; nothing was downloaded.",
        )

    filename = (
        f"Technical_Vulnerability_Report_{scan_id}.pdf" if scan_id
        else "Technical_Vulnerability_Report.pdf"
    )
    log_action(
        db, "export_report", "report", current_user.organization_id, current_user.id,
        "technical", metadata={"format": "pdf", "scan_id": scan_id, "bytes": len(pdf_bytes)},
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
