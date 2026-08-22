from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.core.deps import get_db, get_current_user, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.reports.pdf_generator import PDFReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/executive/pdf")
def download_executive_report_pdf(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.GENERATE_REPORTS)),
):
    """Generate and download the Executive Security Report in PDF format."""
    generator = PDFReportGenerator(db=db, org_id=current_user.organization_id)
    try:
        pdf_bytes = generator.generate_executive_report()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=Executive_Security_Report.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

@router.get("/technical/pdf")
def download_technical_report_pdf(
    scan_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.GENERATE_REPORTS)),
):
    """Generate and download the Technical Vulnerability Report in PDF format."""
    generator = PDFReportGenerator(db=db, org_id=current_user.organization_id)
    try:
        pdf_bytes = generator.generate_technical_report(scan_id)
        filename = f"Technical_Vulnerability_Report_{scan_id}.pdf" if scan_id else "Technical_Vulnerability_Report.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
