from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from app.core.deps import get_db, get_current_user
from app.models.user import User
from app.reports.pdf_generator import PDFReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/executive/pdf")
def download_executive_report_pdf(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
