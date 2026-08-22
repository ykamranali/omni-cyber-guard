from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant
from app.models.scan_job import ScanJob, ScanStatus

db = SessionLocal()
bypass_tenant(db)

queued_jobs = db.query(ScanJob).filter(ScanJob.status == ScanStatus.QUEUED).all()
print(f"Found {len(queued_jobs)} queued jobs.")

for job in queued_jobs:
    job.status = ScanStatus.FAILED
    job.error_message = "Scan task was lost due to a system restart. Please start a new scan."

db.commit()
db.close()
