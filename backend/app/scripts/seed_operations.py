import os
import sys
import uuid
import random
from datetime import datetime, timedelta, timezone

# Add the backend directory to sys.path so we can import 'app'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant, clear_tenant
from app.models.organization import Organization
from app.models.user import User
from app.models.remediation import RemediationTask, RemediationStatus, AcceptanceStatus, RemediationPriority
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.blocked_ip import BlockedIp
from app.models.audit_log import AuditLog
from app.models.finding import Finding, FindingStatus, Severity
from app.models.asset import Asset

def seed_operations():
    db = SessionLocal()
    try:
        bypass_tenant(db)
        
        # Get primary org and user
        org = db.query(Organization).first()
        user = db.query(User).filter(User.organization_id == org.id).first()
        
        if not org or not user:
            print("No organization or user found. Please run seed.py first.")
            return

        print(f"Seeding operations data for org {org.name}...")

        # 1. Blocked IPs
        print("Seeding Blocked IPs...")
        db.query(BlockedIp).delete()
        blocked_ips = [
            {"ip": "185.15.59.224", "reason": "Repeated SSH brute force attempts (Threat Intel Match)", "status": "enforced"},
            {"ip": "45.133.1.20", "reason": "WAF blocked SQL injection attack vector", "status": "enforced"},
            {"ip": "194.26.29.11", "reason": "Known malicious scanner (C2 infrastructure)", "status": "enforced"},
            {"ip": "89.248.165.143", "reason": "Log4j exploitation attempt blocked", "status": "recommended"},
            {"ip": "141.98.11.16", "reason": "Expired block - Temporary firewall drop", "status": "expired"},
            {"ip": "103.145.253.111", "reason": "False positive - Revoked by administrator", "status": "expired"},
        ]
        
        now = datetime.now(timezone.utc)
        for b in blocked_ips:
            entry = BlockedIp(
                organization_id=org.id,
                ip_address=b["ip"],
                reason=b["reason"],
                status=b["status"],
                created_at=now - timedelta(days=random.randint(1, 14))
            )
            db.add(entry)

        # 2. Remediation Tasks
        print("Seeding Remediation Tasks...")
        db.query(RemediationTask).delete()
        
        asset = db.query(Asset).filter(Asset.organization_id == org.id).first()
        
        # Find some real findings to attach if they exist
        findings = db.query(Finding).filter(Finding.organization_id == org.id).limit(10).all()
        if not findings and asset:
            # Create a dummy finding
            dummy_finding = Finding(
                organization_id=org.id,
                asset_id=asset.id,
                title="Dummy Vulnerability for Task",
                description="This is a fallback finding.",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                fingerprint=str(uuid.uuid4())
            )
            db.add(dummy_finding)
            db.flush()
            findings = [dummy_finding]
        
        tasks = [
            {
                "title": "Patch OpenSSL on Edge Routers",
                "status": RemediationStatus.OPEN,
                "priority": RemediationPriority.URGENT,
                "days_offset": -2,
                "due_days": 1
            },
            {
                "title": "Disable legacy TLS 1.0/1.1 across all load balancers",
                "status": RemediationStatus.IN_PROGRESS,
                "priority": RemediationPriority.HIGH,
                "days_offset": -5,
                "due_days": 2
            },
            {
                "title": "Update Jenkins to resolve unauthenticated RCE",
                "status": RemediationStatus.AWAITING_VERIFICATION,
                "priority": RemediationPriority.URGENT,
                "days_offset": -1,
                "due_days": 0
            },
            {
                "title": "Rotate exposed AWS IAM access keys",
                "status": RemediationStatus.VERIFIED,
                "priority": RemediationPriority.URGENT,
                "days_offset": -10,
                "due_days": -2
            },
            {
                "title": "Remove hardcoded credentials from internal GitHub repo",
                "status": RemediationStatus.OPEN,
                "priority": RemediationPriority.HIGH,
                "days_offset": -20,
                "due_days": -5
            }
        ]
        
        if not findings:
            print("No findings available to attach to remediation tasks. Skipping tasks.")
        else:
            for i, t in enumerate(tasks):
                task = RemediationTask(
                    organization_id=org.id,
                    title=t["title"],
                    description="Auto-generated remediation task from seed.",
                    status=t["status"],
                    priority=t["priority"],
                    assigned_to_user_id=user.id if random.choice([True, False]) else None,
                    created_at=now + timedelta(days=t["days_offset"]),
                    due_date=(now + timedelta(days=t["due_days"])).date(),
                    finding_id=findings[i % len(findings)].id
                )
                db.add(task)
                db.flush()

        # 3. Incidents
        print("Seeding Incidents...")
        db.query(Incident).delete()
        
        asset = db.query(Asset).filter(Asset.organization_id == org.id).first()
        
        incidents = [
            {
                "title": "Ransomware pre-cursor activity detected",
                "desc": "Endpoint detection triggered on powershell execution bypassing AMSI. Possible Cobalt Strike beacon.",
                "sev": IncidentSeverity.CRITICAL,
                "status": IncidentStatus.OPEN,
                "days_offset": -1,
                "playbook": True
            },
            {
                "title": "Unauthorized access to S3 bucket",
                "desc": "CloudTrail indicates anomalous volume of ListBucket and GetObject requests from Tor exit node.",
                "sev": IncidentSeverity.HIGH,
                "status": IncidentStatus.INVESTIGATING,
                "days_offset": -2,
                "playbook": True
            },
            {
                "title": "Multiple failed logins for administrator account",
                "desc": "Over 500 failed authentication attempts detected against Okta admin portal.",
                "sev": IncidentSeverity.MEDIUM,
                "status": IncidentStatus.CONTAINED,
                "days_offset": -5,
                "playbook": False
            },
            {
                "title": "Malware detected on developer workstation",
                "desc": "Antivirus quarantined a known infostealer payload delivered via phishing.",
                "sev": IncidentSeverity.LOW,
                "status": IncidentStatus.RESOLVED,
                "days_offset": -14,
                "playbook": False
            }
        ]
        
        for inc in incidents:
            playbook_text = None
            if inc["playbook"]:
                playbook_text = "### Omni AI Playbook Generated\n\n1. **Isolate Asset**: Immediately disconnect the affected host from the corporate network.\n2. **Capture Memory**: Dump RAM for forensic analysis before powering off.\n3. **Review Logs**: Correlate EDR logs with firewall traffic for C2 communication.\n4. **Rotate Credentials**: Force password resets for all accounts authenticated on this endpoint in the last 48 hours."
                
            incident = Incident(
                organization_id=org.id,
                title=inc["title"],
                description=inc["desc"],
                severity=inc["sev"],
                status=inc["status"],
                asset_id=asset.id if asset else None,
                created_at=now + timedelta(days=inc["days_offset"]),
                resolved_at=now if inc["status"] == IncidentStatus.RESOLVED else None,
                ai_playbook=playbook_text
            )
            db.add(incident)

        # 4. Audit Logs
        print("Seeding Audit Logs...")
        db.query(AuditLog).delete()
        
        actions = [
            ("user_login", "user", str(user.id), "Success login via SSO"),
            ("update_finding", "finding", str(uuid.uuid4()), "Changed severity to critical"),
            ("create_remediation_task", "task", str(uuid.uuid4()), "Created task for patch"),
            ("block_ip", "blocked_ip", str(uuid.uuid4()), "Blocked IP due to bruteforce"),
            ("scan_started", "scan", str(uuid.uuid4()), "Initiated network discovery"),
            ("report_downloaded", "report", str(uuid.uuid4()), "Downloaded executive PDF")
        ]
        
        for i in range(20):
            action, res_type, res_id, meta = random.choice(actions)
            log = AuditLog(
                organization_id=org.id,
                action=action,
                actor_user_id=user.id if random.choice([True, True, False]) else None,
                resource_type=res_type,
                resource_id=res_id,
                ip_address=f"10.0.1.{random.randint(10, 250)}",
                created_at=now - timedelta(hours=random.randint(1, 168)),
                metadata_json={"details": meta}
            )
            db.add(log)

        db.commit()
        print("Successfully seeded operations data.")

    except Exception as e:
        db.rollback()
        print(f"Error seeding data: {e}")
        raise
    finally:
        clear_tenant(db)
        db.close()

if __name__ == "__main__":
    seed_operations()
