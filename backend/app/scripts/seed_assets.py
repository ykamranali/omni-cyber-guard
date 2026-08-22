import sys
import os
import random
import uuid
from datetime import datetime, timezone, timedelta

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant
from app.models.organization import Organization
from app.models.asset import Asset, AssetType, AssetStatus, Criticality, DataSensitivity
from app.models.finding import Finding, FindingStatus, Severity, FindingClass, Confidence

def seed():
    db = SessionLocal()
    try:
        bypass_tenant(db)
        org = db.query(Organization).first()
        if not org:
            print("No organization found. Please run seed.py first.")
            return

        print("Seeding assets...")
        # Clear existing assets just in case
        db.query(Asset).delete()

        now = datetime.now(timezone.utc)
        assets_data = [
            {"hostname": "prod-web-01", "ip": "10.0.1.20", "type": AssetType.SERVER, "os": "Ubuntu 22.04 LTS", "crit": Criticality.HIGH},
            {"hostname": "prod-web-02", "ip": "10.0.1.21", "type": AssetType.SERVER, "os": "Ubuntu 22.04 LTS", "crit": Criticality.HIGH},
            {"hostname": "prod-db-master", "ip": "10.0.2.50", "type": AssetType.DATABASE, "os": "Debian 11", "crit": Criticality.CRITICAL},
            {"hostname": "core-fw-primary", "ip": "10.0.0.1", "type": AssetType.FIREWALL, "os": "pfSense", "crit": Criticality.CRITICAL},
            {"hostname": "dev-workstation-11", "ip": "192.168.1.115", "type": AssetType.WORKSTATION, "os": "Windows 11", "crit": Criticality.LOW},
            {"hostname": "hr-laptop-22", "ip": "192.168.1.189", "type": AssetType.LAPTOP, "os": "macOS Sonoma", "crit": Criticality.MEDIUM},
            {"hostname": "cctv-nvr", "ip": "10.10.10.5", "type": AssetType.NVR, "os": "Embedded Linux", "crit": Criticality.MEDIUM},
            {"hostname": "lobby-printer", "ip": "10.10.20.50", "type": AssetType.PRINTER, "os": "HP JetDirect", "crit": Criticality.LOW},
        ]

        assets = []
        for a in assets_data:
            asset = Asset(
                organization_id=org.id,
                hostname=a["hostname"],
                ip_address=a["ip"],
                asset_type=a["type"],
                operating_system=a["os"],
                criticality=a["crit"],
                status=AssetStatus.ACTIVE,
                is_internet_facing=a["type"] == AssetType.FIREWALL,
                is_production="prod" in a["hostname"] or a["crit"] == Criticality.CRITICAL,
                first_seen=now - timedelta(days=random.randint(30, 365)),
                last_seen=now - timedelta(hours=random.randint(0, 24)),
                risk_score=random.uniform(0.0, 100.0)
            )
            db.add(asset)
            assets.append(asset)
        db.flush()

        print("Seeding findings...")
        db.query(Finding).delete()

        findings_data = [
            {"title": "OpenSSH 8.9p1 Vulnerability (CVE-2023-38408)", "sev": Severity.CRITICAL, "class": FindingClass.VULNERABILITY, "cve": "CVE-2023-38408", "asset_idx": 0},
            {"title": "Anonymous FTP Access Allowed", "sev": Severity.HIGH, "class": FindingClass.MISCONFIGURATION, "cve": None, "asset_idx": 1},
            {"title": "PostgreSQL accessible from Internet", "sev": Severity.CRITICAL, "class": FindingClass.EXPOSURE, "cve": None, "asset_idx": 2},
            {"title": "Outdated pfSense Version", "sev": Severity.MEDIUM, "class": FindingClass.VULNERABILITY, "cve": "CVE-2023-XXXX", "asset_idx": 3},
            {"title": "Missing Windows Defender Updates", "sev": Severity.HIGH, "class": FindingClass.MISCONFIGURATION, "cve": None, "asset_idx": 4},
            {"title": "Default printer credentials (admin/admin)", "sev": Severity.CRITICAL, "class": FindingClass.EXPOSURE, "cve": None, "asset_idx": 7},
        ]

        for f in findings_data:
            asset = assets[f["asset_idx"]]
            finding = Finding(
                organization_id=org.id,
                asset_id=asset.id,
                fingerprint=str(uuid.uuid4()),
                title=f["title"],
                description=f"Automated finding for {f['title']}",
                severity=f["sev"],
                status=FindingStatus.OPEN,
                finding_class=f["class"],
                cve_id=f["cve"],
                confidence=Confidence.CONFIRMED,
            )
            db.add(finding)
        
        db.commit()
        print("Successfully seeded assets and findings.")
    except Exception as e:
        db.rollback()
        print(f"Error seeding data: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed()
