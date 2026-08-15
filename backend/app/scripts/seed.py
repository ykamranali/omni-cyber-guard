"""
OPTIONAL demo-data seed script for Omni Cyber Guard. This is a development
convenience only — it is never run automatically by the application or by
docker-compose. A fresh install starts completely empty (just whichever
organization/admin you create through the API) so the dashboard only ever
reflects data you actually add.

Run explicitly, only if you want sample data to explore the UI with:
    python -m app.scripts.seed
"""
import random

from app.core.security import hash_password
from app.db.session import Base, SessionLocal, engine
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.finding import Finding, Severity, FindingStatus
from app.models.organization import Organization
from app.models.user import User
from app.services.org_provisioning import provision_new_organization
from app.services.risk_scoring import recompute_asset_risk_score


def run():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Organization).count() > 0:
            print("Database already has data. Skipping seed to avoid duplicating records.")
            return

        # Demo organization
        org = Organization(
            name="Acme Corporation",
            slug="acme-corp",
            primary_color="#0EA5E9",
            secondary_color="#7C3AED",
            footer_text="Powered by Omni Digital Solution",
            subscription_plan="enterprise",
            license_seats=250,
        )
        db.add(org)
        db.flush()

        role_objs = provision_new_organization(db, org)

        # Platform super admin
        super_admin = User(
            organization_id=org.id,
            email="admin@omnidigitalsolution.com",
            full_name="Platform Super Admin",
            hashed_password=hash_password("ChangeMe!12345"),
            is_super_admin=True,
        )
        super_admin.roles = [role_objs["super_administrator"]]
        db.add(super_admin)

        # One demo user per role for easy testing
        demo_users = [
            ("orgadmin@acme.test", "Olivia Admin", "organization_administrator"),
            ("secmanager@acme.test", "Sam Manager", "security_manager"),
            ("analyst@acme.test", "Alex Analyst", "security_analyst"),
            ("itadmin@acme.test", "Ivy ITAdmin", "it_administrator"),
            ("compliance@acme.test", "Cameron Compliance", "compliance_officer"),
            ("auditor@acme.test", "Aria Auditor", "auditor"),
            ("helpdesk@acme.test", "Hank Helpdesk", "helpdesk_technician"),
            ("readonly@acme.test", "Riley ReadOnly", "read_only_user"),
        ]
        for email, name, role_key in demo_users:
            u = User(
                organization_id=org.id, email=email, full_name=name,
                hashed_password=hash_password("Demo!12345"),
            )
            u.roles = [role_objs[role_key]]
            db.add(u)

        # Demo assets — real-world-shaped fixtures, but clearly tagged as demo data.
        # latitude/longitude are approximate real coordinates for the named site, used to
        # exercise the geographic distribution map with real-shaped (not random) values.
        asset_defs = [
            ("web-prod-01", AssetType.SERVER, "Ubuntu 22.04 LTS", "Dell", "HQ Datacenter", "Engineering", 37.7749, -122.4194),
            ("db-prod-01", AssetType.SERVER, "PostgreSQL on RHEL 9", "HPE", "HQ Datacenter", "Engineering", 37.7749, -122.4194),
            ("fw-edge-01", AssetType.NETWORK_DEVICE, "FortiOS 7.4", "Fortinet", "HQ Datacenter", "IT", 37.7749, -122.4194),
            ("ws-fin-014", AssetType.WORKSTATION, "Windows 11 Pro", "Lenovo", "Chicago Office", "Finance", 41.8781, -87.6298),
            ("ws-hr-003", AssetType.WORKSTATION, "macOS Sonoma", "Apple", "Chicago Office", "Human Resources", 41.8781, -87.6298),
            ("cloud-api-gw", AssetType.CLOUD_RESOURCE, "AWS API Gateway", "AWS", "AWS us-east-1", "Engineering", 39.0438, -77.4874),
            ("app-crm-portal", AssetType.APPLICATION, "Node.js 20", "Internal", "AWS us-east-1", "Sales", 39.0438, -77.4874),
            ("ws-eng-091", AssetType.WORKSTATION, "Windows 11 Pro", "Dell", "Austin Office", "Engineering", 30.2672, -97.7431),
        ]
        assets: list[Asset] = []
        for hostname, atype, os_, vendor, site, dept, lat, lng in asset_defs:
            a = Asset(
                organization_id=org.id, hostname=hostname, asset_type=atype,
                status=AssetStatus.ACTIVE, operating_system=os_, vendor=vendor,
                site=site, department=dept, latitude=lat, longitude=lng,
                ip_address=f"10.20.{random.randint(0,20)}.{random.randint(2,254)}",
                tags=["demo-data"],
            )
            db.add(a)
            assets.append(a)
        db.flush()

        # Demo findings — real Finding rows (asset risk scores below are then computed
        # FROM these findings, not assigned directly).
        finding_templates = [
            ("Outdated OpenSSL exposes known CVE", "CVE-2024-6119", 9.1, Severity.CRITICAL,
             "Upgrade OpenSSL to the latest patched version and restart affected services."),
            ("Weak TLS cipher suites enabled", "CVE-2023-3817", 7.5, Severity.HIGH,
             "Disable deprecated cipher suites; enforce TLS 1.2+ with modern ciphers only."),
            ("Missing security patch for kernel", "CVE-2024-1086", 8.8, Severity.HIGH,
             "Apply vendor kernel security update during next maintenance window."),
            ("Default credentials on management interface", None, 6.5, Severity.MEDIUM,
             "Rotate default credentials and enforce MFA on the management interface."),
            ("Verbose error messages leak stack traces", None, 4.3, Severity.MEDIUM,
             "Disable debug/verbose error output in production configuration."),
            ("Self-signed certificate in use", None, 3.1, Severity.LOW,
             "Replace with a certificate issued by a trusted internal or public CA."),
        ]
        for asset in assets[:6]:
            title, cve, cvss, sev, guidance = random.choice(finding_templates)
            status = random.choice([FindingStatus.OPEN, FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.REMEDIATED])
            db.add(Finding(
                organization_id=org.id, asset_id=asset.id, title=title, cve_id=cve,
                cvss_score=cvss, severity=sev, status=status,
                remediation_guidance=guidance, source="manual",
                description=f"Identified on {asset.hostname} during authorized assessment.",
            ))

        db.commit()

        for asset in assets:
            recompute_asset_risk_score(db, asset)

        print("Seed complete. This is DEMO DATA — tagged 'demo-data' on every seeded asset.")
        print("Super admin login: admin@omnidigitalsolution.com / ChangeMe!12345")
        print("Demo org users (password Demo!12345): orgadmin@acme.test, secmanager@acme.test, analyst@acme.test, ...")
    finally:
        db.close()


if __name__ == "__main__":
    run()
