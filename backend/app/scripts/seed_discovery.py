import sys
import os
from datetime import datetime, timedelta

# Add backend directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db.session import SessionLocal
from app.models.organization import Organization
from app.models.discovery import AttackSurfaceDomain, CloudResource, IdentityProfile

def seed():
    db = SessionLocal()
    
    # Get the default org
    org = db.query(Organization).first()
    if not org:
        print("No organization found. Run main seed first.")
        return
        
    print(f"Seeding discovery modules for organization: {org.name}")
    
    # Attack Surface
    domains = [
        AttackSurfaceDomain(
            organization_id=org.id,
            domain_name="example.com",
            ip_addresses="93.184.216.34",
            registrar="MarkMonitor Inc.",
            is_active=True,
            cert_issuer="DigiCert Inc",
            cert_valid_from=datetime.utcnow() - timedelta(days=100),
            cert_valid_to=datetime.utcnow() + timedelta(days=265),
        ),
        AttackSurfaceDomain(
            organization_id=org.id,
            domain_name="api.example.com",
            ip_addresses="93.184.216.35",
            registrar="MarkMonitor Inc.",
            is_active=True,
            cert_issuer="Let's Encrypt",
            cert_valid_from=datetime.utcnow() - timedelta(days=70),
            cert_valid_to=datetime.utcnow() + timedelta(days=20),
        ),
        AttackSurfaceDomain(
            organization_id=org.id,
            domain_name="legacy-portal.example.com",
            ip_addresses="10.0.0.100",
            registrar="GoDaddy",
            is_active=True,
            cert_issuer="Sectigo RSA",
            cert_valid_from=datetime.utcnow() - timedelta(days=400),
            cert_valid_to=datetime.utcnow() - timedelta(days=35), # Expired!
        )
    ]
    db.add_all(domains)
    
    # Cloud Resources
    resources = [
        CloudResource(
            organization_id=org.id,
            provider="AWS",
            resource_type="AWS::EC2::Instance",
            resource_id="i-0abcd1234efgh5678",
            name="prod-web-server-01",
            region="us-east-1",
            status="ACTIVE",
            compliance_status="PASSED",
        ),
        CloudResource(
            organization_id=org.id,
            provider="AWS",
            resource_type="AWS::S3::Bucket",
            resource_id="arn:aws:s3:::example-corp-backups",
            name="example-corp-backups",
            region="us-east-1",
            status="ACTIVE",
            compliance_status="FAILED",
        ),
        CloudResource(
            organization_id=org.id,
            provider="Azure",
            resource_type="Microsoft.Compute/virtualMachines",
            resource_id="/subscriptions/.../vm1",
            name="az-internal-db",
            region="westeurope",
            status="ACTIVE",
            compliance_status="UNKNOWN",
        )
    ]
    db.add_all(resources)
    
    # Identities
    profiles = [
        IdentityProfile(
            organization_id=org.id,
            email="admin@example.com",
            full_name="System Administrator",
            provider="Entra ID",
            is_active=True,
            mfa_enabled=True,
            last_login=datetime.utcnow() - timedelta(hours=2),
            privilege_level="ADMIN"
        ),
        IdentityProfile(
            organization_id=org.id,
            email="legacy_admin@example.com",
            full_name="Old Admin Account",
            provider="Entra ID",
            is_active=True,
            mfa_enabled=False,
            last_login=datetime.utcnow() - timedelta(days=120),
            privilege_level="ADMIN"
        ),
        IdentityProfile(
            organization_id=org.id,
            email="jdoe@example.com",
            full_name="John Doe",
            provider="Okta",
            is_active=True,
            mfa_enabled=True,
            last_login=datetime.utcnow() - timedelta(days=1),
            privilege_level="USER"
        )
    ]
    db.add_all(profiles)
    
    db.commit()
    print("Seed complete.")

if __name__ == "__main__":
    seed()
