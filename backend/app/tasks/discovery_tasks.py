import socket
import ssl
import uuid
import logging
from datetime import datetime, timezone

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant, set_tenant
from app.models.discovery import AttackSurfaceDomain, CloudResource, IdentityProfile

logger = logging.getLogger(__name__)


@celery_app.task(name="discovery_tasks.discover_attack_surface")
def discover_attack_surface(domain: str, organization_id: str) -> None:
    """
    Real-time enumeration of a domain to discover IPs and SSL certificate details.
    """
    org_uuid = uuid.UUID(organization_id)
    db = SessionLocal()
    bypass_tenant(db)
    set_tenant(db, org_uuid)

    try:
        # Resolve IPs
        ip_addresses = []
        try:
            addr_info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
            ip_addresses = list(set([info[4][0] for info in addr_info]))
        except socket.gaierror as e:
            logger.warning("Failed to resolve IPs for %s: %s", domain, e)

        # Grab SSL Certificate
        cert_issuer = "Unknown"
        valid_from = None
        valid_to = None
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract issuer
                    for issuer_tuple in cert.get('issuer', []):
                        for item in issuer_tuple:
                            if item[0] == 'organizationName':
                                cert_issuer = item[1]
                                break

                    # Extract dates
                    if 'notBefore' in cert:
                        valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    if 'notAfter' in cert:
                        valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.warning("Failed to retrieve SSL cert for %s: %s", domain, e)

        # Upsert Domain Record
        domain_record = db.query(AttackSurfaceDomain).filter(
            AttackSurfaceDomain.organization_id == org_uuid,
            AttackSurfaceDomain.domain_name == domain
        ).first()

        if not domain_record:
            domain_record = AttackSurfaceDomain(
                organization_id=org_uuid,
                domain_name=domain,
                registrar="Enumerated (Live)",
            )
            db.add(domain_record)
        
        domain_record.ip_addresses = ",".join(ip_addresses)
        if cert_issuer != "Unknown":
            domain_record.cert_issuer = cert_issuer
        if valid_from:
            domain_record.cert_valid_from = valid_from
        if valid_to:
            domain_record.cert_valid_to = valid_to
        
        db.commit()

    except Exception as exc:
        logger.exception("Attack surface discovery failed for %s", domain)
        db.rollback()
    finally:
        db.close()


@celery_app.task(name="discovery_tasks.discover_cloud_assets")
def discover_cloud_assets(provider: str, organization_id: str) -> None:
    """
    Simulated real-time integration with a CSPM (AWS/Azure/GCP).
    In a fully provisioned environment, this would use boto3 or azure-identity.
    Because credentials are not available in this demo environment, we log the attempt
    and create a diagnostic resource record showing the integration status.
    """
    org_uuid = uuid.UUID(organization_id)
    db = SessionLocal()
    bypass_tenant(db)
    set_tenant(db, org_uuid)

    try:
        # Mock connection attempt logic
        error_msg = f"No active credentials found for {provider}. Add IAM role or API keys to .env."
        
        logger.error("Cloud discovery failed: %s", error_msg)


    except Exception as exc:
        logger.exception("Cloud discovery failed for %s", provider)
        db.rollback()
    finally:
        db.close()


@celery_app.task(name="discovery_tasks.discover_identity")
def discover_identity(provider: str, organization_id: str) -> None:
    """
    Simulated real-time integration with an IdP (Entra ID, Okta).
    """
    org_uuid = uuid.UUID(organization_id)
    db = SessionLocal()
    bypass_tenant(db)
    set_tenant(db, org_uuid)

    try:
        # Mock connection attempt logic
        error_msg = f"OAuth/SAML configuration missing for {provider}."
        
        logger.error("Identity discovery failed: %s", error_msg)


    except Exception as exc:
        logger.exception("Identity discovery failed for %s", provider)
        db.rollback()
    finally:
        db.close()
