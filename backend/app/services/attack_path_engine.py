import hashlib
import uuid

from sqlalchemy import delete, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.graph import AttackPath


def calculate_attack_paths(db: Session, organization_id: uuid.UUID):
    """
    Computes potential attack paths for the organization.
    
    A foundational attack path in Phase 8:
    Internet -> Asset (Internet Exposed) -> Finding (CRITICAL/HIGH)
    """
    
    # 1. Clear existing unverified attack paths
    db.execute(
        delete(AttackPath).where(
            AttackPath.organization_id == organization_id,
            AttackPath.is_verified == False
        )
    )

    # In a full-blown Neo4j implementation, we would use Cypher. 
    # Here we use SQLAlchemy to find vulnerable internet-exposed assets.
    
    # Find assets that are internet exposed
    # And have OPEN findings that are CRITICAL or HIGH
    
    query = """
    SELECT 
        a.id as asset_id, 
        a.hostname, 
        a.ip_address,
        f.id as finding_id, 
        f.title, 
        f.severity,
        cve.cve_id as cve_id,
        cve.cvss_v3_score as cvss_score
    FROM assets a
    JOIN findings f ON f.asset_id = a.id
    LEFT JOIN cves cve ON f.cve_id = cve.cve_id
    WHERE a.organization_id = :org_id
      AND (a.exposure_breakdown->>'internet_exposed')::boolean = true
      AND f.status = 'OPEN'
      AND f.severity IN ('CRITICAL', 'HIGH')
    """
    
    results = db.execute(text(query), {"org_id": str(organization_id)}).fetchall()
    
    paths_to_insert = []
    
    for row in results:
        asset_id, hostname, ip_address, finding_id, title, severity, cve_id, cvss_score = row
        
        # Build the path structure
        # Step 1: Internet
        # Step 2: Exposed Asset
        # Step 3: Vulnerability
        
        path_nodes = [
            {"type": "External", "name": "Internet", "id": "internet"},
            {"type": "Asset", "name": hostname or ip_address or "Unknown Asset", "id": str(asset_id)},
            {"type": "Finding", "name": title, "id": str(finding_id), "severity": severity, "cvss": cvss_score}
        ]
        
        # Calculate risk score (simplified)
        risk_score = 90.0 if severity == 'CRITICAL' else 70.0
        if cvss_score:
            risk_score = float(cvss_score) * 10
            
        # Signature to avoid duplicates
        signature_base = f"internet->{asset_id}->{finding_id}"
        signature = hashlib.sha256(signature_base.encode()).hexdigest()
        
        paths_to_insert.append({
            "organization_id": organization_id,
            "source_node_id": uuid.UUID(int=0), # Represents Internet
            "source_node_type": "External",
            "target_node_id": finding_id,
            "target_node_type": "Finding",
            "path_edges": [],
            "path_nodes": path_nodes,
            "path_signature": signature,
            "risk_score": risk_score,
            "is_verified": False
        })
        
    if paths_to_insert:
        # Use ON CONFLICT DO NOTHING to preserve verified paths if we switch to an upsert logic
        db.execute(insert(AttackPath).values(paths_to_insert).on_conflict_do_nothing(
            index_elements=['organization_id', 'path_signature']
        ))
        
    db.commit()

