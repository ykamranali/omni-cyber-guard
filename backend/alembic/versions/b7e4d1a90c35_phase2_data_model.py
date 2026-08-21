"""Phase 2: sites, networks, asset detail tables, tags, credential vault,
finding dedup identity, and PostgreSQL row-level security.

Revision ID: b7e4d1a90c35
Revises: a1f0c3d29b74
Create Date: 2026-08-21

Notable behaviour change
------------------------
`assets.scan_job_id` and `findings.scan_job_id` change from ON DELETE CASCADE
to ON DELETE SET NULL. Under the old rule, deleting a scan record destroyed the
assets whose "last scanned by" pointer happened to reference it — including
inventory built up over many previous scans. Asset inventory now outlives the
scan that discovered it.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "b7e4d1a90c35"
down_revision = "a1f0c3d29b74"
branch_labels = None
depends_on = None


ASSET_TYPES = [
    "SERVER", "WORKSTATION", "LAPTOP", "FIREWALL", "ROUTER", "SWITCH",
    "ACCESS_POINT", "PRINTER", "CAMERA", "NVR", "NAS", "PBX", "VOIP",
    "IOT_DEVICE", "OT_DEVICE", "MOBILE_DEVICE", "CLOUD_RESOURCE", "CONTAINER",
    "WEB_SERVER", "DATABASE", "NETWORK_DEVICE", "APPLICATION", "HYPERVISOR",
    "OTHER",
]

FINDING_STATUSES = ["ACKNOWLEDGED", "MITIGATED"]

# Every table carrying organization_id, protected by an RLS policy.
TENANT_TABLES = [
    "assets", "asset_interfaces", "asset_services", "asset_software",
    "asset_tags", "findings", "scan_jobs", "scan_targets", "scan_schedules",
    "compliance_frameworks", "credential_profiles", "blocked_ips", "incidents",
    "dashboard_snapshots", "sites", "networks", "audit_logs", "users", "roles",
]


def _timestamps():
    return (
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def upgrade() -> None:
    # ==================================================================
    # 1. Enum extensions
    # ==================================================================
    # New values cannot be referenced in the transaction that adds them, hence
    # the autocommit block.
    with op.get_context().autocommit_block():
        for value in ASSET_TYPES:
            op.execute(f"ALTER TYPE assettype ADD VALUE IF NOT EXISTS '{value}'")
        for value in FINDING_STATUSES:
            op.execute(f"ALTER TYPE findingstatus ADD VALUE IF NOT EXISTS '{value}'")

    # Enum types are created once here with an explicit guard, and every
    # column below references them with create_type=False. Letting
    # create_table/add_column emit CREATE TYPE implicitly means the same type
    # is created twice in one migration, which fails with DuplicateObject.
    new_enums = {
        "criticality": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSIGNED"],
        "datasensitivity": ["RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC", "UNASSIGNED"],
        "findingclass": ["VULNERABILITY", "EXPOSURE", "MISCONFIGURATION", "COMPLIANCE", "INFORMATIONAL"],
        "confidence": ["CONFIRMED", "PROBABLE", "POSSIBLE"],
        "credentialtype": ["SSH_PASSWORD", "SSH_KEY", "WINDOWS", "SNMP_V2C", "SNMP_V3",
                           "LDAP", "AWS", "AZURE", "GCP", "API_TOKEN", "DATABASE"],
        "targetstatus": ["PENDING", "RUNNING", "COMPLETED", "FAILED", "SKIPPED"],
    }
    for type_name, values in new_enums.items():
        labels = ", ".join(f"'{value}'" for value in values)
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{type_name}') THEN
                    CREATE TYPE {type_name} AS ENUM ({labels});
                END IF;
            END
            $$
            """
        )

    criticality = postgresql.ENUM(name="criticality", create_type=False)
    data_sensitivity = postgresql.ENUM(name="datasensitivity", create_type=False)
    finding_class = postgresql.ENUM(name="findingclass", create_type=False)
    confidence = postgresql.ENUM(name="confidence", create_type=False)
    credential_type = postgresql.ENUM(name="credentialtype", create_type=False)
    target_status = postgresql.ENUM(name="targetstatus", create_type=False)

    # ==================================================================
    # 2. Containment hierarchy: Site -> Network
    # ==================================================================
    op.create_table(
        "sites",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("location", sa.String(255), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("organization_id", "name", name="uq_site_name_per_org"),
    )

    op.create_table(
        "networks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("site_id", UUID(as_uuid=True),
                  sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("cidr", sa.String(64), nullable=False, index=True),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("is_internet_facing", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_authorized_scope", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("authorized_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("authorization_note", sa.Text(), nullable=False, server_default=""),
        *_timestamps(),
        sa.UniqueConstraint("organization_id", "cidr", name="uq_network_cidr_per_org"),
    )

    # ==================================================================
    # 3. Asset tags
    # ==================================================================
    op.create_table(
        "asset_tags",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("color", sa.String(20), nullable=False, server_default="#64748B"),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        *_timestamps(),
        sa.UniqueConstraint("organization_id", "name", name="uq_tag_name_per_org"),
    )

    op.create_table(
        "asset_tag_links",
        sa.Column("asset_id", UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tag_id", UUID(as_uuid=True),
                  sa.ForeignKey("asset_tags.id", ondelete="CASCADE"), primary_key=True),
    )

    # ==================================================================
    # 4. Asset: business context, fingerprinting, lifecycle, exposure
    # ==================================================================
    op.add_column("assets", sa.Column("site_id", UUID(as_uuid=True), nullable=True))
    op.add_column("assets", sa.Column("network_id", UUID(as_uuid=True), nullable=True))
    op.create_foreign_key("fk_assets_site", "assets", "sites", ["site_id"], ["id"], ondelete="SET NULL")
    op.create_foreign_key("fk_assets_network", "assets", "networks", ["network_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_assets_site_id", "assets", ["site_id"])
    op.create_index("ix_assets_network_id", "assets", ["network_id"])
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"])

    op.add_column("assets", sa.Column("model", sa.String(255), nullable=True))
    op.add_column("assets", sa.Column("fingerprint_confidence", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("assets", sa.Column("fingerprint_evidence", sa.JSON(), nullable=True))
    op.add_column("assets", sa.Column("criticality", criticality, nullable=False, server_default="UNASSIGNED"))
    op.add_column("assets", sa.Column("data_sensitivity", data_sensitivity, nullable=False, server_default="UNASSIGNED"))
    op.add_column("assets", sa.Column("is_internet_facing", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("assets", sa.Column("is_production", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("assets", sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.add_column("assets", sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.add_column("assets", sa.Column("exposure_score", sa.Float(), nullable=False, server_default="0"))
    op.add_column("assets", sa.Column("exposure_breakdown", sa.JSON(), nullable=True))
    op.add_column("assets", sa.Column("exposure_calculated_at", sa.DateTime(timezone=True), nullable=True))

    op.execute("UPDATE assets SET fingerprint_evidence = '[]'::json WHERE fingerprint_evidence IS NULL")
    op.execute("UPDATE assets SET exposure_breakdown = '{}'::json WHERE exposure_breakdown IS NULL")
    op.execute("UPDATE assets SET first_seen = created_at, last_seen = updated_at")

    # Inventory must survive deletion of the scan that happened to touch it last.
    op.drop_constraint("assets_scan_job_id_fkey", "assets", type_="foreignkey")
    op.create_foreign_key(
        "assets_scan_job_id_fkey", "assets", "scan_jobs", ["scan_job_id"], ["id"], ondelete="SET NULL"
    )

    # ==================================================================
    # 5. Asset detail tables
    # ==================================================================
    op.create_table(
        "asset_interfaces",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("asset_id", UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("ip_address", sa.String(64), nullable=False, index=True),
        sa.Column("mac_address", sa.String(64), nullable=True, index=True),
        sa.Column("mac_vendor", sa.String(255), nullable=True),
        sa.Column("interface_name", sa.String(128), nullable=True),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        *_timestamps(),
        sa.UniqueConstraint("asset_id", "ip_address", name="uq_interface_ip_per_asset"),
    )

    op.create_table(
        "asset_services",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("asset_id", UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("port", sa.Integer(), nullable=False, index=True),
        sa.Column("protocol", sa.String(16), nullable=False, server_default="tcp"),
        sa.Column("service_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("product", sa.String(255), nullable=False, server_default=""),
        sa.Column("version", sa.String(128), nullable=False, server_default=""),
        sa.Column("banner", sa.Text(), nullable=False, server_default=""),
        sa.Column("cpe", sa.String(512), nullable=True, index=True),
        sa.Column("is_tls", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("state", sa.String(32), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        *_timestamps(),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_service_port_per_asset"),
    )

    op.create_table(
        "asset_software",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("asset_id", UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("asset_service_id", UUID(as_uuid=True),
                  sa.ForeignKey("asset_services.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("vendor", sa.String(255), nullable=False, server_default=""),
        sa.Column("version", sa.String(128), nullable=False, server_default=""),
        sa.Column("cpe", sa.String(512), nullable=True, index=True),
        sa.Column("detection_method", sa.String(64), nullable=False, server_default="service_banner"),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        *_timestamps(),
        sa.UniqueConstraint("asset_id", "name", "version", name="uq_software_version_per_asset"),
    )

    # ==================================================================
    # 6. Credential vault
    # ==================================================================
    op.create_table(
        "credential_profiles",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("created_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("credential_type", credential_type, nullable=False),
        sa.Column("username", sa.String(255), nullable=False, server_default=""),
        sa.Column("domain", sa.String(255), nullable=False, server_default=""),
        # Ciphertext only. There is deliberately no plaintext column.
        sa.Column("secret_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("extra_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("organization_id", "name", name="uq_credential_name_per_org"),
    )

    # ==================================================================
    # 7. Scan targets
    # ==================================================================
    op.create_table(
        "scan_targets",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_job_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("status", target_status, nullable=False, server_default="PENDING"),
        sa.Column("hosts_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_generated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
    )

    # ==================================================================
    # 8. Finding: dedup identity, classification, intelligence, lifecycle
    # ==================================================================
    op.add_column("findings", sa.Column("fingerprint", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("asset_service_id", UUID(as_uuid=True), nullable=True))
    op.add_column("findings", sa.Column("finding_class", finding_class, nullable=False, server_default="INFORMATIONAL"))
    op.add_column("findings", sa.Column("confidence", confidence, nullable=False, server_default="POSSIBLE"))
    op.add_column("findings", sa.Column("cvss_vector", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("cwe_id", sa.String(32), nullable=True))
    op.add_column("findings", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("is_known_exploited", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("findings", sa.Column("exploit_available", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("findings", sa.Column("intelligence_synced_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("affected_product", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("affected_version", sa.String(128), nullable=True))
    op.add_column("findings", sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.add_column("findings", sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.add_column("findings", sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("resolved_by_scan_job_id", UUID(as_uuid=True), nullable=True))

    op.create_foreign_key("fk_findings_asset_service", "findings", "asset_services",
                          ["asset_service_id"], ["id"], ondelete="SET NULL")
    op.create_foreign_key("fk_findings_resolved_by_scan", "findings", "scan_jobs",
                          ["resolved_by_scan_job_id"], ["id"], ondelete="SET NULL")

    op.execute("UPDATE findings SET first_seen = created_at, last_seen = updated_at")

    # Backfill a fingerprint for pre-existing rows.
    #
    # This must reproduce app/services/finding_identity.compute_fingerprint
    # exactly, or rows created before this migration will not deduplicate
    # against rows created after it. chr(31) is the same Unit Separator that
    # function uses; tests/test_finding_identity.py asserts the two agree.
    op.execute(
        """
        UPDATE findings
        SET fingerprint = encode(
            sha256(
                convert_to(
                    asset_id::text || chr(31) ||
                    lower(CASE
                        WHEN cve_id IS NOT NULL THEN 'vulnerability'
                        WHEN source = 'network_scan' THEN 'exposure'
                        ELSE 'informational'
                    END) || chr(31) ||
                    lower(coalesce(source, '')) || chr(31) ||
                    lower(coalesce(cve_id, title)) || chr(31) ||
                    '',
                    'UTF8'
                )
            ),
            'hex'
        )
        WHERE fingerprint IS NULL
        """
    )

    # Classify pre-existing rows from what is actually known about them.
    op.execute("UPDATE findings SET finding_class = 'VULNERABILITY' WHERE cve_id IS NOT NULL")
    op.execute("UPDATE findings SET finding_class = 'EXPOSURE' WHERE source = 'network_scan'")
    op.execute("UPDATE findings SET finding_class = 'MISCONFIGURATION' WHERE source IN ('lynis', 'windows_audit')")
    # A version banner is not a confirmed defect.
    op.execute("UPDATE findings SET confidence = 'PROBABLE' WHERE source = 'network_scan'")

    # Collapse any duplicates the old LIKE-based dedup let through, keeping the
    # earliest row and preserving the true first_seen / occurrence_count.
    op.execute(
        """
        WITH ranked AS (
            SELECT id, asset_id, fingerprint,
                   ROW_NUMBER() OVER (PARTITION BY asset_id, fingerprint ORDER BY created_at) AS rn,
                   COUNT(*)    OVER (PARTITION BY asset_id, fingerprint)                      AS dupes,
                   MIN(created_at) OVER (PARTITION BY asset_id, fingerprint)                  AS earliest,
                   MAX(updated_at) OVER (PARTITION BY asset_id, fingerprint)                  AS latest
            FROM findings
        )
        UPDATE findings f
        SET occurrence_count = r.dupes,
            first_seen = r.earliest,
            last_seen = r.latest
        FROM ranked r
        WHERE f.id = r.id AND r.rn = 1
        """
    )
    op.execute(
        """
        DELETE FROM findings f
        USING (
            SELECT id, ROW_NUMBER() OVER (PARTITION BY asset_id, fingerprint ORDER BY created_at) AS rn
            FROM findings
        ) r
        WHERE f.id = r.id AND r.rn > 1
        """
    )

    op.alter_column("findings", "fingerprint", nullable=False)
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_unique_constraint("uq_finding_fingerprint_per_asset", "findings", ["asset_id", "fingerprint"])
    op.create_index("ix_findings_org_status_severity", "findings", ["organization_id", "status", "severity"])
    op.create_index("ix_findings_org_last_seen", "findings", ["organization_id", "last_seen"])

    op.drop_constraint("findings_scan_job_id_fkey", "findings", type_="foreignkey")
    op.create_foreign_key(
        "findings_scan_job_id_fkey", "findings", "scan_jobs", ["scan_job_id"], ["id"], ondelete="SET NULL"
    )

    # ==================================================================
    # 9. Row-level security
    # ==================================================================
    # Policies are FORCED so they apply to the table owner as well — otherwise
    # the application role, which owns these tables, would bypass them silently
    # and the whole control would be decorative.
    #
    # With neither app.current_org_id nor app.rls_bypass set, current_setting
    # returns NULL, the predicate is NULL, and no rows match. A connection with
    # no scope therefore sees nothing, which is the correct failure direction.
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (
                current_setting('app.rls_bypass', true) = 'on'
                OR organization_id = nullif(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                current_setting('app.rls_bypass', true) = 'on'
                OR organization_id = nullif(current_setting('app.current_org_id', true), '')::uuid
            )
            """
        )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_constraint("findings_scan_job_id_fkey", "findings", type_="foreignkey")
    op.create_foreign_key(
        "findings_scan_job_id_fkey", "findings", "scan_jobs", ["scan_job_id"], ["id"], ondelete="CASCADE"
    )
    op.drop_constraint("uq_finding_fingerprint_per_asset", "findings", type_="unique")
    op.drop_index("ix_findings_org_last_seen", table_name="findings")
    op.drop_index("ix_findings_org_status_severity", table_name="findings")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_constraint("fk_findings_resolved_by_scan", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_asset_service", "findings", type_="foreignkey")
    for column in (
        "resolved_by_scan_job_id", "resolved_at", "occurrence_count", "last_seen",
        "first_seen", "affected_version", "affected_product", "intelligence_synced_at",
        "exploit_available", "is_known_exploited", "epss_score", "cwe_id",
        "cvss_vector", "confidence", "finding_class", "asset_service_id", "fingerprint",
    ):
        op.drop_column("findings", column)

    op.drop_table("scan_targets")
    op.drop_table("credential_profiles")
    op.drop_table("asset_software")
    op.drop_table("asset_services")
    op.drop_table("asset_interfaces")

    op.drop_constraint("assets_scan_job_id_fkey", "assets", type_="foreignkey")
    op.create_foreign_key(
        "assets_scan_job_id_fkey", "assets", "scan_jobs", ["scan_job_id"], ["id"], ondelete="CASCADE"
    )
    for column in (
        "exposure_calculated_at", "exposure_breakdown", "exposure_score", "last_seen",
        "first_seen", "is_production", "is_internet_facing", "data_sensitivity",
        "criticality", "fingerprint_evidence", "fingerprint_confidence", "model",
    ):
        op.drop_column("assets", column)
    op.drop_index("ix_assets_ip_address", table_name="assets")
    op.drop_index("ix_assets_network_id", table_name="assets")
    op.drop_index("ix_assets_site_id", table_name="assets")
    op.drop_constraint("fk_assets_network", "assets", type_="foreignkey")
    op.drop_constraint("fk_assets_site", "assets", type_="foreignkey")
    op.drop_column("assets", "network_id")
    op.drop_column("assets", "site_id")

    op.drop_table("asset_tag_links")
    op.drop_table("asset_tags")
    op.drop_table("networks")
    op.drop_table("sites")

    for enum_name in ("targetstatus", "credentialtype", "confidence", "findingclass",
                      "datasensitivity", "criticality"):
        op.execute(f"DROP TYPE IF EXISTS {enum_name}")
    # Values added to assettype and findingstatus cannot be removed from a
    # PostgreSQL enum; they are left in place and are harmless.
