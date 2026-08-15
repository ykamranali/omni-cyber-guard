"""
Role-Based Access Control definitions.

Defines the fixed set of platform roles and the granular permissions each
role holds by default. Organization Administrators may further customize
permissions per-role within their own organization (stored in the
role_permissions association table).
"""
from enum import Enum


class RoleName(str, Enum):
    SUPER_ADMIN = "super_administrator"
    ORG_ADMIN = "organization_administrator"
    SECURITY_MANAGER = "security_manager"
    SECURITY_ANALYST = "security_analyst"
    IT_ADMIN = "it_administrator"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR = "auditor"
    HELPDESK = "helpdesk_technician"
    READ_ONLY = "read_only_user"


class Permission(str, Enum):
    # Platform administration (super admin only)
    MANAGE_PLATFORM = "manage_platform"
    MANAGE_ORGANIZATIONS = "manage_organizations"

    # Organization administration
    MANAGE_ORG_SETTINGS = "manage_org_settings"
    MANAGE_USERS = "manage_users"
    MANAGE_ROLES = "manage_roles"
    MANAGE_BRANDING = "manage_branding"
    MANAGE_API_KEYS = "manage_api_keys"

    # Assets
    VIEW_ASSETS = "view_assets"
    MANAGE_ASSETS = "manage_assets"

    # Vulnerabilities / findings
    VIEW_FINDINGS = "view_findings"
    MANAGE_FINDINGS = "manage_findings"
    RUN_SCANS = "run_scans"

    # Compliance
    VIEW_COMPLIANCE = "view_compliance"
    MANAGE_COMPLIANCE = "manage_compliance"

    # Reporting
    VIEW_REPORTS = "view_reports"
    GENERATE_REPORTS = "generate_reports"

    # Audit
    VIEW_AUDIT_LOGS = "view_audit_logs"


DEFAULT_ROLE_PERMISSIONS: dict[RoleName, list[Permission]] = {
    RoleName.SUPER_ADMIN: list(Permission),
    RoleName.ORG_ADMIN: [
        Permission.MANAGE_ORG_SETTINGS, Permission.MANAGE_USERS, Permission.MANAGE_ROLES,
        Permission.MANAGE_BRANDING, Permission.MANAGE_API_KEYS, Permission.VIEW_ASSETS,
        Permission.MANAGE_ASSETS, Permission.VIEW_FINDINGS, Permission.MANAGE_FINDINGS,
        Permission.RUN_SCANS, Permission.VIEW_COMPLIANCE, Permission.MANAGE_COMPLIANCE,
        Permission.VIEW_REPORTS, Permission.GENERATE_REPORTS, Permission.VIEW_AUDIT_LOGS,
    ],
    RoleName.SECURITY_MANAGER: [
        Permission.VIEW_ASSETS, Permission.MANAGE_ASSETS, Permission.VIEW_FINDINGS,
        Permission.MANAGE_FINDINGS, Permission.RUN_SCANS, Permission.VIEW_COMPLIANCE,
        Permission.MANAGE_COMPLIANCE, Permission.VIEW_REPORTS, Permission.GENERATE_REPORTS,
    ],
    RoleName.SECURITY_ANALYST: [
        Permission.VIEW_ASSETS, Permission.VIEW_FINDINGS, Permission.MANAGE_FINDINGS,
        Permission.RUN_SCANS, Permission.VIEW_COMPLIANCE, Permission.VIEW_REPORTS,
    ],
    RoleName.IT_ADMIN: [
        Permission.VIEW_ASSETS, Permission.MANAGE_ASSETS, Permission.VIEW_FINDINGS,
        Permission.VIEW_REPORTS,
    ],
    RoleName.COMPLIANCE_OFFICER: [
        Permission.VIEW_ASSETS, Permission.VIEW_FINDINGS, Permission.VIEW_COMPLIANCE,
        Permission.MANAGE_COMPLIANCE, Permission.VIEW_REPORTS, Permission.GENERATE_REPORTS,
    ],
    RoleName.AUDITOR: [
        Permission.VIEW_ASSETS, Permission.VIEW_FINDINGS, Permission.VIEW_COMPLIANCE,
        Permission.VIEW_REPORTS, Permission.VIEW_AUDIT_LOGS,
    ],
    RoleName.HELPDESK: [
        Permission.VIEW_ASSETS, Permission.VIEW_FINDINGS,
    ],
    RoleName.READ_ONLY: [
        Permission.VIEW_ASSETS, Permission.VIEW_FINDINGS, Permission.VIEW_COMPLIANCE,
        Permission.VIEW_REPORTS,
    ],
}
