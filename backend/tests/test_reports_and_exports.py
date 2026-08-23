"""
Downloads that actually contain something.

`generate_executive_report` was annotated `-> bytes`, assembled its elements,
and then ended — no `doc.build(...)`, no `return`. It returned `None`, and the
endpoint served HTTP 200 with a PDF filename, a PDF content type, and an empty
body. The download reported success and delivered nothing.

Both report methods also filtered with `Finding.status == "open"`. The column is
an enum stored by member name (`OPEN`), so the predicate matched no rows and
every report stated zero findings regardless of the estate — a fabricated
all-clear, which is the worst direction for that mistake.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import requires_db

from app.core.rbac import RoleName
from app.core.security import create_access_token, hash_password
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.finding import (
    Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.models.user import User
from app.reports.pdf_generator import PDFReportGenerator
from app.services.finding_identity import compute_fingerprint
from app.services.org_provisioning import provision_new_organization

PDF_MAGIC = b"%PDF"

_ROLES: dict = {}


def _user(db, organization, role_name: RoleName = RoleName.ORG_ADMIN) -> User:
    key = (id(db), organization.id)
    if key not in _ROLES:
        _ROLES[key] = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Test User",
        hashed_password=hash_password("irrelevant"),
        is_active=True,
    )
    user.roles = [_ROLES[key][role_name.value]]
    db.add(user)
    db.flush()
    return user


def _finding(db, organization, asset, **overrides) -> Finding:
    values = dict(
        organization_id=organization.id,
        asset_id=asset.id,
        title="Telnet is exposed on the management interface",
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        finding_class=FindingClass.EXPOSURE,
        confidence=Confidence.CONFIRMED,
        source="nmap",
        evidence="23/tcp open telnet",
        remediation_guidance="Disable telnet and use SSH.",
    )
    values.update(overrides)
    values["fingerprint"] = compute_fingerprint(
        asset_id=asset.id, finding_class=values["finding_class"],
        source=values["source"], identifier=values["title"], location="23/tcp",
    )
    record = Finding(**values)
    db.add(record)
    db.flush()
    return record


@requires_db
class TestPdfGeneration:
    def test_the_executive_report_is_a_real_pdf(self, db, organization):
        pdf = PDFReportGenerator(db, organization.id).generate_executive_report()
        assert pdf, "the executive report returned nothing"
        assert pdf.startswith(PDF_MAGIC)
        assert len(pdf) > 1000

    def test_the_technical_report_is_a_real_pdf(self, db, organization, asset):
        _finding(db, organization, asset)
        pdf = PDFReportGenerator(db, organization.id).generate_technical_report()
        assert pdf.startswith(PDF_MAGIC)

    def test_open_findings_are_actually_counted(self, db, organization, asset):
        """
        The enum-versus-string predicate meant this number was always zero.
        A report that says "0 critical" when there are two is not a report.
        """
        _finding(db, organization, asset)
        _finding(
            db, organization, asset, title="SMBv1 enabled",
            severity=Severity.HIGH,
        )
        generator = PDFReportGenerator(db, organization.id)
        assert len(generator._open_findings()) == 2

    def test_closed_findings_are_excluded(self, db, organization, asset):
        _finding(db, organization, asset)
        _finding(
            db, organization, asset, title="Old issue",
            status=FindingStatus.REMEDIATED,
        )
        generator = PDFReportGenerator(db, organization.id)
        assert len(generator._open_findings()) == 1

    def test_another_organizations_findings_are_not_in_the_report(
        self, db, organization, second_organization, asset
    ):
        from app.models.asset import Asset, AssetStatus, AssetType

        _finding(db, organization, asset)
        other_asset = Asset(
            organization_id=second_organization.id, hostname="other",
            asset_type=AssetType.SERVER, status=AssetStatus.ACTIVE,
        )
        db.add(other_asset)
        db.flush()
        _finding(db, second_organization, other_asset, title="Theirs")

        generator = PDFReportGenerator(db, organization.id)
        titles = {finding.title for finding in generator._open_findings()}
        assert "Theirs" not in titles

    def test_a_malformed_scan_id_raises_rather_than_producing_a_report(
        self, db, organization
    ):
        with pytest.raises(ValueError):
            PDFReportGenerator(db, organization.id).generate_technical_report("not-a-uuid")


@requires_db
class TestReportEndpoints:
    @pytest.fixture
    def client(self, db):
        from app.api.v1.endpoints.reports import router

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app)

    @staticmethod
    def _auth(user):
        return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    def test_the_executive_download_has_a_body(self, client, db, organization):
        user = _user(db, organization)
        response = client.get("/reports/executive/pdf", headers=self._auth(user))

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(PDF_MAGIC)
        # The defect this pins down: 200, correct headers, zero bytes.
        assert len(response.content) > 1000

    def test_the_technical_download_has_a_body(self, client, db, organization, asset):
        _finding(db, organization, asset)
        user = _user(db, organization)
        response = client.get("/reports/technical/pdf", headers=self._auth(user))

        assert response.status_code == 200
        assert response.content.startswith(PDF_MAGIC)

    def test_an_export_is_recorded_in_the_audit_log(self, client, db, organization):
        user = _user(db, organization)
        client.get("/reports/executive/pdf", headers=self._auth(user))

        actions = {row.action for row in db.query(AuditLog).all()}
        assert "export_report" in actions


@requires_db
class TestAuditLogFiltersAndExport:
    @pytest.fixture
    def client(self, db):
        from app.api.v1.endpoints.audit_logs import router

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app)

    @staticmethod
    def _auth(user):
        return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    def _entries(self, db, organization, actor):
        from app.services.audit import log_action

        log_action(db, "start_scan", "scan_job", organization.id, actor.id, "s-1",
                   metadata={"target_cidr": "192.168.1.0/24"})
        log_action(db, "delete", "asset", organization.id, actor.id, "a-1")
        log_action(db, "login", "user", organization.id, None, None)

    def test_a_role_without_view_audit_logs_is_refused(self, client, db, organization):
        """
        VIEW_AUDIT_LOGS exists for this. The endpoint previously used
        get_current_active_user, so a helpdesk technician could read the whole
        organization's audit trail.
        """
        from app.core.rbac import DEFAULT_ROLE_PERMISSIONS, Permission

        assert Permission.VIEW_AUDIT_LOGS not in DEFAULT_ROLE_PERMISSIONS[RoleName.HELPDESK]
        helpdesk = _user(db, organization, RoleName.HELPDESK)

        response = client.get("/audit-logs", headers=self._auth(helpdesk))
        assert response.status_code == 403

    def test_an_auditor_may_read_the_log(self, client, db, organization):
        auditor = _user(db, organization, RoleName.AUDITOR)
        response = client.get("/audit-logs", headers=self._auth(auditor))
        assert response.status_code == 200

    def test_filtering_by_action(self, client, db, organization):
        admin = _user(db, organization)
        self._entries(db, organization, admin)

        body = client.get(
            "/audit-logs", params={"action": "start_scan"}, headers=self._auth(admin)
        ).json()
        assert body["total"] == 1
        assert body["items"][0]["action"] == "start_scan"

    def test_searching_by_actor_email(self, client, db, organization):
        admin = _user(db, organization)
        self._entries(db, organization, admin)

        body = client.get(
            "/audit-logs", params={"search": admin.email.split("@")[0]},
            headers=self._auth(admin),
        ).json()
        assert body["total"] >= 2
        assert all(item["actor_email"] == admin.email for item in body["items"])

    def test_searching_by_resource_type(self, client, db, organization):
        admin = _user(db, organization)
        self._entries(db, organization, admin)

        body = client.get(
            "/audit-logs", params={"resource_type": "asset"}, headers=self._auth(admin)
        ).json()
        assert body["total"] == 1

    def test_filter_options_are_derived_from_the_data(self, client, db, organization):
        admin = _user(db, organization)
        self._entries(db, organization, admin)

        body = client.get("/audit-logs/filters", headers=self._auth(admin)).json()
        assert "start_scan" in body["actions"]
        assert "asset" in body["resource_types"]
        assert any(entry["email"] == admin.email for entry in body["actors"])

    def test_the_pdf_export_is_a_real_pdf(self, client, db, organization):
        admin = _user(db, organization)
        self._entries(db, organization, admin)

        response = client.get("/audit-logs/export.pdf", headers=self._auth(admin))
        assert response.status_code == 200
        assert response.content.startswith(PDF_MAGIC)
        assert "attachment" in response.headers["content-disposition"]

    def test_the_export_applies_the_same_filters_as_the_screen(
        self, client, db, organization
    ):
        admin = _user(db, organization)
        self._entries(db, organization, admin)

        filtered = client.get(
            "/audit-logs/export.pdf", params={"action": "start_scan"},
            headers=self._auth(admin),
        )
        unfiltered = client.get("/audit-logs/export.pdf", headers=self._auth(admin))
        assert filtered.status_code == 200
        assert unfiltered.status_code == 200
        assert len(filtered.content) != len(unfiltered.content)

    def test_exporting_an_empty_result_still_produces_a_document(
        self, client, db, organization
    ):
        """It says nothing matched, rather than failing or producing zero bytes."""
        admin = _user(db, organization)
        response = client.get(
            "/audit-logs/export.pdf", params={"action": "nothing-matches-this"},
            headers=self._auth(admin),
        )
        assert response.status_code == 200
        assert response.content.startswith(PDF_MAGIC)

    def test_another_organizations_entries_are_not_returned(
        self, client, db, organization, second_organization
    ):
        from app.services.audit import log_action

        admin = _user(db, organization)
        other = _user(db, second_organization)
        log_action(db, "secret_action", "thing", second_organization.id, other.id, "x")

        body = client.get("/audit-logs", headers=self._auth(admin)).json()
        assert all(item["action"] != "secret_action" for item in body["items"])
