"""
External discovery must not invent inventory.

The behaviour under test is the one the previous implementation got exactly
backwards. Finding no credentials, `discover_cloud_assets` inserted a
`CloudResource` named "Discovery Failed: No active credentials found for AWS",
and `discover_identity` inserted an `IdentityProfile` with the email address
`admin_integration_failed@aws.local` and the display name "Integration Error:
OAuth/SAML configuration missing". Both were then served by their endpoints as
discovered inventory, indistinguishable from real records.

So the central assertion here is a negative one: after an unconfigured or
failing discovery run, the inventory tables are still empty.
"""
from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_db

from app.models.discovery import CloudResource, IdentityProfile
from app.models.integration import IntegrationKind, IntegrationState, IntegrationStatus
from app.services.integrations import cloud as cloud_integrations
from app.services.integrations import identity as identity_integrations
from app.services.integrations.base import AdapterError, DiscoveryResult
from app.tasks import discovery_tasks


@pytest.fixture
def unconfigured_settings(monkeypatch):
    """The shipped default: nothing configured."""
    from app.core.config import settings

    for name in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION",
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "AZURE_SUBSCRIPTION_ID", "OKTA_ORG_URL", "OKTA_API_TOKEN",
    ):
        monkeypatch.setattr(settings, name, "", raising=False)
    return settings


class TestAdapterDescriptions:
    def test_an_unconfigured_cloud_adapter_names_what_is_missing(
        self, unconfigured_settings
    ):
        description = cloud_integrations.AwsAdapter().describe()
        assert description.configured is False
        assert "AWS_ACCESS_KEY_ID" in description.missing
        assert description.why_required
        assert "boto3" in description.how_to_enable
        assert description.implemented_in.endswith("cloud.py")

    def test_an_unconfigured_identity_adapter_names_what_is_missing(
        self, unconfigured_settings
    ):
        description = identity_integrations.OktaAdapter().describe()
        assert description.configured is False
        assert "OKTA_ORG_URL" in description.missing
        assert "OKTA_API_TOKEN" in description.missing
        assert "read-only API token" in description.how_to_enable

    def test_a_configured_adapter_reports_configured(self, unconfigured_settings):
        from app.core.config import settings

        settings.OKTA_ORG_URL = "https://example.okta.com"
        settings.OKTA_API_TOKEN = "token"
        description = identity_integrations.OktaAdapter().describe()
        assert description.configured is True
        assert description.missing == []

    def test_an_unknown_provider_is_refused(self):
        with pytest.raises(AdapterError, match="not a cloud provider"):
            cloud_integrations.get_adapter("Hetzner")


@requires_db
class TestNoFabricatedInventory:
    def test_unconfigured_cloud_discovery_writes_no_resource(
        self, db, organization, unconfigured_settings, monkeypatch
    ):
        monkeypatch.setattr(discovery_tasks, "_session_for", lambda _org: db)
        monkeypatch.setattr(db, "close", lambda: None)

        result = discovery_tasks.discover_cloud_assets(
            "AWS", str(organization.id)
        )

        assert result["succeeded"] is False
        assert db.query(CloudResource).count() == 0

        state = db.query(IntegrationState).filter(
            IntegrationState.organization_id == organization.id,
            IntegrationState.kind == IntegrationKind.CLOUD,
        ).one()
        assert state.status is IntegrationStatus.NOT_CONFIGURED
        assert "AWS_ACCESS_KEY_ID" in state.missing_configuration
        # A failed run must never look like a successful one.
        assert state.last_success_at is None
        assert state.records_discovered == 0

    def test_unconfigured_identity_discovery_writes_no_profile(
        self, db, organization, unconfigured_settings, monkeypatch
    ):
        monkeypatch.setattr(discovery_tasks, "_session_for", lambda _org: db)
        monkeypatch.setattr(db, "close", lambda: None)

        result = discovery_tasks.discover_identity("Okta", str(organization.id))

        assert result["succeeded"] is False
        assert db.query(IdentityProfile).count() == 0

        state = db.query(IntegrationState).filter(
            IntegrationState.kind == IntegrationKind.IDENTITY
        ).one()
        assert state.status is IntegrationStatus.NOT_CONFIGURED

    def test_a_failing_configured_adapter_writes_no_inventory(
        self, db, organization, unconfigured_settings, monkeypatch
    ):
        """A credentialed integration that errors records the error, not a row."""
        from app.core.config import settings

        settings.OKTA_ORG_URL = "https://example.okta.com"
        settings.OKTA_API_TOKEN = "token"

        def _explode(self):
            raise AdapterError("401 Unauthorized: the API token was rejected.")

        monkeypatch.setattr(
            identity_integrations.OktaAdapter, "discover", _explode, raising=True
        )
        monkeypatch.setattr(discovery_tasks, "_session_for", lambda _org: db)
        monkeypatch.setattr(db, "close", lambda: None)

        result = discovery_tasks.discover_identity("Okta", str(organization.id))

        assert result["succeeded"] is False
        assert db.query(IdentityProfile).count() == 0
        state = db.query(IntegrationState).one()
        assert state.status is IntegrationStatus.ERROR
        assert "401 Unauthorized" in state.message

    def test_a_successful_run_writes_the_records_it_actually_read(
        self, db, organization, unconfigured_settings, monkeypatch
    ):
        from app.core.config import settings

        settings.OKTA_ORG_URL = "https://example.okta.com"
        settings.OKTA_API_TOKEN = "token"

        monkeypatch.setattr(
            identity_integrations.OktaAdapter, "discover",
            lambda self: DiscoveryResult(
                succeeded=True,
                records=[
                    {
                        "email": "ada@example.com", "full_name": "Ada Lovelace",
                        "is_active": True, "mfa_enabled": None,
                        "last_login": None, "privilege_level": None,
                    },
                ],
                message="Read 1 account(s).",
            ),
            raising=True,
        )
        monkeypatch.setattr(discovery_tasks, "_session_for", lambda _org: db)
        monkeypatch.setattr(db, "close", lambda: None)

        result = discovery_tasks.discover_identity("Okta", str(organization.id))

        assert result["succeeded"] is True
        profile = db.query(IdentityProfile).one()
        assert profile.email == "ada@example.com"
        # The directory listing does not report factor enrolment. Recording
        # False would assert that MFA is off — a claim the response never made.
        assert profile.mfa_enabled is None
        assert profile.privilege_level == ""

        state = db.query(IntegrationState).one()
        assert state.status is IntegrationStatus.CONNECTED
        assert state.last_success_at is not None
        assert state.records_discovered == 1

    def test_rerunning_updates_rather_than_duplicates(
        self, db, organization, unconfigured_settings, monkeypatch
    ):
        from app.core.config import settings

        settings.OKTA_ORG_URL = "https://example.okta.com"
        settings.OKTA_API_TOKEN = "token"

        monkeypatch.setattr(
            identity_integrations.OktaAdapter, "discover",
            lambda self: DiscoveryResult(
                succeeded=True,
                records=[{
                    "email": "ada@example.com", "full_name": "Ada L.",
                    "is_active": False, "mfa_enabled": True,
                    "last_login": None, "privilege_level": "admin",
                }],
            ),
            raising=True,
        )
        monkeypatch.setattr(discovery_tasks, "_session_for", lambda _org: db)
        monkeypatch.setattr(db, "close", lambda: None)

        discovery_tasks.discover_identity("Okta", str(organization.id))
        discovery_tasks.discover_identity("Okta", str(organization.id))

        profile = db.query(IdentityProfile).one()
        assert profile.is_active is False
        assert profile.mfa_enabled is True
        assert profile.privilege_level == "admin"

    def test_a_record_without_a_provider_identity_is_skipped(
        self, db, organization, unconfigured_settings, monkeypatch
    ):
        """
        A resource with no provider-side id cannot be deduplicated or traced
        back, so it is dropped rather than given an invented identifier.
        """
        written = discovery_tasks._upsert_cloud_resources(
            db, organization.id, "AWS",
            [{"resource_id": "", "name": "nameless"},
             {"resource_id": "i-123", "name": "web-1", "resource_type": "AWS::EC2::Instance"}],
        )
        db.flush()
        assert written == 1
        assert db.query(CloudResource).count() == 1

    def test_reading_an_inventory_asserts_nothing_about_compliance(
        self, db, organization
    ):
        discovery_tasks._upsert_cloud_resources(
            db, organization.id, "AWS",
            [{"resource_id": "i-123", "name": "web-1", "status": "running"}],
        )
        db.flush()
        assert db.query(CloudResource).one().compliance_status == "UNKNOWN"


@requires_db
class TestAttackSurfaceAuthorization:
    def test_probing_an_unregistered_domain_records_a_refusal_and_writes_nothing(
        self, db, organization, monkeypatch
    ):
        from app.models.discovery import AttackSurfaceDomain

        monkeypatch.setattr(discovery_tasks, "_session_for", lambda _org: db)
        monkeypatch.setattr(db, "close", lambda: None)

        result = discovery_tasks.discover_attack_surface(
            "not-registered.example.com", str(organization.id)
        )

        assert result["succeeded"] is False
        assert "not registered as an authorized scope" in result["message"]
        assert db.query(AttackSurfaceDomain).count() == 0
