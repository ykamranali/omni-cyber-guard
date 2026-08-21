"""
PostgreSQL row-level security.

Application-level filtering is the first line of tenant isolation; these
policies are the second, and they matter precisely because the first one
depends on a human remembering. Every test here writes a query with *no*
organization filter at all — the kind of query a missed `.filter()` produces —
and asserts the database returns nothing it should not.
"""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from app.db.tenancy import TENANT_TABLES, bypass_tenant, clear_tenant, current_scope, set_tenant
from app.models.asset import Asset
from app.models.finding import Confidence, Finding, FindingClass, Severity


def _asset(db, org, hostname, ip):
    record = Asset(organization_id=org.id, hostname=hostname, ip_address=ip)
    db.add(record)
    db.flush()
    return record


def _finding(db, org, asset, title):
    record = Finding(
        organization_id=org.id,
        asset_id=asset.id,
        fingerprint=uuid.uuid4().hex + uuid.uuid4().hex[:32],
        title=title,
        finding_class=FindingClass.EXPOSURE,
        confidence=Confidence.CONFIRMED,
        severity=Severity.HIGH,
    )
    db.add(record)
    db.flush()
    return record


@pytest.fixture
def two_tenants(db, organization, second_organization):
    mine = _asset(db, organization, "mine", "192.168.1.2")
    theirs = _asset(db, second_organization, "theirs", "192.168.1.3")
    _finding(db, organization, mine, "my finding")
    _finding(db, second_organization, theirs, "their finding")
    db.flush()
    return organization, second_organization


def test_policies_exist_on_every_tenant_table(db):
    protected = {
        row[0] for row in db.execute(
            text("SELECT tablename FROM pg_policies WHERE policyname = 'tenant_isolation'")
        )
    }
    missing = set(TENANT_TABLES) - protected
    assert not missing, f"tables without a tenant_isolation policy: {sorted(missing)}"


def test_policies_are_forced_so_the_owner_cannot_bypass_them(db):
    """Without FORCE, the role that owns the tables ignores its own policies."""
    unforced = [
        row[0] for row in db.execute(
            text(
                "SELECT relname FROM pg_class "
                "WHERE relname = ANY(:tables) AND relrowsecurity AND NOT relforcerowsecurity"
            ),
            {"tables": list(TENANT_TABLES)},
        )
    ]
    assert not unforced, f"row-level security is not forced on: {unforced}"


def test_an_unfiltered_query_only_returns_the_scoped_tenant(db, two_tenants):
    mine, _ = two_tenants
    set_tenant(db, mine.id)

    # Deliberately no organization_id filter — this is the mistake RLS exists
    # to catch.
    hostnames = {asset.hostname for asset in db.query(Asset).all()}
    assert hostnames == {"mine"}


def test_findings_are_isolated_too(db, two_tenants):
    mine, _ = two_tenants
    set_tenant(db, mine.id)
    titles = {finding.title for finding in db.query(Finding).all()}
    assert titles == {"my finding"}


def test_another_tenants_row_cannot_be_fetched_by_id(db, two_tenants):
    mine, theirs = two_tenants
    bypass_tenant(db)
    their_asset_id = db.query(Asset).filter(Asset.organization_id == theirs.id).one().id

    set_tenant(db, mine.id)
    assert db.query(Asset).filter(Asset.id == their_asset_id).first() is None


def test_a_session_with_no_scope_sees_nothing(db, two_tenants):
    """The failure direction matters: an unscoped connection must be blind."""
    clear_tenant(db)
    assert db.query(Asset).count() == 0
    assert db.query(Finding).count() == 0


def test_bypass_sees_every_tenant(db, two_tenants):
    bypass_tenant(db)
    assert {asset.hostname for asset in db.query(Asset).all()} == {"mine", "theirs"}


def test_writing_a_row_for_another_tenant_is_rejected(db, two_tenants):
    """WITH CHECK stops a scoped session from planting data in another tenant."""
    mine, theirs = two_tenants
    set_tenant(db, mine.id)

    # A savepoint keeps the rejected INSERT from poisoning the outer
    # transaction the fixture rolls back.
    savepoint = db.begin_nested()
    db.add(Asset(organization_id=theirs.id, hostname="smuggled", ip_address="10.0.0.1"))
    with pytest.raises(ProgrammingError):
        db.flush()
    savepoint.rollback()


def test_scope_is_readable_for_diagnostics(db, organization):
    set_tenant(db, organization.id)
    scope = current_scope(db)
    assert scope["organization_id"] == str(organization.id)
    assert scope["bypass"] == "off"

    bypass_tenant(db)
    assert current_scope(db)["bypass"] == "on"


def test_row_level_security_is_actually_in_force(db):
    """
    A superuser connection makes every policy inert without any error.

    The application checks this at startup; the test asserts the check reports
    the truth for the role the suite runs as. If this fails, the RLS tests
    above were passing vacuously.
    """
    from app.db.tenancy import rls_effective

    effective, explanation = rls_effective(db)
    assert effective, explanation


def test_the_effectiveness_check_detects_an_unforced_table(db):
    """
    The check has to be able to fail, or it proves nothing.

    Dropping FORCE on one table is the failure mode reachable from inside a
    test: the table owner then silently bypasses that table's policy. (The
    superuser and BYPASSRLS branches cannot be provoked here — the suite
    deliberately runs as a role that has neither privilege, which is the point.)
    """
    from app.db.tenancy import rls_effective

    savepoint = db.begin_nested()
    try:
        db.execute(text("ALTER TABLE assets NO FORCE ROW LEVEL SECURITY"))
        effective, explanation = rls_effective(db)
        assert not effective
        assert "assets" in explanation
        assert "FORCED" in explanation
    finally:
        savepoint.rollback()


def test_the_effectiveness_check_names_the_role_it_verified(db):
    from app.db.tenancy import rls_effective

    effective, explanation = rls_effective(db)
    assert effective
    role = db.execute(text("SELECT current_user")).scalar_one()
    assert role in explanation
