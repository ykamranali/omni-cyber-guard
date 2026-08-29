"""
The tenant scope must follow the Session, not the connection.

This is the regression test for the fault that presented as four unrelated
bugs: scans stuck at queued, sites and networks failing to save, deletes
reporting errors, and CVE Intelligence failing to load.

`set_config(..., is_local => false)` is state on one PostgreSQL *connection*.
SQLAlchemy hands the connection back to the pool when a transaction ends and
takes one again for the next statement, so a request that committed and then
read anything back could be working on a connection another request had since
reset. Row-level security then correctly hid every row — including the one the
session had just written — and the reload raised "Could not refresh instance".

It only happened under pool contention, which is why it never reproduced on
demand and why it looked like a different bug in every screen.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from tests.conftest import TEST_DATABASE_URL, requires_db

from app.db.tenancy import bypass_tenant, clear_tenant, current_scope, set_tenant
from app.models.organization import Organization
from app.models.scan_job import ScanJob, ScanStatus, ScanType


@pytest.fixture
def contended_sessions():
    """
    A pool of exactly one connection: the contention a busy API produces,
    made deterministic. Two sessions here must take turns on one connection,
    which is precisely the situation that lost the scope.
    """
    engine = create_engine(
        TEST_DATABASE_URL,
        pool_pre_ping=True,
        pool_size=1,
        max_overflow=0,
    )
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        yield factory
    finally:
        engine.dispose()


@requires_db
class TestScopeSurvivesConnectionReuse:
    def _organization(self, session) -> uuid.UUID:
        bypass_tenant(session)
        org = session.query(Organization).first()
        if org is None:
            org = Organization(name=f"Scope Test {uuid.uuid4().hex[:6]}", slug=f"scope-{uuid.uuid4().hex[:6]}")
            session.add(org)
            session.flush()
        org_id = org.id
        session.commit()
        return org_id

    def test_a_committed_row_is_still_visible_to_the_session_that_wrote_it(
        self, contended_sessions
    ):
        writer = contended_sessions()
        try:
            org_id = self._organization(writer)
            set_tenant(writer, org_id)

            job = ScanJob(
                organization_id=org_id,
                target_cidr="10.99.0.0/24",
                scan_type=ScanType.PORT_SERVICE_SCAN,
                engine="nmap",
                status=ScanStatus.QUEUED,
            )
            writer.add(job)
            writer.commit()   # the connection goes back to the pool here

            # Another request now takes that connection and, on its way out,
            # resets the scope exactly as get_db's teardown does.
            other = contended_sessions()
            other.execute(text("SELECT 1"))
            clear_tenant(other)
            other.commit()
            other.close()

            # The writer must still be scoped to its own organization.
            assert current_scope(writer)["organization_id"] == str(org_id)

            # And must still be able to see the row it just wrote. Before the
            # fix this raised InvalidRequestError: Could not refresh instance.
            writer.refresh(job)
            assert job.status is ScanStatus.QUEUED

            bypass_tenant(writer)
            writer.execute(text("DELETE FROM scan_jobs WHERE target_cidr = '10.99.0.0/24'"))
            writer.commit()
        finally:
            writer.close()

    def test_bypass_also_survives_connection_reuse(self, contended_sessions):
        """A worker session spanning tenants must not silently narrow to none."""
        worker = contended_sessions()
        try:
            bypass_tenant(worker)
            worker.commit()

            other = contended_sessions()
            other.execute(text("SELECT 1"))
            clear_tenant(other)
            other.commit()
            other.close()

            assert current_scope(worker)["bypass"] == "on"
        finally:
            worker.close()

    def test_a_session_that_never_set_a_scope_is_left_alone(self, contended_sessions):
        """
        The listener keys off the session's own recorded intent, so sessions
        that never asked for a scope — migrations, diagnostics — are untouched.
        """
        plain = contended_sessions()
        try:
            assert plain.info.get("ocg_tenant_scope") is None
            assert plain.execute(text("SELECT 1")).scalar() == 1
        finally:
            plain.close()
