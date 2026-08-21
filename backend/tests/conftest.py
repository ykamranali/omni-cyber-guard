"""
Shared pytest fixtures.

The schema under test is built by running the real Alembic migration chain,
not `Base.metadata.create_all`. That costs a few seconds per session and buys
two things worth far more: the migrations are proven to apply on every run, and
the tests exercise the row-level security policies, which only exist because a
migration created them.

The models use PostgreSQL-specific types and features (UUID, JSON, RLS), so a
live PostgreSQL is required. CI provides one as a service container; locally,
`docker compose up -d postgres` is enough.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

BACKEND_ROOT = Path(__file__).resolve().parents[1]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql://ocg_user:ocg_password@localhost:5432/omni_cyber_guard_test",
)

# Settings are read at import time, so the target database has to be in the
# environment before any application module loads.
os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ.setdefault("SECRET_KEY", "test-only-secret")
os.environ.setdefault("ENVIRONMENT", "test")


def _postgres_reachable(url: str) -> bool:
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


POSTGRES_AVAILABLE = _postgres_reachable(TEST_DATABASE_URL)

requires_db = pytest.mark.skipif(
    not POSTGRES_AVAILABLE, reason=f"PostgreSQL not reachable at {TEST_DATABASE_URL}"
)


@pytest.fixture(scope="session")
def db_engine():
    if not POSTGRES_AVAILABLE:
        pytest.skip("PostgreSQL not reachable")

    from alembic import command
    from alembic.config import Config

    engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)

    # Start from nothing so the full migration chain is exercised, including
    # the RLS policies and the enum types.
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", TEST_DATABASE_URL)
    command.upgrade(config, "head")

    yield engine
    engine.dispose()


@pytest.fixture
def db(db_engine):
    """
    A session inside a transaction that is rolled back after each test.

    Opens in RLS bypass, matching how a request-scoped session starts before
    authentication has identified a tenant. Tests that care about isolation
    call `set_tenant` explicitly.
    """
    from app.db.tenancy import bypass_tenant

    connection = db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection, autocommit=False, autoflush=False)
    session = Session()
    bypass_tenant(session)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def organization(db):
    from app.models.organization import Organization

    org = Organization(name="Test Org", slug=f"test-org-{uuid.uuid4().hex[:8]}")
    db.add(org)
    db.flush()
    return org


@pytest.fixture
def second_organization(db):
    from app.models.organization import Organization

    org = Organization(name="Other Org", slug=f"other-org-{uuid.uuid4().hex[:8]}")
    db.add(org)
    db.flush()
    return org


@pytest.fixture
def asset(db, organization):
    from app.models.asset import Asset, AssetStatus, AssetType

    record = Asset(
        organization_id=organization.id,
        hostname="test-host",
        ip_address="192.168.1.50",
        asset_type=AssetType.SERVER,
        status=AssetStatus.ACTIVE,
    )
    db.add(record)
    db.flush()
    return record


@pytest.fixture
def scan_job(db, organization):
    from app.models.scan_job import ScanJob, ScanStatus

    job = ScanJob(
        organization_id=organization.id,
        target_cidr="192.168.1.0/24",
        engine="nmap",
        status=ScanStatus.RUNNING,
    )
    db.add(job)
    db.flush()
    return job
