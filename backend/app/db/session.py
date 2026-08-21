from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Request-scoped database session.

    Opens in bypass so authentication can resolve the bearer token's subject
    before any tenant is known; `get_current_user` immediately narrows the
    session to the authenticated user's organization (see app/core/deps.py).
    The scope is always set explicitly at the start of a request and cleared on
    the way out, so a value left on a pooled connection is never inherited.
    """
    from app.db.tenancy import bypass_tenant, clear_tenant

    db = SessionLocal()
    try:
        if settings.ENABLE_ROW_LEVEL_SECURITY:
            bypass_tenant(db)
        yield db
    finally:
        try:
            if settings.ENABLE_ROW_LEVEL_SECURITY:
                clear_tenant(db)
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
