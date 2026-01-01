"""
Database Configuration and Session Management

Provides SQLAlchemy engine, session management, and RLS utilities.
Implements multitenancy via PostgreSQL RLS (Row-Level Security).
"""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from models import Base

# Set up logging
logger = logging.getLogger(__name__)

# Database URL from environment variable
# Use SQLite for testing if DATABASE_URL is not set
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+pysqlite:///./test_user.db")

# Create engine with connection pooling
# SQLite doesn't support pool_size/max_overflow, so we handle it conditionally
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        echo=os.getenv("SQL_DEBUG", "false").lower() == "true",
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        echo=os.getenv("SQL_DEBUG", "false").lower() == "true",
    )

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency for FastAPI to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Context manager for database session (for use outside FastAPI)."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def set_tenant_id(session: Session, tenant_id: str | UUID) -> None:
    """
    Set the current tenant ID for RLS (Row-Level Security).

    This sets a PostgreSQL session variable that RLS policies use
    to filter data by tenant. MUST be called before any queries
    in a multi-tenant context.

    Args:
        session: SQLAlchemy session
        tenant_id: UUID string or UUID object of the tenant

    Raises:
        ValueError: If tenant_id is invalid
    """
    if tenant_id is None:
        logger.warning("Attempted to set None tenant_id - skipping RLS setup")
        return

    # Convert UUID to string if needed
    tenant_id_str = str(tenant_id)

    # Validate UUID format to prevent SQL injection
    try:
        UUID(tenant_id_str)
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid tenant_id format: {tenant_id_str}")
        raise ValueError(f"Invalid tenant_id format: {tenant_id_str}") from e

    # Only set RLS variable for PostgreSQL
    try:
        session.execute(text(f"SET app.tenant_id = '{tenant_id_str}'"))
        logger.debug(f"RLS tenant_id set to: {tenant_id_str}")
    except Exception as e:
        # Non-PostgreSQL databases will fail - OK for testing with SQLite
        logger.debug(f"Could not set RLS tenant_id (non-PostgreSQL?): {e}")


def reset_tenant_id(session: Session) -> None:
    """Reset the tenant ID session variable."""
    try:
        session.execute(text("RESET app.tenant_id"))
        logger.debug("RLS tenant_id reset")
    except Exception as e:
        logger.warning(f"Failed to reset tenant_id: {e}")


@contextmanager
def tenant_context(
    session: Session, tenant_id: str | UUID
) -> Generator[Session, None, None]:
    """
    Context manager for tenant-scoped database operations.

    Sets the tenant_id for RLS before yielding, and resets it after.
    """
    try:
        set_tenant_id(session, tenant_id)
        yield session
    finally:
        reset_tenant_id(session)


def check_db_connection() -> bool:
    """Check if database connection is healthy."""
    try:
        with get_db_context() as db:
            db.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False


# Initialize tables on module load
try:
    logger.info("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")
except Exception as e:
    logger.error(f"Failed to create database tables: {e}")
    logger.warning(
        "Continuing without table creation - tables may need to be created manually"
    )
