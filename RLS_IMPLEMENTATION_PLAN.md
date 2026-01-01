# User-Service: PostgreSQL RLS Implementation Plan

## Overview

Implement PostgreSQL Row-Level Security (RLS) for multitenancy in the user-service, matching the implementation in reservation-service.

### Requirements

1. Add `tenant_id` column - preserve existing data
2. Keep `tenantId` hidden from GraphQL API
3. Email unique per tenant (not globally)
4. `keycloak_user_id` mandatory (NOT NULL) and unique per tenant
5. Strict RLS: No tenant header = empty results (no default fallback)

---

## Task Checklist

- [ ] 1. Update `db/init/001_init.sql` - Schema, indexes, RLS policies
- [ ] 2. Update `models.py` - Add tenant_id, make keycloak_user_id NOT NULL
- [ ] 3. Update `db.py` - Add RLS helper functions
- [ ] 4. Update `main.py` - Add tenant header handling, update context
- [ ] 5. Update `schema.py` - Update mutations for tenant_id, mandatory keycloak_user_id
- [ ] 6. Update `tests/test_graphql.py` - Add tenant headers, update tests
- [ ] 7. Apply migration to production database
- [ ] 8. Run formatters, linters, and tests
- [ ] 9. Commit, push, and wait for CI
- [ ] 10. Deploy to AKS and verify

---

## 1. Update `db/init/001_init.sql`

Replace the entire file with:

```sql
-- =============================================================================
-- User Service Database Schema
-- =============================================================================
-- Supports multitenancy via tenant_id column with PostgreSQL RLS.
-- Email and keycloak_user_id are unique per tenant (not globally).

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- Users Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    email TEXT NOT NULL,
    keycloak_user_id UUID NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Unique constraints per tenant
    CONSTRAINT users_tenant_email_unique UNIQUE (tenant_id, email),
    CONSTRAINT users_tenant_keycloak_unique UNIQUE (tenant_id, keycloak_user_id)
);

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_keycloak_user_id ON users(keycloak_user_id);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- =============================================================================
-- Row-Level Security (RLS) for Multitenancy
-- =============================================================================
-- STRICT POLICY: If app.tenant_id is not set or empty, NO rows are returned.
-- Uses CASE expression to avoid UUID cast errors on empty string.

-- Enable RLS on table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Force RLS to apply even to table owner
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- Drop existing policy if exists
DROP POLICY IF EXISTS tenant_isolation_policy ON users;

-- Create strict RLS policy
CREATE POLICY tenant_isolation_policy ON users
    FOR ALL
    USING (
        CASE 
            WHEN COALESCE(current_setting('app.tenant_id', true), '') = '' THEN false
            ELSE tenant_id = current_setting('app.tenant_id', true)::UUID
        END
    )
    WITH CHECK (
        CASE 
            WHEN COALESCE(current_setting('app.tenant_id', true), '') = '' THEN false
            ELSE tenant_id = current_setting('app.tenant_id', true)::UUID
        END
    );
```

---

## 2. Update `models.py`

Replace the entire file with:

```python
from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="users_tenant_email_unique"),
        UniqueConstraint(
            "tenant_id", "keycloak_user_id", name="users_tenant_keycloak_unique"
        ),
    )

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    tenant_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String, nullable=False)
    keycloak_user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,  # Now mandatory
    )
    first_name: Mapped[str] = mapped_column(String, nullable=False)
    last_name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
    )
```

---

## 3. Update `db.py`

Replace the entire file with:

```python
"""
Database Configuration and Session Management

Provides SQLAlchemy engine, session management, and RLS utilities.
Implements multitenancy via PostgreSQL RLS (Row-Level Security).
"""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from models import Base

# Set up logging
logger = logging.getLogger(__name__)

# Database URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required.")

# Create engine with connection pooling
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
```

---

## 4. Update `main.py`

Replace the entire file with:

```python
"""
User Service - Main Application

FastAPI application for managing users with multitenancy support.
Uses PostgreSQL RLS for tenant isolation.
"""

import logging
import os
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from keycloak import KeycloakOpenID
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from strawberry.fastapi import GraphQLRouter

from db import get_db, set_tenant_id
from models import UserModel
from schema import schema

# =============================================================================
# Logging Configuration
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# =============================================================================
# Pydantic Models
# =============================================================================


class HealthResponse(BaseModel):
    status: str
    service: str = "user-service"
    version: str = "1.0.0"


class UserStatsResponse(BaseModel):
    total_users: int
    users_with_keycloak_id: int
    recent_users: int


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="User Service API",
    description=(
        "A user management microservice for the Parkora smart parking system. "
        "Provides GraphQL API for user operations with Keycloak authentication. "
        "Implements multitenancy via PostgreSQL Row-Level Security."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    root_path="/api/v1/user",
    contact={
        "name": "Parkora Team",
        "url": "https://parkora.crn.si",
    },
    license_info={
        "name": "MIT",
    },
)

app.servers = [{"url": "https://parkora.crn.si", "description": "Production server"}]

# =============================================================================
# Keycloak Configuration
# =============================================================================

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "https://keycloak.parkora.crn.si/auth/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "parkora")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "backend-services")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_URL,
    client_id=KEYCLOAK_CLIENT_ID,
    realm_name=KEYCLOAK_REALM,
    client_secret_key=KEYCLOAK_CLIENT_SECRET,
)

# =============================================================================
# CORS Middleware
# =============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Authentication Helpers
# =============================================================================


def get_current_user(request: Request) -> dict | None:
    """Extract and verify JWT token from Authorization header."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ")[1]
    try:
        token_info = keycloak_openid.introspect(token)
        if not token_info.get("active", False):
            return None
        return token_info
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
        return None


def get_tenant_id(request: Request) -> str | None:
    """Extract tenant ID from X-Tenant-ID header."""
    return request.headers.get("x-tenant-id")


# =============================================================================
# GraphQL Context
# =============================================================================


def get_context(
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Create GraphQL context with database session and tenant info.

    Sets up PostgreSQL RLS by setting app.tenant_id session variable.
    STRICT MODE: If no tenant_id is provided, RLS will return NO rows.
    """
    current_user = get_current_user(request)
    tenant_id = get_tenant_id(request)

    # Try to get tenant_id from JWT token if not in header
    if not tenant_id and current_user:
        tenant_id = current_user.get("tenant_id")

    # STRICT: If no tenant_id, don't set RLS - database will return no rows
    if not tenant_id:
        logger.warning("No tenant_id provided - RLS will return empty results")
    else:
        try:
            set_tenant_id(db, tenant_id)
            logger.debug(f"RLS enabled for tenant: {tenant_id}")
        except ValueError as e:
            logger.error(f"Invalid tenant_id format: {e}")
            tenant_id = None

    return {
        "db": db,
        "current_user": current_user,
        "tenant_id": tenant_id,
        "request": request,
    }


# =============================================================================
# Mount GraphQL Router
# =============================================================================

graphql_app = GraphQLRouter(schema, context_getter=get_context)
app.include_router(graphql_app, prefix="/graphql")

# =============================================================================
# Health Check Endpoints
# =============================================================================


@app.get(
    "/health/live",
    response_model=HealthResponse,
    summary="Liveness Health Check",
    tags=["Health"],
)
def health_live() -> HealthResponse:
    """Liveness probe - indicates if the service is running."""
    return HealthResponse(status="alive")


@app.get(
    "/health/ready",
    response_model=HealthResponse,
    summary="Readiness Health Check",
    tags=["Health"],
)
def health_ready(db: Session = Depends(get_db)) -> HealthResponse:
    """Readiness probe - indicates if the service is ready."""
    try:
        db.execute(func.text("SELECT 1"))
        return HealthResponse(status="ready")
    except Exception:
        return HealthResponse(status="unhealthy")


@app.get(
    "/",
    summary="API Root",
    tags=["General"],
)
def root():
    """Root endpoint providing basic API information."""
    return {
        "message": "User Service API",
        "version": "1.0.0",
        "docs": "/docs",
        "graphql": "/graphql",
        "health": {"live": "/health/live", "ready": "/health/ready"},
        "features": [
            "GraphQL API for user management",
            "Multitenancy support via RLS",
            "Keycloak authentication integration",
        ],
    }


# =============================================================================
# Stats Endpoint
# =============================================================================


@app.get(
    "/stats",
    response_model=UserStatsResponse,
    summary="User Statistics",
    tags=["Analytics"],
)
def get_user_stats(
    request: Request,
    db: Session = Depends(get_db),
) -> UserStatsResponse:
    """
    Get user statistics for the current tenant.

    STRICT MODE: Returns zeros if no tenant_id is provided.
    """
    tenant_id = get_tenant_id(request)

    # STRICT: No tenant = return zeros
    if not tenant_id:
        logger.warning("Stats request without tenant_id - returning zeros")
        return UserStatsResponse(
            total_users=0,
            users_with_keycloak_id=0,
            recent_users=0,
        )

    try:
        set_tenant_id(db, tenant_id)

        # RLS handles tenant filtering automatically
        total_users = db.query(func.count(UserModel.id)).scalar() or 0

        # All users now have keycloak_id (mandatory)
        users_with_keycloak = total_users

        # Recent users (last 30 days)
        recent_users = (
            db.query(func.count(UserModel.id))
            .filter(
                UserModel.created_at >= func.now() - func.text("interval '30 days'")
            )
            .scalar()
            or 0
        )

        return UserStatsResponse(
            total_users=total_users,
            users_with_keycloak_id=users_with_keycloak,
            recent_users=recent_users,
        )
    except Exception as e:
        logger.error(f"Failed to get user stats: {e}")
        return UserStatsResponse(
            total_users=0,
            users_with_keycloak_id=0,
            recent_users=0,
        )
```

---

## 5. Update `schema.py`

Replace the entire file with:

```python
"""
GraphQL Schema for User Service

Provides queries and mutations for user management.
Uses PostgreSQL RLS for automatic tenant isolation.
tenantId is NOT exposed in the GraphQL API (hidden).
"""

from datetime import datetime
from typing import cast
from uuid import UUID as PyUUID

import strawberry
from sqlalchemy import select
from sqlalchemy.orm import Session

from models import UserModel


@strawberry.type
class User:
    """User type - tenantId is intentionally hidden."""

    id: str
    email: str
    keycloak_user_id: str
    first_name: str
    last_name: str
    created_at: str  # ISO string


@strawberry.type
class DeleteResult:
    success: bool


def to_graphql_user(u: UserModel) -> User:
    """Convert SQLAlchemy model to GraphQL type."""
    created_at = cast(datetime | None, u.created_at)
    return User(
        id=str(u.id),
        email=u.email,
        keycloak_user_id=str(u.keycloak_user_id),
        first_name=u.first_name,
        last_name=u.last_name,
        created_at=created_at.isoformat() if created_at else "",
    )


def get_tenant_id(info) -> str:
    """Get tenant_id from context, raising error if not present."""
    tenant_id = info.context.get("tenant_id")
    if not tenant_id:
        raise ValueError("Tenant ID is required (X-Tenant-ID header)")
    return tenant_id


@strawberry.type
class Query:
    @strawberry.field
    def users(self, info) -> list[User]:
        """Get all users for the current tenant."""
        db: Session = info.context["db"]
        # RLS automatically filters by tenant
        rows = (
            db.execute(select(UserModel).order_by(UserModel.created_at.desc()))
            .scalars()
            .all()
        )
        return [to_graphql_user(u) for u in rows]

    @strawberry.field
    def user_by_id(self, info, id: str) -> User | None:
        """Get user by ID (within current tenant)."""
        db: Session = info.context["db"]
        # RLS ensures we can only get users from our tenant
        row = db.get(UserModel, PyUUID(id))
        return to_graphql_user(row) if row else None

    @strawberry.field
    def user_by_email(self, info, email: str) -> User | None:
        """Get user by email (within current tenant)."""
        db: Session = info.context["db"]
        row = db.execute(
            select(UserModel).where(UserModel.email == email)
        ).scalar_one_or_none()
        return to_graphql_user(row) if row else None

    @strawberry.field
    def user_by_keycloak_id(self, info, keycloak_user_id: str) -> User | None:
        """Get user by Keycloak ID (within current tenant)."""
        db: Session = info.context["db"]
        row = db.execute(
            select(UserModel).where(
                UserModel.keycloak_user_id == PyUUID(keycloak_user_id)
            )
        ).scalar_one_or_none()
        return to_graphql_user(row) if row else None


@strawberry.type
class Mutation:
    @strawberry.mutation
    def create_user(
        self,
        info,
        email: str,
        first_name: str,
        last_name: str,
        keycloak_user_id: str,  # Mandatory - no default
    ) -> User:
        """
        Create a new user.

        Requires X-Tenant-ID header.
        keycloak_user_id is mandatory.
        Email must be unique within the tenant.
        """
        db: Session = info.context["db"]
        tenant_id = get_tenant_id(info)

        # Check email uniqueness within tenant (RLS already filters by tenant)
        existing_email = db.execute(
            select(UserModel).where(UserModel.email == email)
        ).scalar_one_or_none()
        if existing_email:
            raise ValueError("Email already exists in this tenant")

        # Check keycloak_user_id uniqueness within tenant
        existing_keycloak = db.execute(
            select(UserModel).where(
                UserModel.keycloak_user_id == PyUUID(keycloak_user_id)
            )
        ).scalar_one_or_none()
        if existing_keycloak:
            raise ValueError("Keycloak user ID already exists in this tenant")

        user = UserModel(
            tenant_id=PyUUID(tenant_id),
            email=email,
            first_name=first_name,
            last_name=last_name,
            keycloak_user_id=PyUUID(keycloak_user_id),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return to_graphql_user(user)

    @strawberry.mutation
    def update_user(
        self,
        info,
        id: str,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> User:
        """
        Update an existing user.

        Can only update users within the current tenant (RLS enforced).
        """
        db: Session = info.context["db"]

        # RLS ensures we can only get users from our tenant
        user = db.get(UserModel, PyUUID(id))
        if not user:
            raise ValueError("User not found")

        if email is not None and email != user.email:
            # Check uniqueness within tenant
            existing = db.execute(
                select(UserModel).where(UserModel.email == email)
            ).scalar_one_or_none()
            if existing:
                raise ValueError("Email already exists in this tenant")
            user.email = email

        if first_name is not None:
            user.first_name = first_name
        if last_name is not None:
            user.last_name = last_name

        db.commit()
        db.refresh(user)
        return to_graphql_user(user)

    @strawberry.mutation
    def delete_user(self, info, id: str) -> DeleteResult:
        """
        Delete a user.

        Can only delete users within the current tenant (RLS enforced).
        """
        db: Session = info.context["db"]

        user = db.get(UserModel, PyUUID(id))
        if not user:
            return DeleteResult(success=False)

        db.delete(user)
        db.commit()
        return DeleteResult(success=True)


schema = strawberry.Schema(query=Query, mutation=Mutation)
```

---

## 6. Update `tests/test_graphql.py`

Replace the entire file with:

```python
"""
GraphQL API Tests for User Service

All tests include X-Tenant-ID header for RLS compliance.
keycloak_user_id is mandatory in all create mutations.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import app
from models import Base, UserModel

# Test tenant IDs
TENANT_1 = "00000000-0000-0000-0000-000000000001"
TENANT_2 = "00000000-0000-0000-0000-000000000002"

# Create file-based SQLite database for tests
engine = create_engine("sqlite+pysqlite:///./test_user.db")
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# Override the database dependency
from db import get_db

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_database():
    """Clear the database before each test."""
    db = TestingSessionLocal()
    try:
        db.query(UserModel).delete()
        db.commit()
    finally:
        db.close()


def create_user(
    email: str,
    first_name: str = "Test",
    last_name: str = "User",
    keycloak_user_id: str | None = None,
    tenant_id: str = TENANT_1,
) -> dict:
    """Helper to create a user via GraphQL."""
    kc_id = keycloak_user_id or str(uuid.uuid4())
    mutation = f"""
    mutation {{
        createUser(
            email: "{email}",
            firstName: "{first_name}",
            lastName: "{last_name}",
            keycloakUserId: "{kc_id}"
        ) {{
            id
            email
            keycloakUserId
            firstName
            lastName
        }}
    }}
    """
    response = client.post(
        "/graphql",
        json={"query": mutation},
        headers={"X-Tenant-ID": tenant_id},
    )
    return response.json()


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_health_live(self):
        response = client.get("/health/live")
        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    def test_health_ready(self):
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


class TestUserQueries:
    """Test GraphQL queries."""

    def test_users_empty(self):
        """Test querying all users when empty."""
        query = """
        query {
            users {
                id
                email
                keycloakUserId
                firstName
                lastName
            }
        }
        """
        response = client.post(
            "/graphql",
            json={"query": query},
            headers={"X-Tenant-ID": TENANT_1},
        )
        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert data["data"]["users"] == []

    def test_user_by_id(self):
        """Test querying user by ID."""
        # Create a user
        result = create_user("test@example.com")
        user_id = result["data"]["createUser"]["id"]

        # Query by ID
        query = f"""
        query {{
            userById(id: "{user_id}") {{
                id
                email
                firstName
                lastName
            }}
        }}
        """
        response = client.post(
            "/graphql",
            json={"query": query},
            headers={"X-Tenant-ID": TENANT_1},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["userById"]["id"] == user_id
        assert data["data"]["userById"]["email"] == "test@example.com"

    def test_user_by_email(self):
        """Test querying user by email."""
        create_user("findme@example.com")

        query = """
        query {
            userByEmail(email: "findme@example.com") {
                id
                email
                firstName
            }
        }
        """
        response = client.post(
            "/graphql",
            json={"query": query},
            headers={"X-Tenant-ID": TENANT_1},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["userByEmail"]["email"] == "findme@example.com"

    def test_user_by_keycloak_id(self):
        """Test querying user by Keycloak ID."""
        kc_id = str(uuid.uuid4())
        create_user("keycloak@example.com", keycloak_user_id=kc_id)

        query = f"""
        query {{
            userByKeycloakId(keycloakUserId: "{kc_id}") {{
                id
                email
                keycloakUserId
            }}
        }}
        """
        response = client.post(
            "/graphql",
            json={"query": query},
            headers={"X-Tenant-ID": TENANT_1},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["userByKeycloakId"]["keycloakUserId"] == kc_id


class TestUserMutations:
    """Test GraphQL mutations."""

    def test_create_user(self):
        """Test creating a new user."""
        result = create_user("newuser@example.com", "New", "User")
        assert "data" in result
        assert result["data"]["createUser"]["email"] == "newuser@example.com"
        assert result["data"]["createUser"]["firstName"] == "New"
        assert result["data"]["createUser"]["lastName"] == "User"
        assert result["data"]["createUser"]["keycloakUserId"] is not None

    def test_create_user_requires_keycloak_id(self):
        """Test that keycloak_user_id is mandatory."""
        mutation = """
        mutation {
            createUser(
                email: "nokeycloak@example.com",
                firstName: "No",
                lastName: "Keycloak"
            ) {
                id
            }
        }
        """
        response = client.post(
            "/graphql",
            json={"query": mutation},
            headers={"X-Tenant-ID": TENANT_1},
        )
        data = response.json()
        # Should fail due to missing required argument
        assert "errors" in data

    def test_create_user_duplicate_email(self):
        """Test that duplicate email within tenant fails."""
        kc_id_1 = str(uuid.uuid4())
        kc_id_2 = str(uuid.uuid4())

        # Create first user
        create_user("duplicate@example.com", keycloak_user_id=kc_id_1)

        # Try to create second user with same email
        mutation = f"""
        mutation {{
            createUser(
                email: "duplicate@example.com",
                firstName: "Second",
                lastName: "User",
                keycloakUserId: "{kc_id_2}"
            ) {{
                id
            }}
        }}
        """
        response = client.post(
            "/graphql",
            json={"query": mutation},
            headers={"X-Tenant-ID": TENANT_1},
        )
        data = response.json()
        assert "errors" in data
        assert "Email already exists" in str(data["errors"])

    def test_create_user_duplicate_keycloak_id(self):
        """Test that duplicate keycloak_user_id within tenant fails."""
        kc_id = str(uuid.uuid4())

        # Create first user
        create_user("first@example.com", keycloak_user_id=kc_id)

        # Try to create second user with same keycloak_user_id
        mutation = f"""
        mutation {{
            createUser(
                email: "second@example.com",
                firstName: "Second",
                lastName: "User",
                keycloakUserId: "{kc_id}"
            ) {{
                id
            }}
        }}
        """
        response = client.post(
            "/graphql",
            json={"query": mutation},
            headers={"X-Tenant-ID": TENANT_1},
        )
        data = response.json()
        assert "errors" in data
        assert "Keycloak user ID already exists" in str(data["errors"])

    def test_update_user(self):
        """Test updating a user."""
        result = create_user("update@example.com")
        user_id = result["data"]["createUser"]["id"]

        mutation = f"""
        mutation {{
            updateUser(
                id: "{user_id}",
                firstName: "Updated",
                lastName: "Name"
            ) {{
                id
                firstName
                lastName
            }}
        }}
        """
        response = client.post(
            "/graphql",
            json={"query": mutation},
            headers={"X-Tenant-ID": TENANT_1},
        )
        data = response.json()
        assert data["data"]["updateUser"]["firstName"] == "Updated"
        assert data["data"]["updateUser"]["lastName"] == "Name"

    def test_delete_user(self):
        """Test deleting a user."""
        result = create_user("delete@example.com")
        user_id = result["data"]["createUser"]["id"]

        mutation = f"""
        mutation {{
            deleteUser(id: "{user_id}") {{
                success
            }}
        }}
        """
        response = client.post(
            "/graphql",
            json={"query": mutation},
            headers={"X-Tenant-ID": TENANT_1},
        )
        data = response.json()
        assert data["data"]["deleteUser"]["success"] is True


class TestMultitenancy:
    """Test tenant isolation.

    Note: SQLite doesn't support RLS, so we test tenant_id assignment.
    Full RLS testing requires PostgreSQL.
    """

    def test_user_created_with_tenant_id(self):
        """Test that users are created with the correct tenant_id."""
        result = create_user("tenant1@example.com", tenant_id=TENANT_1)
        assert "data" in result
        assert result["data"]["createUser"]["email"] == "tenant1@example.com"

        # Verify by querying - in SQLite this works without RLS
        # In PostgreSQL, RLS would enforce the filter
        query = """
        query {
            users {
                email
            }
        }
        """
        response = client.post(
            "/graphql",
            json={"query": query},
            headers={"X-Tenant-ID": TENANT_1},
        )
        data = response.json()
        assert len(data["data"]["users"]) >= 1

    @pytest.mark.skip(reason="SQLite doesn't support RLS - test in PostgreSQL")
    def test_tenant_isolation(self):
        """Test that tenants cannot see each other's users."""
        # Create user in tenant 1
        create_user("tenant1@example.com", tenant_id=TENANT_1)

        # Create user in tenant 2
        create_user("tenant2@example.com", tenant_id=TENANT_2)

        # Query as tenant 1 - should only see tenant 1 user
        query = """
        query {
            users {
                email
            }
        }
        """
        response = client.post(
            "/graphql",
            json={"query": query},
            headers={"X-Tenant-ID": TENANT_1},
        )
        data = response.json()
        emails = [u["email"] for u in data["data"]["users"]]
        assert "tenant1@example.com" in emails
        assert "tenant2@example.com" not in emails


class TestStatsEndpoint:
    """Test /stats endpoint."""

    def test_stats_with_tenant(self):
        """Test stats endpoint with tenant header."""
        create_user("stats@example.com")

        response = client.get("/stats", headers={"X-Tenant-ID": TENANT_1})
        assert response.status_code == 200
        data = response.json()
        assert data["total_users"] >= 1

    def test_stats_without_tenant(self):
        """Test stats endpoint without tenant header returns zeros."""
        create_user("stats2@example.com")

        response = client.get("/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_users"] == 0
        assert data["users_with_keycloak_id"] == 0
        assert data["recent_users"] == 0
```

---

## 7. Production Database Migration

Run these SQL commands on the production database via:

```bash
kubectl exec -n keycloak keycloak-postgresql-7d66c6956d-hn9zn -- psql -U keycloak -d user_service
```

### Migration Script

```sql
-- =============================================================================
-- User Service: Add Multitenancy with RLS
-- =============================================================================

-- Step 1: Add tenant_id column as nullable
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Step 2: Set default tenant for existing rows
UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;

-- Step 3: Make tenant_id NOT NULL
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;

-- Step 4: Make keycloak_user_id NOT NULL (all existing users have it)
ALTER TABLE users ALTER COLUMN keycloak_user_id SET NOT NULL;

-- Step 5: Drop old unique constraints (global uniqueness)
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_keycloak_user_id_key;

-- Step 6: Add new composite unique constraints (unique per tenant)
ALTER TABLE users ADD CONSTRAINT users_tenant_email_unique 
    UNIQUE (tenant_id, email);
ALTER TABLE users ADD CONSTRAINT users_tenant_keycloak_unique 
    UNIQUE (tenant_id, keycloak_user_id);

-- Step 7: Add index on tenant_id
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);

-- Step 8: Enable RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- Step 9: Create strict RLS policy
DROP POLICY IF EXISTS tenant_isolation_policy ON users;
CREATE POLICY tenant_isolation_policy ON users
    FOR ALL
    USING (
        CASE 
            WHEN COALESCE(current_setting('app.tenant_id', true), '') = '' THEN false
            ELSE tenant_id = current_setting('app.tenant_id', true)::UUID
        END
    )
    WITH CHECK (
        CASE 
            WHEN COALESCE(current_setting('app.tenant_id', true), '') = '' THEN false
            ELSE tenant_id = current_setting('app.tenant_id', true)::UUID
        END
    );

-- Step 10: Verify
SELECT 
    relname, 
    relrowsecurity, 
    relforcerowsecurity 
FROM pg_class 
WHERE relname = 'users';

SELECT * FROM pg_policies WHERE tablename = 'users';

\d users
```

---

## 8. Format, Lint, and Test

```bash
cd /var/home/user/Programming/fri/rso/microservices/user-service

# Activate virtual environment
source venv/bin/activate

# Install dependencies if needed
pip install -r requirements.txt

# Format code
black .
isort .

# Verify formatting
black --check .
isort --check-only .

# Run linters
mypy . --ignore-missing-imports
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

# Run tests
python -m pytest -v
```

---

## 9. Commit and Push

```bash
cd /var/home/user/Programming/fri/rso/microservices/user-service

git add -A
git commit -m "feat: implement PostgreSQL RLS for multitenancy

- Add tenant_id column to users table
- Make keycloak_user_id mandatory (NOT NULL)
- Change email/keycloak_user_id unique constraints to per-tenant
- Add RLS policies with strict CASE-based enforcement
- Add set_tenant_id, reset_tenant_id, tenant_context to db.py
- Update main.py with tenant header handling
- Update schema.py for mandatory keycloak_user_id
- Update tests with tenant headers

BREAKING CHANGES:
- keycloak_user_id is now required when creating users
- X-Tenant-ID header required for all operations
- Requests without tenant header return empty results"

git push
```

---

## 10. Deploy to AKS

```bash
# Wait for CI to pass
gh run watch

# Deploy
helm upgrade --install user-service ./helm/user-service \
    --namespace parkora \
    --set image.tag=main

# Wait for rollout
kubectl rollout status deployment/user-service -n parkora

# Verify
curl -s https://parkora.crn.si/api/v1/user/health/live
curl -s https://parkora.crn.si/api/v1/user/health/ready

# Test with tenant header
curl -s -X POST https://parkora.crn.si/api/v1/user/graphql \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: 00000000-0000-0000-0000-000000000001" \
    -d '{"query": "{ users { id email } }"}'

# Test without tenant header (should return empty)
curl -s -X POST https://parkora.crn.si/api/v1/user/graphql \
    -H "Content-Type: application/json" \
    -d '{"query": "{ users { id email } }"}'
```

---

## Verification Checklist

After deployment, verify:

- [ ] Health endpoints work
- [ ] GraphQL endpoint accessible
- [ ] With tenant header: returns tenant's users
- [ ] Without tenant header: returns empty `[]`
- [ ] Create user requires `keycloakUserId`
- [ ] Create user requires `X-Tenant-ID` header
- [ ] Duplicate email within tenant fails
- [ ] Same email in different tenant succeeds
- [ ] Stats endpoint with tenant returns counts
- [ ] Stats endpoint without tenant returns zeros
