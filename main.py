"""
User Service - Main Application

FastAPI application for managing users with multitenancy support.
Uses PostgreSQL RLS for tenant isolation.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from keycloak import KeycloakOpenID
from pydantic import BaseModel
from sqlalchemy import func, text
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
        db.execute(text("SELECT 1"))
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
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_users = (
            db.query(func.count(UserModel.id))
            .filter(UserModel.created_at >= thirty_days_ago)
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
