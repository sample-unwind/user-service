import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from keycloak import KeycloakOpenID
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from strawberry.fastapi import GraphQLRouter

from db import get_db
from models import UserModel
from schema import schema


# Pydantic models for API responses
class HealthResponse(BaseModel):
    status: str
    service: str = "user-service"
    version: str = "1.0.0"


class UserStatsResponse(BaseModel):
    total_users: int
    users_with_keycloak_id: int
    recent_users: int


app = FastAPI(
    title="User Service API",
    description="A comprehensive user management microservice for the Parkora smart parking system. Provides GraphQL API for user operations with Keycloak authentication integration.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={
        "name": "Parkora Team",
        "url": "https://parkora.crn.si",
    },
    license_info={
        "name": "MIT",
    },
)

# Set servers for OpenAPI schema after app creation
app.servers = [{"url": "/api/v1/user", "description": "Production server"}]


# Keycloak configuration
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get(
    "/health/live",
    response_model=HealthResponse,
    summary="Liveness Health Check",
    description="Check if the service is alive and responding to requests.",
    tags=["Health"],
)
def health_live():
    """Liveness probe - indicates if the service is running."""
    return HealthResponse(status="alive")


@app.get(
    "/health/ready",
    response_model=HealthResponse,
    summary="Readiness Health Check",
    description="Check if the service is ready to handle requests, including database connectivity.",
    tags=["Health"],
)
def health_ready(db: Session = Depends(get_db)):
    """Readiness probe - indicates if the service is ready to handle traffic."""
    try:
        # Test database connectivity
        db.execute(func.text("SELECT 1"))
        return HealthResponse(status="ready")
    except Exception:
        return HealthResponse(status="unhealthy")


@app.get(
    "/",
    summary="API Root",
    description="Welcome endpoint for the User Service API.",
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
    }


@app.get(
    "/stats",
    response_model=UserStatsResponse,
    summary="User Statistics",
    description="Get basic statistics about users in the system.",
    tags=["Analytics"],
)
def get_user_stats(db: Session = Depends(get_db)):
    """Get user statistics for monitoring and analytics."""
    try:
        # Total users
        total_users = db.query(func.count(UserModel.id)).scalar()

        # Users with Keycloak ID
        users_with_keycloak = (
            db.query(func.count(UserModel.id))
            .filter(UserModel.keycloak_user_id.isnot(None))
            .scalar()
        )

        # Recent users (last 30 days - simplified for PostgreSQL)
        recent_users = (
            db.query(func.count(UserModel.id))
            .filter(
                UserModel.created_at >= func.now() - func.text("interval '30 days'")
            )
            .scalar()
        )

        return UserStatsResponse(
            total_users=total_users or 0,
            users_with_keycloak_id=users_with_keycloak or 0,
            recent_users=recent_users or 0,
        )
    except Exception:
        # Return zeros if database query fails
        return UserStatsResponse(
            total_users=0,
            users_with_keycloak_id=0,
            recent_users=0,
        )


def get_current_user(request: Request) -> dict | None:
    """Extract and verify JWT token from Authorization header."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ")[1]
    try:
        # Verify token with Keycloak
        token_info = keycloak_openid.introspect(token)
        if not token_info.get("active", False):
            return None
        return token_info
    except Exception:
        return None


def get_context(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request)
    return {"db": db, "current_user": current_user}


app.include_router(GraphQLRouter(schema, context_getter=get_context), prefix="/graphql")
