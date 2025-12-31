import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from keycloak import KeycloakOpenID
from sqlalchemy.orm import Session
from strawberry.fastapi import GraphQLRouter

from db import get_db
from schema import schema

app = FastAPI(title="User Service", version="1.0.0")

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


@app.get("/health/live")
def health_live():
    return {"status": "alive"}


@app.get("/health/ready")
def health_ready():
    return {"status": "ready"}


@app.get("/")
def root():
    return {"message": "User Service API"}


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
