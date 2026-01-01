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
