import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import app
from models import Base, UserModel

# Create file-based SQLite database for tests
engine = create_engine("sqlite+pysqlite:///./test.db")
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
app.dependency_overrides = {}
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


def test_graphql_users_query():
    """Test querying all users."""
    query = """
    query {
        users {
            id
            email
            keycloakUserId
            firstName
            lastName
            createdAt
        }
    }
    """
    response = client.post("/graphql", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert "users" in data["data"]
    assert isinstance(data["data"]["users"], list)


def test_graphql_user_by_id_query():
    """Test querying user by ID."""
    # First create a user
    mutation = """
    mutation {
        createUser(email: "test@example.com", firstName: "Test", lastName: "User") {
            id
            email
            keycloakUserId
            firstName
            lastName
        }
    }
    """
    response = client.post("/graphql", json={"query": mutation})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    user_id = data["data"]["createUser"]["id"]

    # Now query by ID
    query = f"""
    query {{
        userById(id: "{user_id}") {{
            id
            email
            keycloakUserId
            firstName
            lastName
            createdAt
        }}
    }}
    """
    response = client.post("/graphql", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["userById"]["id"] == user_id
    assert data["data"]["userById"]["email"] == "test@example.com"


def test_graphql_user_by_email_query():
    """Test querying user by email."""
    import time

    timestamp = str(int(time.time()))
    email = f"test_{timestamp}@example.com"

    # First create a user
    mutation = f"""
    mutation {{
        createUser(email: "{email}", firstName: "Test", lastName: "User") {{
            id
        }}
    }}
    """
    client.post("/graphql", json={"query": mutation})

    # Now query by email
    query = f"""
    query {{
        userByEmail(email: "{email}") {{
            id
            email
            keycloakUserId
            firstName
            lastName
        }}
    }}
    """
    response = client.post("/graphql", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["userByEmail"]["email"] == email


def test_graphql_create_user_mutation():
    """Test creating a new user."""
    mutation = """
    mutation {
        createUser(email: "newuser@example.com", firstName: "New", lastName: "User") {
            id
            email
            keycloakUserId
            firstName
            lastName
        }
    }
    """
    response = client.post("/graphql", json={"query": mutation})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["createUser"]["email"] == "newuser@example.com"
    assert data["data"]["createUser"]["firstName"] == "New"
    assert data["data"]["createUser"]["lastName"] == "User"
    assert data["data"]["createUser"]["keycloakUserId"] is None


def test_graphql_create_user_with_keycloak_id():
    """Test creating a user with Keycloak ID."""
    import uuid

    keycloak_id = str(uuid.uuid4())

    mutation = f"""
    mutation {{
        createUser(
            email: "keycloak@example.com",
            firstName: "Keycloak",
            lastName: "User",
            keycloakUserId: "{keycloak_id}"
        ) {{
            id
            email
            keycloakUserId
            firstName
            lastName
        }}
    }}
    """
    response = client.post("/graphql", json={"query": mutation})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["createUser"]["email"] == "keycloak@example.com"
    assert data["data"]["createUser"]["keycloakUserId"] == keycloak_id


def test_graphql_user_by_keycloak_id_query():
    """Test querying user by Keycloak ID."""
    import uuid

    keycloak_id = str(uuid.uuid4())

    # Create user with Keycloak ID
    mutation = f"""
    mutation {{
        createUser(
            email: "keycloak2@example.com",
            firstName: "Keycloak2",
            lastName: "User",
            keycloakUserId: "{keycloak_id}"
        ) {{
            id
            email
            keycloakUserId
        }}
    }}
    """
    response = client.post("/graphql", json={"query": mutation})
    assert response.status_code == 200

    # Query by Keycloak ID
    query = f"""
    query {{
        userByKeycloakId(keycloakUserId: "{keycloak_id}") {{
            id
            email
            keycloakUserId
            firstName
            lastName
        }}
    }}
    """
    response = client.post("/graphql", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["userByKeycloakId"]["keycloakUserId"] == keycloak_id


def test_graphql_create_user_duplicate_email():
    """Test creating user with duplicate email fails."""
    # Create first user
    mutation1 = """
    mutation {
        createUser(email: "duplicate@example.com", firstName: "First", lastName: "User") {
            id
        }
    }
    """
    client.post("/graphql", json={"query": mutation1})

    # Try to create second user with same email
    mutation2 = """
    mutation {
        createUser(email: "duplicate@example.com", firstName: "Second", lastName: "User") {
            id
        }
    }
    """
    response = client.post("/graphql", json={"query": mutation2})
    assert response.status_code == 200
    data = response.json()
    assert "errors" in data
    assert "Email already exists" in str(data["errors"])


def test_graphql_create_user_duplicate_keycloak_id():
    """Test creating user with duplicate Keycloak ID fails."""
    import uuid

    keycloak_id = str(uuid.uuid4())

    # Create first user
    mutation1 = f"""
    mutation {{
        createUser(
            email: "unique1_{keycloak_id[:8]}@example.com",
            firstName: "First",
            lastName: "User",
            keycloakUserId: "{keycloak_id}"
        ) {{
            id
        }}
    }}
    """
    client.post("/graphql", json={"query": mutation1})

    # Try to create second user with same Keycloak ID
    mutation2 = f"""
    mutation {{
        createUser(
            email: "unique2_{keycloak_id[:8]}@example.com",
            firstName: "Second",
            lastName: "User",
            keycloakUserId: "{keycloak_id}"
        ) {{
            id
        }}
    }}
    """
    response = client.post("/graphql", json={"query": mutation2})
    assert response.status_code == 200
    data = response.json()
    assert "errors" in data
    assert "Keycloak user ID already exists" in str(data["errors"])
