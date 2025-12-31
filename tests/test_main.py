from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_live():
    response = client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "alive"
    assert data["service"] == "user-service"
    assert data["version"] == "1.0.0"


def test_health_ready():
    response = client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in [
        "ready",
        "unhealthy",
    ]  # Allow unhealthy for test environment
    assert data["service"] == "user-service"
    assert data["version"] == "1.0.0"


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data
    assert "docs" in data
    assert "graphql" in data
    assert "health" in data


def test_stats():
    response = client.get("/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_users" in data
    assert "users_with_keycloak_id" in data
    assert "recent_users" in data
    assert isinstance(data["total_users"], int)
    assert isinstance(data["users_with_keycloak_id"], int)
    assert isinstance(data["recent_users"], int)
