"""Tests for authentication endpoints."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def test_login_page_get(client: TestClient) -> None:
    """Test GET /login returns HTML form."""
    response = client.get("/login")
    assert response.status_code == 200
    assert "Content-Type" in response.headers
    assert "text/html" in response.headers["Content-Type"]
    assert "<form" in response.text


def test_login_page_with_redirect(client: TestClient) -> None:
    """Test GET /login with redirect_to parameter."""
    response = client.get("/login?redirect_to=/dashboard")
    assert response.status_code == 200
    assert "/dashboard" in response.text


def test_login_success(client: TestClient, test_user, db_session: Session) -> None:
    """Test successful login."""
    response = client.post(
        "/login",
        data={
            "username": "user@example.com",
            "password": "password123",
            "redirect_to": "/",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/"
    assert "session_id" in response.cookies


def test_login_invalid_password(client: TestClient, test_user) -> None:
    """Test login with wrong password."""
    response = client.post(
        "/login",
        data={
            "username": "user@example.com",
            "password": "wrongpassword",
            "redirect_to": "/",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/login" in response.headers["location"]
    assert "error" in response.headers["location"]


def test_login_unknown_user(client: TestClient) -> None:
    """Test login with unknown user."""
    response = client.post(
        "/login",
        data={
            "username": "unknown@example.com",
            "password": "password123",
            "redirect_to": "/",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/login" in response.headers["location"]
    assert "error" in response.headers["location"]
