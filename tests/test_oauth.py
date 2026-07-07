"""Tests for OIDC and OAuth2 endpoints."""

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.session import create_session
from app.models.orm import OAuthAuthorizationCode
from app.security.pkce import generate_code_challenge, generate_code_verifier


def test_discovery_endpoint(client: TestClient) -> None:
    """Test OpenID Connect Discovery endpoint."""
    response = client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    data = response.json()

    assert data["issuer"]
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "userinfo_endpoint" in data
    assert "jwks_uri" in data
    assert "RS256" in data["id_token_signing_alg_values_supported"]


def test_jwks_endpoint(client: TestClient) -> None:
    """Test JWKS endpoint."""
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    data = response.json()

    assert "keys" in data
    assert len(data["keys"]) > 0
    assert data["keys"][0]["kty"] == "RSA"
    assert "n" in data["keys"][0]
    assert "e" in data["keys"][0]


def test_authorize_invalid_response_type(client: TestClient, test_oauth_client) -> None:
    """Test authorization with invalid response_type."""
    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "token",  # Invalid – only 'code' supported
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "state": "state123",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["error"] == "unsupported_response_type"


def test_authorize_unknown_client(client: TestClient) -> None:
    """Test authorization with unknown client."""
    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "unknown-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "state": "state123",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["error"] == "invalid_client"


def test_authorize_invalid_redirect_uri(client: TestClient, test_oauth_client) -> None:
    """Test authorization with redirect_uri not registered."""
    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://malicious.com/callback",
            "scope": "openid profile",
            "state": "state123",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["error"] == "invalid_redirect_uri"


def test_authorize_invalid_scope(client: TestClient, test_oauth_client) -> None:
    """Test authorization with scope not allowed for client."""
    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid admin",  # 'admin' not allowed
            "state": "state123",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["error"] == "invalid_scope"


def test_authorize_not_logged_in(client: TestClient, test_oauth_client) -> None:
    """Test authorization when user is not logged in."""
    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "state": "state123",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/login" in response.headers["location"]
    assert "redirect_to" in response.headers["location"]


def test_authorize_logged_in(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test authorization when user is logged in."""
    session_id = create_session(test_user.id)

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "state": "state123",
        },
        cookies={"session_id": session_id},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "authorized"
    assert "code=" in data["redirect_uri"]
    assert "state=state123" in data["redirect_uri"]


def test_authorize_with_pkce(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test authorization with PKCE."""
    session_id = create_session(test_user.id)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier, "S256")

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "state": "state123",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies={"session_id": session_id},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "authorized"


def test_token_exchange_success(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test successful authorization code token exchange."""
    # Step 1: Get authorization code
    session_id = create_session(test_user.id)
    auth_response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile email",
            "state": "state123",
            "nonce": "nonce123",
        },
        cookies={"session_id": session_id},
    )

    assert auth_response.status_code == 200
    redirect_uri = auth_response.json()["redirect_uri"]

    # Extract code from redirect URI
    parsed = urlparse(redirect_uri)
    code = parse_qs(parsed.query)["code"][0]

    # Step 2: Exchange code for tokens
    token_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    assert token_response.status_code == 200
    tokens = token_response.json()
    assert tokens["access_token"]
    assert tokens["id_token"]
    assert tokens["refresh_token"]
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] > 0


def test_token_exchange_invalid_code(client: TestClient, test_oauth_client) -> None:
    """Test token exchange with invalid authorization code."""
    response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": "invalid-code",
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["error"] == "invalid_grant"


def test_token_exchange_wrong_redirect_uri(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test token exchange with mismatched redirect_uri."""
    # Get authorization code
    session_id = create_session(test_user.id)
    auth_response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid",
            "state": "state123",
        },
        cookies={"session_id": session_id},
    )

    redirect_uri = auth_response.json()["redirect_uri"]
    parsed = urlparse(redirect_uri)
    code = parse_qs(parsed.query)["code"][0]

    # Try to exchange with different redirect_uri
    token_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://different.com/callback",  # Wrong!
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    assert token_response.status_code == 400
    data = token_response.json()
    assert data["detail"]["error"] == "invalid_grant"


def test_token_exchange_invalid_client_secret(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test token exchange with invalid client secret."""
    # Get authorization code
    session_id = create_session(test_user.id)
    auth_response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid",
            "state": "state123",
        },
        cookies={"session_id": session_id},
    )

    redirect_uri = auth_response.json()["redirect_uri"]
    parsed = urlparse(redirect_uri)
    code = parse_qs(parsed.query)["code"][0]

    # Exchange with wrong secret
    token_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "client_secret": "wrong-secret",
        },
    )

    assert token_response.status_code == 401
    data = token_response.json()
    assert data["detail"]["error"] == "invalid_client"


def test_token_exchange_with_pkce(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test token exchange with PKCE validation."""
    session_id = create_session(test_user.id)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier, "S256")

    # Get authorization code with PKCE
    auth_response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid",
            "state": "state123",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies={"session_id": session_id},
    )

    redirect_uri = auth_response.json()["redirect_uri"]
    parsed = urlparse(redirect_uri)
    code = parse_qs(parsed.query)["code"][0]

    # Exchange with correct verifier
    token_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "code_verifier": code_verifier,
        },
    )

    assert token_response.status_code == 200


def test_token_exchange_invalid_pkce_verifier(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test token exchange with invalid PKCE verifier."""
    session_id = create_session(test_user.id)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier, "S256")

    # Get authorization code with PKCE
    auth_response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid",
            "state": "state123",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies={"session_id": session_id},
    )

    redirect_uri = auth_response.json()["redirect_uri"]
    parsed = urlparse(redirect_uri)
    code = parse_qs(parsed.query)["code"][0]

    # Exchange with wrong verifier
    token_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "code_verifier": "wrong-verifier-value",
        },
    )

    assert token_response.status_code == 400
    data = token_response.json()
    assert data["detail"]["error"] == "invalid_grant"


def test_userinfo_endpoint(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test UserInfo endpoint."""
    # Get access token
    session_id = create_session(test_user.id)
    auth_response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile email",
            "state": "state123",
        },
        cookies={"session_id": session_id},
    )

    redirect_uri = auth_response.json()["redirect_uri"]
    parsed = urlparse(redirect_uri)
    code = parse_qs(parsed.query)["code"][0]

    token_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    access_token = token_response.json()["access_token"]

    # Call UserInfo endpoint
    userinfo_response = client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert userinfo_response.status_code == 200
    userinfo = userinfo_response.json()
    assert userinfo["sub"] == str(test_user.id)
    assert userinfo["email"] == "user@example.com"
    assert userinfo["email_verified"] is True
    assert "analysis" in userinfo["roles"]


def test_userinfo_invalid_token(client: TestClient) -> None:
    """Test UserInfo with invalid token."""
    response = client.get(
        "/oauth/userinfo",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["error"] == "invalid_token"


def test_userinfo_missing_auth_header(client: TestClient) -> None:
    """Test UserInfo without Authorization header."""
    response = client.get("/oauth/userinfo")

    assert response.status_code == 401
    data = response.json()
    assert data["detail"]["error"] == "invalid_token"


def test_refresh_token_flow(
    client: TestClient,
    test_oauth_client,
    test_user,
    db_session: Session,
) -> None:
    """Test refresh token grant flow."""
    # Get initial tokens
    session_id = create_session(test_user.id)
    auth_response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "test-client",
            "response_type": "code",
            "redirect_uri": "http://localhost:3000/callback",
            "scope": "openid profile",
            "state": "state123",
        },
        cookies={"session_id": session_id},
    )

    redirect_uri = auth_response.json()["redirect_uri"]
    parsed = urlparse(redirect_uri)
    code = parse_qs(parsed.query)["code"][0]

    token_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/callback",
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    refresh_token = token_response.json()["refresh_token"]

    # Use refresh token to get new access token
    refresh_response = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    assert refresh_response.status_code == 200
    new_tokens = refresh_response.json()
    assert new_tokens["access_token"]
    assert new_tokens["refresh_token"]
    assert new_tokens["token_type"] == "Bearer"


def test_refresh_token_invalid(client: TestClient, test_oauth_client) -> None:
    """Test refresh token grant with invalid token."""
    response = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "refresh_token": "invalid-refresh-token",
            "client_id": "test-client",
            "client_secret": "test-secret",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["error"] == "invalid_grant"


def test_health_endpoint(client: TestClient) -> None:
    """Test health check endpoint."""
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
