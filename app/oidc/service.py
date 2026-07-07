"""OIDC-specific business logic and token generation.

Handles all OIDC operations including claims generation, authorization code flow,
and token exchange.
"""

import secrets
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config.settings import settings
from app.models.orm import (
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthToken,
    User,
    UserConsent,
)
from app.models.schemas import (
    AccessTokenClaims,
    IDTokenClaims,
    UserInfoResponse,
)
from app.security.jwt import sign_jwt
from app.security.pkce import verify_pkce


def _now_utc() -> datetime:
    """Get current time in UTC, timezone-aware."""
    return datetime.now(timezone.utc)


def _is_expired(expires_at: datetime) -> bool:
    """Check if a datetime has expired, handling both timezone-aware and naive datetimes."""
    now = _now_utc()
    # Ensure both datetimes are comparable
    if expires_at.tzinfo is None:
        # SQLite returns naive datetimes; treat as UTC
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return now > expires_at


def get_oauth_client(db: Session, client_id: str) -> OAuthClient | None:
    """Fetch an OAuth client by ID.

    Args:
        db: Database session.
        client_id: The client identifier.

    Returns:
        OAuthClient or None if not found.
    """
    return db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()


def create_authorization_code(
    db: Session,
    client_id: str,
    user_id: int,
    redirect_uri: str,
    scope: str,
    code_challenge: str | None,
    code_challenge_method: str | None,
    nonce: str | None,
) -> str:
    """Create and store an authorization code.

    Args:
        db: Database session.
        client_id: OAuth client identifier string (e.g., "test-public-client").
        user_id: Authenticated user ID.
        redirect_uri: Where to send the user after authorization.
        scope: Space-separated requested scopes.
        code_challenge: PKCE code challenge (optional).
        code_challenge_method: PKCE method (optional).
        nonce: OIDC nonce (optional).

    Returns:
        Generated authorization code string.
    """
    # Look up the numeric client ID from the client_id string
    client = get_oauth_client(db, client_id)
    if not client:
        raise ValueError(f"Client not found: {client_id}")
    
    code = secrets.token_urlsafe(32)
    now = _now_utc()
    expires_at = now + timedelta(
        seconds=settings.auth_code_expire_seconds
    )

    auth_code = OAuthAuthorizationCode(
        code=code,
        client_id=client.id,
        user_id=user_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        expires_at=expires_at,
        created_at=now,
        used=False,
    )

    db.add(auth_code)
    db.commit()
    db.refresh(auth_code)

    return code


def get_authorization_code(db: Session, code: str) -> OAuthAuthorizationCode | None:
    """Retrieve an authorization code and check if it's still valid.

    A code is valid if:
    - It exists in the database
    - It hasn't been used yet
    - It hasn't expired

    Args:
        db: Database session.
        code: The authorization code string.

    Returns:
        OAuthAuthorizationCode or None if not found or invalid.
    """
    auth_code = db.query(OAuthAuthorizationCode).filter(
        OAuthAuthorizationCode.code == code
    ).first()

    if not auth_code:
        return None

    # Check if already used
    if auth_code.used:
        return None

    # Check if expired
    if _is_expired(auth_code.expires_at):
        return None

    return auth_code


def mark_authorization_code_used(db: Session, auth_code: OAuthAuthorizationCode) -> None:
    """Mark an authorization code as used after token exchange.

    Prevents replay attacks by ensuring a code can only be exchanged once.

    Args:
        db: Database session.
        auth_code: The authorization code object.
    """
    auth_code.used = True
    db.commit()


def record_user_consent(
    db: Session,
    user_id: int,
    client_id: str,
    scope: str,
) -> None:
    """Record that a user has consented to specific scopes for a client.

    Args:
        db: Database session.
        user_id: User ID.
        client_id: OAuth client identifier string (e.g., "test-public-client").
        scope: Space-separated scopes.
    """
    # Look up the numeric client ID from the client_id string
    client = get_oauth_client(db, client_id)
    if not client:
        raise ValueError(f"Client not found: {client_id}")
    
    # Check if consent already exists
    existing = db.query(UserConsent).filter(
        UserConsent.user_id == user_id,
        UserConsent.client_id == client.id,
    ).first()

    now = _now_utc()
    if existing:
        # Update existing consent
        existing.scope = scope
        existing.created_at = now
    else:
        # Create new consent record
        consent = UserConsent(
            user_id=user_id,
            client_id=client.id,
            scope=scope,
            created_at=now,
        )
        db.add(consent)

    db.commit()


def generate_id_token(
    user: User,
    client_id: str,
    nonce: str | None,
    auth_time: int,
) -> str:
    """Generate an OpenID Connect ID token (JWT).

    ID tokens contain information about the user's authentication.

    Args:
        user: The authenticated user.
        client_id: The client that will receive the token.
        nonce: The nonce from the authorization request (for replay protection).
        auth_time: Unix timestamp when user was authenticated.

    Returns:
        Signed JWT token string.
    """
    claims = IDTokenClaims(
        iss=settings.oidc_issuer,
        sub=str(user.id),
        aud=client_id,
        nonce=nonce,
        auth_time=auth_time,
        preferred_username=user.username,
        email=user.username,
        email_verified=True,
        roles=user.roles or [],
    )

    token = sign_jwt(
        claims.model_dump(exclude_none=True),
        settings.access_token_expire_seconds,
    )
    return token


def generate_access_token(
    user_id: int,
    client_id: str,
    scope: str,
) -> str:
    """Generate an OAuth2 access token (JWT).

    Access tokens are bearer tokens used to access protected resources.

    Args:
        user_id: The user this token is for.
        client_id: The client this token was issued to.
        scope: Space-separated scopes granted.

    Returns:
        Signed JWT token string.
    """
    claims = AccessTokenClaims(
        iss=settings.oidc_issuer,
        sub=str(user_id),
        aud="api",  # Generic audience for all APIs
        scope=scope,
        client_id=client_id,
    )

    token = sign_jwt(
        claims.model_dump(),
        settings.access_token_expire_seconds,
    )
    return token


def generate_refresh_token() -> str:
    """Generate an opaque refresh token.

    Refresh tokens are used to obtain new access tokens without re-authenticating.
    They are longer-lived than access tokens.

    Returns:
        Opaque refresh token string.
    """
    return secrets.token_urlsafe(32)


def create_tokens(
    db: Session,
    user_id: int,
    client_id: str,
    scope: str,
    nonce: str | None = None,
) -> tuple[str, str, str]:
    """Create and store tokens for a user and client.

    Generates ID token, access token, and refresh token.
    Stores tokens in the database for revocation and validation.

    Args:
        db: Database session.
        user_id: Authenticated user ID.
        client_id: OAuth client ID.
        scope: Space-separated scopes.
        nonce: OIDC nonce (optional).

    Returns:
        Tuple of (id_token, access_token, refresh_token).
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise ValueError(f"User {user_id} not found")

    # Look up the numeric client ID from the client_id string
    client = get_oauth_client(db, client_id)
    if not client:
        raise ValueError(f"Client not found: {client_id}")

    auth_time = int(time.time())

    # Generate tokens
    id_token = generate_id_token(user, client_id, nonce, auth_time)
    access_token = generate_access_token(user_id, client_id, scope)
    refresh_token = generate_refresh_token()

    # Store tokens in database
    now = _now_utc()
    access_token_expires_at = now + timedelta(
        seconds=settings.access_token_expire_seconds
    )
    refresh_token_expires_at = now + timedelta(
        seconds=settings.refresh_token_expire_seconds
    )

    oauth_token = OAuthToken(
        user_id=user_id,
        client_id=client.id,
        access_token=access_token,
        refresh_token=refresh_token,
        scope=scope,
        issued_at=now,
        access_token_expires_at=access_token_expires_at,
        refresh_token_expires_at=refresh_token_expires_at,
        revoked=False,
    )

    db.add(oauth_token)
    db.commit()

    return id_token, access_token, refresh_token


def get_oauth_token(db: Session, access_token: str) -> OAuthToken | None:
    """Retrieve an OAuth token and check if it's still valid.

    A token is valid if:
    - It exists
    - It hasn't been revoked
    - It hasn't expired

    Args:
        db: Database session.
        access_token: JWT access token string.

    Returns:
        OAuthToken or None if not found or invalid.
    """
    token = db.query(OAuthToken).filter(OAuthToken.access_token == access_token).first()

    if not token:
        return None

    if token.revoked:
        return None

    if _is_expired(token.access_token_expires_at):
        return None

    return token


def refresh_access_token(
    db: Session,
    refresh_token: str,
) -> tuple[str, str] | None:
    """Exchange a refresh token for a new access token.

    Args:
        db: Database session.
        refresh_token: The refresh token to exchange.

    Returns:
        Tuple of (new_access_token, new_refresh_token) or None if invalid.
    """
    token = db.query(OAuthToken).filter(
        OAuthToken.refresh_token == refresh_token
    ).first()

    if not token:
        return None

    if token.revoked:
        return None

    if token.refresh_token_expires_at is None:
        return None

    if _is_expired(token.refresh_token_expires_at):
        return None

    # Look up the client to get the string client_id
    client = db.query(OAuthClient).filter(OAuthClient.id == token.client_id).first()
    if not client:
        raise ValueError(f"Client not found for token with client_id={token.client_id}")

    # Generate new tokens
    new_access_token = generate_access_token(
        token.user_id,
        client.client_id,
        token.scope,
    )
    new_refresh_token = generate_refresh_token()

    # Update the stored token
    now = _now_utc()
    token.access_token = new_access_token
    token.refresh_token = new_refresh_token
    token.access_token_expires_at = now + timedelta(
        seconds=settings.access_token_expire_seconds
    )
    token.refresh_token_expires_at = now + timedelta(
        seconds=settings.refresh_token_expire_seconds
    )
    db.commit()

    return new_access_token, new_refresh_token


def revoke_token(db: Session, access_token: str) -> bool:
    """Revoke an access token.

    Args:
        db: Database session.
        access_token: JWT access token to revoke.

    Returns:
        True if token was revoked, False if not found.
    """
    token = db.query(OAuthToken).filter(OAuthToken.access_token == access_token).first()

    if not token:
        return False

    token.revoked = True
    db.commit()
    return True


def build_userinfo_response(user: User) -> UserInfoResponse:
    """Build a UserInfo response from a user object.

    Args:
        user: User object.

    Returns:
        UserInfoResponse with standardized claims.
    """
    return UserInfoResponse(
        sub=str(user.id),
        preferred_username=user.username,
        email=user.username,
        email_verified=True,
        roles=user.roles or [],
    )
