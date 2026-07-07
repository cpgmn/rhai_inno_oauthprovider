"""SQLAlchemy ORM models for existing database tables.

These models map to tables that already exist in the database.
No schema migrations are applied through these models.
"""

import json
from datetime import datetime, timezone
from typing import Optional

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator, String


class ArrayType(TypeDecorator):
    """Custom type that uses ARRAY for PostgreSQL and String for other databases.
    
    This allows the ORM models to work with both PostgreSQL (which uses native ARRAY)
    and SQLite (which uses JSON strings).
    """
    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        """Use ARRAY for PostgreSQL, String for others."""
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(sa.String))
        return dialect.type_descriptor(String)

    def process_bind_param(self, value, dialect):
        """Convert list to appropriate format when saving."""
        if value is None or (isinstance(value, list) and not value):
            return value
        
        if dialect.name == "postgresql":
            # PostgreSQL native ARRAY will handle it
            return value
        else:
            # SQLite: convert to JSON string
            if isinstance(value, list):
                return json.dumps(value)
            return value

    def process_result_value(self, value, dialect):
        """Convert back to list when loading."""
        if value is None:
            return []
        
        if dialect.name == "postgresql":
            # PostgreSQL returns ARRAY directly
            return value if isinstance(value, list) else []
        else:
            # SQLite: parse JSON string
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return []
            return value if isinstance(value, list) else []


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


class User(Base):
    """Existing 'users' table.

    Attributes:
        id: Primary key.
        username: Email address used as the login identifier.
        password_hash: bcrypt hash of the user's password.
        roles: JSON array of role strings, e.g. ["analysis", "bid_manager"].
        registered: Whether the user has completed registration.
        accepted_tou: Whether the user accepted the Terms of Use.
        created_at: Account creation timestamp.
        updated_at: Last update timestamp.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    username: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(sa.String, nullable=False)
    roles: Mapped[list] = mapped_column(ArrayType, default=list)
    registered: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    accepted_tou: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class OAuthClient(Base):
    """Existing 'oauth_clients' table.

    Attributes:
        id: Primary key.
        client_id: Unique OAuth2 client identifier.
        client_secret: Shared secret for confidential clients (NULL for public clients).
        client_name: Human-readable client name.
        redirect_uris: Allowed redirect URIs stored as a PostgreSQL ARRAY.
        grant_types: Allowed grant types stored as a PostgreSQL ARRAY.
        response_types: Allowed response types stored as a PostgreSQL ARRAY.
        scopes: Allowed scopes stored as a PostgreSQL ARRAY.
        token_endpoint_auth_method: Token endpoint authentication method.
        created_at: Client creation timestamp.
    """

    __tablename__ = "oauth_clients"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    client_id: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    client_secret: Mapped[Optional[str]] = mapped_column(sa.String)
    client_name: Mapped[Optional[str]] = mapped_column(sa.String)
    redirect_uris: Mapped[list] = mapped_column(ArrayType, default=list)
    grant_types: Mapped[list] = mapped_column(ArrayType, default=list)
    response_types: Mapped[list] = mapped_column(ArrayType, default=list)
    scopes: Mapped[list] = mapped_column(ArrayType, default=list)
    token_endpoint_auth_method: Mapped[Optional[str]] = mapped_column(sa.String)
    created_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))


class OAuthAuthorizationCode(Base):
    """Existing 'oauth_authorization_codes' table.

    Attributes:
        id: Primary key.
        code: Unique authorization code string issued to the client.
        client_id: Foreign key to oauth_clients.id (numeric ID, not the client_id string).
        user_id: The authenticated user who approved the request.
        redirect_uri: The redirect URI from the authorization request.
        scope: Space-separated scopes granted by the user.
        code_challenge: PKCE code challenge (optional).
        code_challenge_method: PKCE method, 'S256' or 'plain' (optional).
        nonce: OIDC nonce for replay protection (optional).
        expires_at: Expiry timestamp; codes are invalid after this point.
        used: True once the code has been exchanged for tokens.
        created_at: Code issuance timestamp.
    """

    __tablename__ = "oauth_authorization_codes"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    code: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    client_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("oauth_clients.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("users.id"), nullable=False
    )
    redirect_uri: Mapped[str] = mapped_column(sa.String, nullable=False)
    scope: Mapped[str] = mapped_column(sa.String, nullable=False)
    code_challenge: Mapped[Optional[str]] = mapped_column(sa.String)
    code_challenge_method: Mapped[Optional[str]] = mapped_column(sa.String)
    nonce: Mapped[Optional[str]] = mapped_column(sa.String)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)


class OAuthToken(Base):
    """Existing 'oauth_tokens' table.

    Attributes:
        id: Primary key.
        client_id: Foreign key to oauth_clients.id (numeric ID, not the client_id string).
        user_id: The user the token belongs to.
        access_token: JWT access token string (unique).
        refresh_token: Opaque refresh token string (unique, optional).
        scope: Space-separated scopes.
        issued_at: Token issuance timestamp.
        access_token_expires_at: Access token expiry timestamp.
        refresh_token_expires_at: Refresh token expiry timestamp.
        revoked: True if the token has been explicitly revoked.
    """

    __tablename__ = "oauth_tokens"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("oauth_clients.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("users.id"), nullable=False
    )
    access_token: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    refresh_token: Mapped[Optional[str]] = mapped_column(sa.String, unique=True)
    scope: Mapped[str] = mapped_column(sa.String, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    access_token_expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    refresh_token_expires_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)


class UserConsent(Base):
    """Existing 'user_consent' table.

    Tracks which scopes a user has approved for a client.
    Consent is recorded automatically – no consent screen is shown.

    Attributes:
        id: Primary key.
        user_id: The user who granted consent (foreign key to users.id).
        client_id: The OAuth client ID (foreign key to oauth_clients.id, NOT the client_id string).
        scope: Space-separated scopes consented to.
        created_at: Timestamp when consent was recorded.
    """

    __tablename__ = "user_consent"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("users.id"), nullable=False
    )
    client_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("oauth_clients.id"), nullable=False
    )
    scope: Mapped[str] = mapped_column(sa.String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
