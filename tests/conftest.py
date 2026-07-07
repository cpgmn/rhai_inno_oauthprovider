"""Pytest configuration and fixtures."""

import json
import os
from datetime import datetime, timezone
from typing import Optional

import pytest
import sqlalchemy as sa
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker, DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator, String

from app.db.session import get_db
from app.main import app
from app.security.password import hash_password


# Custom type for handling JSON arrays in SQLite
class JSONArray(TypeDecorator):
    """Custom type that stores JSON arrays as strings in SQLite."""
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert list to JSON string when saving."""
        if value is None:
            return None
        if isinstance(value, list):
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        """Convert JSON string back to list when loading."""
        if value is None:
            return []
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return []
        return value if isinstance(value, list) else []


# Create test-specific base using custom JSONArray type for SQLite compatibility
class TestBase(DeclarativeBase):
    """Base class for test ORM models."""
    pass


class User(TestBase):
    """Test User model - string columns for SQLite."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    username: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(sa.String, nullable=False)
    roles: Mapped[list] = mapped_column(JSONArray, default=list)
    registered: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    accepted_tou: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class OAuthClient(TestBase):
    """Test OAuthClient model - string columns for SQLite."""
    __tablename__ = "oauth_clients"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    client_id: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    client_secret: Mapped[str] = mapped_column(sa.String)
    client_name: Mapped[str] = mapped_column(sa.String)
    redirect_uris: Mapped[list] = mapped_column(JSONArray, default=list)
    grant_types: Mapped[list] = mapped_column(JSONArray, default=list)
    response_types: Mapped[list] = mapped_column(JSONArray, default=list)
    scopes: Mapped[list] = mapped_column(JSONArray, default=list)
    token_endpoint_auth_method: Mapped[str] = mapped_column(sa.String)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))


class OAuthAuthorizationCode(TestBase):
    """Test OAuthAuthorizationCode model."""
    __tablename__ = "oauth_authorization_codes"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    code: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(sa.String, nullable=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(sa.String, nullable=False)
    scope: Mapped[str] = mapped_column(sa.String, nullable=False)
    code_challenge: Mapped[Optional[str]] = mapped_column(sa.String)
    code_challenge_method: Mapped[Optional[str]] = mapped_column(sa.String)
    nonce: Mapped[Optional[str]] = mapped_column(sa.String)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    created_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))


class OAuthToken(TestBase):
    """Test OAuthToken model."""
    __tablename__ = "oauth_tokens"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), nullable=False)
    client_id: Mapped[str] = mapped_column(sa.String, nullable=False)
    access_token: Mapped[str] = mapped_column(sa.String, unique=True, nullable=False)
    refresh_token: Mapped[Optional[str]] = mapped_column(sa.String, unique=True)
    token_type: Mapped[str] = mapped_column(sa.String, default="Bearer", nullable=False)
    scope: Mapped[str] = mapped_column(sa.String, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    refresh_token_expires_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    created_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))


class UserConsent(TestBase):
    """Test UserConsent model."""
    __tablename__ = "user_consent"

    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("users.id"), nullable=False)
    client_id: Mapped[str] = mapped_column(sa.String, nullable=False)
    scope: Mapped[str] = mapped_column(sa.String, nullable=False)
    granted_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))


@pytest.fixture(scope="session")
def db_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Enable foreign keys for SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    TestBase.metadata.create_all(bind=engine)
    yield engine
    TestBase.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(db_engine):
    """Create a fresh database session for each test."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(bind=connection, class_=Session)
    session = session_factory()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """Create a test FastAPI client with test database session."""
    from fastapi.testclient import TestClient

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db_session: Session) -> User:
    """Create a test user."""
    user = User(
        username="user@example.com",
        password_hash=hash_password("password123"),
        roles=["analysis", "bid_manager"],
        registered=True,
        accepted_tou=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def test_oauth_client(db_session: Session) -> OAuthClient:
    """Create a test OAuth client."""
    client = OAuthClient(
        client_id="test-client",
        client_secret="test-secret",
        client_name="Test Client",
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scopes=["openid", "profile", "email"],
        token_endpoint_auth_method="client_secret_basic",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)
    return client


@pytest.fixture
def test_oauth_public_client(db_session: Session) -> OAuthClient:
    """Create a test public OAuth client (no secret)."""
    client = OAuthClient(
        client_id="test-public-client",
        client_secret="",
        client_name="Test Public Client",
        redirect_uris=["http://localhost:3000/callback"],
        grant_types=["authorization_code"],
        response_types=["code"],
        scopes=["openid", "profile", "email"],
        token_endpoint_auth_method="none",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(client)
    db_session.commit()
    db_session.refresh(client)
    return client
