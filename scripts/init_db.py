#!/usr/bin/env python3
"""Initialize database with test data.

Creates sample users and OAuth clients for testing.

Usage:
    python scripts/init_db.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session

from app.db.session import SessionLocal, engine, Base
from app.models.orm import User, OAuthClient
from app.security.password import hash_password


def init_db_with_test_data() -> None:
    """Initialize database with test data."""
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        # Check if data already exists
        user_count = db.query(User).count()
        if user_count > 0:
            print("Database already initialized. Skipping.")
            return
        
        # Create test user
        test_user = User(
            username="user@example.com",
            password_hash=hash_password("password123"),
            roles=["analysis", "bid_manager", "decomposition"],
            registered=True,
            accepted_tou=True,
        )
        db.add(test_user)
        db.flush()
        print(f"✓ Created test user: user@example.com (id={test_user.id})")
        
        # Create confidential OAuth client
        client = OAuthClient(
            client_id="test-client",
            client_secret="test-secret",
            redirect_uris=["http://localhost:3000/callback", "http://localhost:8080/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
        )
        db.add(client)
        print("✓ Created confidential client: test-client")
        
        # Create public OAuth client
        public_client = OAuthClient(
            client_id="test-public-client",
            client_secret=None,
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
        )
        db.add(public_client)
        print("✓ Created public client: test-public-client")

        rhai_client = OAuthClient(
            client_id="rhai-se",
            client_secret=None,
            redirect_uris=["http://localhost:8051/auth/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scopes=["openid", "profile", "email"],
        )
        db.add(rhai_client)
        print("✓ Created public client: rhai-se")
        
        db.commit()
        print("\n✓ Database initialized successfully")
        
    except Exception as e:
        db.rollback()
        print(f"✗ Error: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    init_db_with_test_data()
