"""Tests for security utilities."""

import pytest

from app.security.password import hash_password, verify_password
from app.security.pkce import (
    generate_code_challenge,
    generate_code_verifier,
    verify_pkce,
)
from app.security.validation import (
    validate_redirect_uri,
    is_valid_redirect_uri,
    validate_scope,
)


class TestPasswordHashing:
    """Tests for password hashing and verification."""

    def test_hash_password_produces_hash(self) -> None:
        """Test that hashing produces a non-empty hash."""
        password = "mypassword"
        hashed = hash_password(password)

        assert hashed
        assert hashed != password

    def test_verify_password_success(self) -> None:
        """Test verifying correct password."""
        password = "mypassword"
        hashed = hash_password(password)

        assert verify_password(password, hashed)

    def test_verify_password_failure(self) -> None:
        """Test verifying wrong password."""
        password = "correctpassword"
        hashed = hash_password(password)

        assert not verify_password("wrongpassword", hashed)

    def test_different_passwords_different_hashes(self) -> None:
        """Test that same password hashed twice produces different hashes."""
        password = "mypassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        # Different hashes but both verify correctly
        assert hash1 != hash2
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)


class TestPKCE:
    """Tests for PKCE support."""

    def test_generate_code_verifier(self) -> None:
        """Test code verifier generation."""
        verifier = generate_code_verifier()

        assert verifier
        assert len(verifier) > 30  # At least 43 characters
        assert len(verifier) <= 128

    def test_generate_code_challenge_s256(self) -> None:
        """Test S256 code challenge generation."""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, "S256")

        assert challenge
        assert challenge != verifier

    def test_generate_code_challenge_plain(self) -> None:
        """Test plain code challenge generation."""
        verifier = "test-verifier"
        challenge = generate_code_challenge(verifier, "plain")

        assert challenge == verifier

    def test_verify_pkce_s256_success(self) -> None:
        """Test PKCE verification with S256."""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, "S256")

        assert verify_pkce(verifier, challenge, "S256")

    def test_verify_pkce_s256_failure(self) -> None:
        """Test PKCE verification with wrong verifier."""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, "S256")
        wrong_verifier = generate_code_verifier()

        assert not verify_pkce(wrong_verifier, challenge, "S256")

    def test_verify_pkce_plain(self) -> None:
        """Test PKCE verification with plain method."""
        verifier = "test-verifier"
        challenge = verifier

        assert verify_pkce(verifier, challenge, "plain")

    def test_verify_pkce_invalid_method(self) -> None:
        """Test PKCE verification with invalid method."""
        verifier = "test-verifier"
        challenge = "test-challenge"

        assert not verify_pkce(verifier, challenge, "invalid")


class TestURIValidation:
    """Tests for URI validation."""

    def test_is_valid_redirect_uri_valid(self) -> None:
        """Test validation of valid redirect URI."""
        assert is_valid_redirect_uri("http://localhost:3000/callback")
        assert is_valid_redirect_uri("https://example.com/callback")
        assert is_valid_redirect_uri("http://192.168.1.1:8000/oauth/callback")

    def test_is_valid_redirect_uri_invalid(self) -> None:
        """Test validation of invalid redirect URIs."""
        assert not is_valid_redirect_uri("")
        assert not is_valid_redirect_uri("localhost:3000")  # No scheme
        assert not is_valid_redirect_uri("/callback")  # Relative
        assert not is_valid_redirect_uri("not-a-url")

    def test_validate_redirect_uri_in_list(self) -> None:
        """Test checking redirect URI is in allowed list."""
        allowed = [
            "http://localhost:3000/callback",
            "https://example.com/callback",
        ]

        assert validate_redirect_uri("http://localhost:3000/callback", allowed)

    def test_validate_redirect_uri_not_in_list(self) -> None:
        """Test rejection of redirect URI not in list."""
        allowed = [
            "http://localhost:3000/callback",
            "https://example.com/callback",
        ]

        assert not validate_redirect_uri("http://attacker.com/callback", allowed)


class TestScopeValidation:
    """Tests for scope validation."""

    def test_validate_scope_valid(self) -> None:
        """Test validation of allowed scopes."""
        allowed = ["openid", "profile", "email"]
        requested = "openid profile"

        is_valid, granted = validate_scope(requested, allowed)

        assert is_valid
        assert "openid" in granted
        assert "profile" in granted

    def test_validate_scope_all_allowed(self) -> None:
        """Test validation when all scopes are allowed."""
        allowed = ["openid", "profile", "email"]
        requested = "openid profile email"

        is_valid, granted = validate_scope(requested, allowed)

        assert is_valid
        assert len(granted) == 3

    def test_validate_scope_some_disallowed(self) -> None:
        """Test rejection when some scopes are not allowed."""
        allowed = ["openid", "profile"]
        requested = "openid email admin"

        is_valid, granted = validate_scope(requested, allowed)

        assert not is_valid
        assert len(granted) == 0

    def test_validate_scope_empty(self) -> None:
        """Test validation of empty scope."""
        allowed = ["openid", "profile"]
        requested = ""

        is_valid, granted = validate_scope(requested, allowed)

        assert is_valid
        assert len(granted) == 0
