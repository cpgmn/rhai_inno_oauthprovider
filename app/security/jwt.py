"""JWT signing and verification utilities.

Uses RS256 (RSA Signature with SHA-256) algorithm.
Private key signs tokens; public key verifies them.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config.settings import settings


def generate_rsa_keypair() -> tuple[str, str]:
    """Generate a new RSA-2048 public/private key pair.

    Used by deployment to generate signing keys.
    For development, use scripts/generate_keys.py

    Returns:
        Tuple of (private_key_pem, public_key_pem) as strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def _normalize_pem_key(key_str: str) -> str:
    """Handle PEM keys with escaped newlines from environment variables.

    Environment variables sometimes contain \\n instead of actual newlines.
    This function normalizes them to proper PEM format.

    Args:
        key_str: PEM key string, possibly with escaped newlines.

    Returns:
        Properly formatted PEM key string.
    """
    # Replace escaped newlines with actual newlines
    key_str = key_str.replace("\\n", "\n")
    return key_str


def sign_jwt(payload: dict[str, Any], expires_in_seconds: int) -> str:
    """Sign a JWT using the configured private key (RS256).

    Args:
        payload: Claims dictionary to include in the token.
        expires_in_seconds: Token lifetime in seconds.

    Returns:
        Encoded JWT token string.

    Raises:
        ValueError: If private key is not configured.
    """
    if not settings.jwt_private_key:
        raise ValueError("JWT_PRIVATE_KEY not configured")

    private_key = _normalize_pem_key(settings.jwt_private_key)

    now = int(time.time())
    payload["iat"] = now
    payload["exp"] = now + expires_in_seconds

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": settings.jwt_key_id},
    )
    return token


def verify_jwt(token: str) -> dict[str, Any]:
    """Verify and decode a JWT using the configured public key (RS256).

    Args:
        token: JWT token string to verify.

    Returns:
        Decoded payload dictionary.

    Raises:
        jwt.InvalidTokenError: If token is invalid, expired, or malformed.
        ValueError: If public key is not configured.
    """
    if not settings.jwt_public_key:
        raise ValueError("JWT_PUBLIC_KEY not configured")

    public_key = _normalize_pem_key(settings.jwt_public_key)

    payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
    )
    return payload


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT without verification (for debugging and introspection).

    WARNING: This completely bypasses signature verification.
    Only use this for inspecting token contents, not for security decisions.

    Args:
        token: JWT token string.

    Returns:
        Decoded payload dictionary.
    """
    payload = jwt.decode(
        token,
        options={"verify_signature": False},
    )
    return payload


def get_jwk_from_public_key() -> dict[str, Any]:
    """Export the public key in JWKS (JSON Web Key Set) format.

    This is used by the /.well-known/jwks.json endpoint
    for clients to download and verify signatures.

    Returns:
        A single JWK in dictionary format.

    Raises:
        ValueError: If public key is not configured.
    """
    if not settings.jwt_public_key:
        raise ValueError("JWT_PUBLIC_KEY not configured")

    public_key_pem = _normalize_pem_key(settings.jwt_public_key)

    # Load the public key using cryptography library
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    public_key = load_pem_public_key(
        public_key_pem.encode("utf-8"),
        backend=default_backend(),
    )

    # Extract RSA components
    public_numbers = public_key.public_numbers()

    # Convert to base64url-encoded integers
    from base64 import urlsafe_b64encode

    def int_to_b64(val: int, byte_length: int) -> str:
        """Convert integer to base64url without padding."""
        return urlsafe_b64encode(val.to_bytes(byte_length, "big")).decode("ascii").rstrip("=")

    # RSA key size in bytes
    key_byte_size = (public_numbers.n.bit_length() + 7) // 8

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": settings.jwt_key_id,
        "n": int_to_b64(public_numbers.n, key_byte_size),
        "e": int_to_b64(public_numbers.e, 3),
    }

    return jwk
