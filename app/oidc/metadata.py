"""OIDC and OAuth2 metadata endpoints and handlers."""

from app.config.settings import settings
from app.models.schemas import OIDCDiscovery, JWKSResponse
from app.security.jwt import get_jwk_from_public_key


def get_discovery_metadata() -> OIDCDiscovery:
    """Build OpenID Connect Discovery metadata.

    This metadata is published at /.well-known/openid-configuration
    and allows OIDC clients to auto-discover endpoints and capabilities.

    Returns:
        OIDCDiscovery model with all required endpoints and capabilities.
    """
    issuer = settings.oidc_issuer.rstrip("/")

    return OIDCDiscovery(
        issuer=issuer,
        authorization_endpoint=f"{issuer}/oauth/authorize",
        token_endpoint=f"{issuer}/oauth/token",
        userinfo_endpoint=f"{issuer}/oauth/userinfo",
        jwks_uri=f"{issuer}/.well-known/jwks.json",
        response_types_supported=["code"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
        scopes_supported=["openid", "profile", "email"],
        grant_types_supported=["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported=[
            "client_secret_basic",
            "client_secret_post",
        ],
        code_challenge_methods_supported=["S256", "plain"],
    )


def get_jwks() -> JWKSResponse:
    """Build JWKS (JSON Web Key Set) response.

    This is published at /.well-known/jwks.json and allows clients
    to download the public key(s) for verifying JWT signatures.

    Returns:
        JWKSResponse containing the public key in JWKS format.
    """
    jwk = get_jwk_from_public_key()
    return JWKSResponse(keys=[jwk])
