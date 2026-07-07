"""OIDC Discovery and JWKS endpoints."""

from fastapi import APIRouter

from app.models.schemas import OIDCDiscovery, JWKSResponse
from app.oidc.metadata import get_discovery_metadata, get_jwks

router = APIRouter(tags=["oidc"])


@router.get("/.well-known/openid-configuration", response_model=OIDCDiscovery)
async def discovery_endpoint() -> OIDCDiscovery:
    """OpenID Connect Discovery endpoint.

    Publishes server capabilities and endpoint URLs for OIDC clients
    to auto-discover and auto-configure.

    Returns:
        OIDCDiscovery metadata.
    """
    return get_discovery_metadata()


@router.get("/.well-known/jwks.json", response_model=JWKSResponse)
async def jwks_endpoint() -> JWKSResponse:
    """JSON Web Key Set (JWKS) endpoint.

    Publishes the server's public keys in standard JWKS format.
    Clients download this to verify JWT signatures.

    Returns:
        JWKSResponse with public keys.
    """
    return get_jwks()
