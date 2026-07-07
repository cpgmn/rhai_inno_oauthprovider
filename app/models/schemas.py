"""Pydantic models for API requests and responses.

These are strongly-typed contracts for all inputs and outputs across the OIDC provider.
"""

from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


# ============================================================================
# Login / Authentication
# ============================================================================


class LoginRequest(BaseModel):
    """User login request.

    Attributes:
        username: Email address to authenticate.
        password: Password to verify.
    """

    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class AuthenticatedUser(BaseModel):
    """Authenticated user information.

    Attributes:
        user_id: Numeric user identifier.
        username: Email address (same as login username).
        roles: List of role strings assigned to the user.
    """

    user_id: int
    username: str
    roles: list[str]


# ============================================================================
# Authorization Request / Response
# ============================================================================


class AuthorizationRequest(BaseModel):
    """OAuth2 authorization endpoint request parameters.

    Attributes:
        client_id: The client requesting authorization.
        response_type: Always 'code' for authorization code flow.
        redirect_uri: Where to send the user after authorization.
        scope: Space-separated list of scopes requested.
        state: Opaque string for CSRF protection.
        code_challenge: PKCE code challenge.
        code_challenge_method: PKCE method: 'S256' or 'plain'.
        nonce: OIDC nonce for ID token binding.
    """

    client_id: str
    response_type: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    nonce: Optional[str] = None


class TokenRequest(BaseModel):
    """OAuth2 token endpoint request.

    Attributes:
        grant_type: 'authorization_code' or 'refresh_token'.
        code: Authorization code (required for 'authorization_code' grant).
        redirect_uri: Must match the authorization request.
        client_id: The client identifier.
        client_secret: Shared secret for confidential clients.
        code_verifier: PKCE code verifier (optional).
        refresh_token: Refresh token (required for 'refresh_token' grant).
    """

    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: str
    client_secret: Optional[str] = None
    code_verifier: Optional[str] = None
    refresh_token: Optional[str] = None


class TokenResponse(BaseModel):
    """OAuth2 token endpoint response.

    Attributes:
        access_token: JWT access token.
        token_type: Always 'Bearer'.
        expires_in: Lifetime of access token in seconds.
        refresh_token: Refresh token (if refresh token grant enabled).
        id_token: OIDC ID token (JWT).
        scope: Granted scopes.
    """

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    scope: str


# ============================================================================
# UserInfo Response
# ============================================================================


class UserInfoResponse(BaseModel):
    """OIDC UserInfo endpoint response.

    Attributes:
        sub: Subject (user ID as string).
        preferred_username: Email address.
        email: Email address.
        email_verified: Always true.
        roles: List of user roles.
    """

    sub: str
    preferred_username: str
    email: str
    email_verified: bool
    roles: list[str]


# ============================================================================
# OIDC Discovery and JWKS
# ============================================================================


class OIDCDiscovery(BaseModel):
    """OpenID Connect Discovery metadata.

    Exposes capabilities and endpoints for OIDC clients to auto-configure.

    Attributes:
        issuer: The issuer URL.
        authorization_endpoint: Authorization endpoint URL.
        token_endpoint: Token endpoint URL.
        userinfo_endpoint: UserInfo endpoint URL.
        jwks_uri: JWKS endpoint URL.
        response_types_supported: Supported response types.
        subject_types_supported: Supported subject types.
        id_token_signing_alg_values_supported: Supported JWT signing algorithms.
        scopes_supported: Supported scopes.
        grant_types_supported: Supported grant types.
        token_endpoint_auth_methods_supported: Supported authentication methods.
        code_challenge_methods_supported: Supported PKCE methods.
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    response_types_supported: list[str] = ["code"]
    subject_types_supported: list[str] = ["public"]
    id_token_signing_alg_values_supported: list[str] = ["RS256"]
    scopes_supported: list[str] = ["openid", "profile", "email"]
    grant_types_supported: list[str] = [
        "authorization_code",
        "refresh_token",
    ]
    token_endpoint_auth_methods_supported: list[str] = [
        "client_secret_basic",
        "client_secret_post",
    ]
    code_challenge_methods_supported: list[str] = ["S256", "plain"]


class JWKSResponse(BaseModel):
    """JWKS (JSON Web Key Set) response.

    Attributes:
        keys: List of JSON Web Keys.
    """

    keys: list[dict]


# ============================================================================
# JWT Claims
# ============================================================================


class IDTokenClaims(BaseModel):
    """OpenID Connect ID token claims.

    Attributes:
        iss: Issuer.
        sub: Subject (user ID as string).
        aud: Audience (client_id).
        exp: Expiry timestamp (added by sign_jwt).
        iat: Issued at timestamp (added by sign_jwt).
        nonce: Nonce from authorization request (optional).
        auth_time: User authentication timestamp.
        preferred_username: Email address.
        email: Email address.
        email_verified: Always true.
        roles: User roles.
    """

    iss: str
    sub: str
    aud: str
    exp: Optional[int] = None  # Added by sign_jwt
    iat: Optional[int] = None  # Added by sign_jwt
    nonce: Optional[str] = None
    auth_time: int
    preferred_username: str
    email: str
    email_verified: bool
    roles: list[str]


class AccessTokenClaims(BaseModel):
    """OAuth2 access token claims.

    Attributes:
        iss: Issuer.
        sub: Subject (user ID as string).
        aud: Audience (typically the API).
        exp: Expiry timestamp (added by sign_jwt).
        iat: Issued at timestamp (added by sign_jwt).
        scope: Space-separated scopes.
        client_id: The client that received the token.
    """

    iss: str
    sub: str
    aud: str
    exp: Optional[int] = None  # Added by sign_jwt
    iat: Optional[int] = None  # Added by sign_jwt
    scope: str
    client_id: str


# ============================================================================
# Errors
# ============================================================================


class ErrorResponse(BaseModel):
    """Standard OAuth2 error response.

    Attributes:
        error: Error code.
        error_description: Human-readable error description.
    """

    error: str
    error_description: str
