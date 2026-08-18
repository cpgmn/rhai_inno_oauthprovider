"""OAuth2 and OIDC protocol endpoints.

Implements authorization code flow, token exchange, and userinfo endpoints.
"""

import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.auth.session import get_session
from app.config.settings import settings
from app.db.session import get_db
from app.models.schemas import (
    AuthorizationRequest,
    ErrorResponse,
    TokenRequest,
    TokenResponse,
    UserInfoResponse,
)
from app.oidc.service import (
    create_authorization_code,
    create_tokens,
    get_authorization_code,
    get_oauth_client,
    get_oauth_token,
    mark_authorization_code_used,
    record_user_consent,
    refresh_access_token,
    build_userinfo_response,
)
from app.security.jwt import verify_jwt
from app.security.pkce import verify_pkce
from app.security.validation import (
    validate_redirect_uri,
    is_valid_redirect_uri,
    validate_scope,
    scope_to_string,
)
from app.auth.service import get_user_by_id

router = APIRouter(prefix="/oauth", tags=["oauth"])
logger = logging.getLogger(__name__)


@router.get("/authorize")
async def authorize_get(
    client_id: str = Query(...),
    response_type: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(...),
    state: str = Query(...),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query(None),
    nonce: str | None = Query(None),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Handle authorization endpoint GET request.

    This endpoint initiates the Authorization Code Flow.
    If the user is logged in, returns authorization code.
    Otherwise, redirects to login page.

    Required query parameters:
        client_id: OAuth2 client identifier (e.g., "test-public-client")
        response_type: Must be 'code' for authorization code flow
        redirect_uri: Where to send the user after authorization (must be registered for client)
        scope: Space-separated scopes requested (e.g., "openid profile email")
        state: Opaque value for CSRF protection (e.g., random string)

    Optional query parameters:
        code_challenge: PKCE code challenge (for public clients)
        code_challenge_method: PKCE method ('S256' or 'plain')
        nonce: OIDC nonce for ID token binding

    Example request:
        GET /oauth/authorize?client_id=test-public-client&response_type=code&redirect_uri=http://localhost:3000/callback&scope=openid+profile+email&state=random123

    Returns:
        - If user not logged in: Redirect to login page
        - If user logged in: Authorization code and redirect to redirect_uri
        - If parameters invalid: OAuth error response
    """
    logger.info(
        "[oauth.authorize] "
        f"client_id={client_id!r} "
        f"redirect_uri={redirect_uri!r} "
        f"state={state!r}"
    )

    # Validate response_type
    if response_type != "code":
        logger.warning(
            "[oauth.authorize] invalid response_type client_id=%r response_type=%r",
            client_id,
            response_type,
        )
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="unsupported_response_type",
                error_description="Only 'code' response type is supported",
            ).model_dump(),
        )

    # Validate and fetch OAuth client
    client = get_oauth_client(db, client_id)
    if not client:
        logger.warning("[oauth.authorize] unknown client_id=%r", client_id)
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_client",
                error_description="Client not found",
            ).model_dump(),
        )

    # Validate redirect_uri
    if not is_valid_redirect_uri(redirect_uri):
        logger.warning(
            "[oauth.authorize] invalid redirect_uri format client_id=%r redirect_uri=%r",
            client_id,
            redirect_uri,
        )
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_request",
                error_description="Invalid redirect_uri format",
            ).model_dump(),
        )

    if not validate_redirect_uri(redirect_uri, client.redirect_uris):
        logger.warning(
            "[oauth.authorize] redirect_uri not registered client_id=%r redirect_uri=%r",
            client_id,
            redirect_uri,
        )
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_redirect_uri",
                error_description="redirect_uri not registered for this client",
            ).model_dump(),
        )

    # Validate scopes
    is_valid, granted_scopes = validate_scope(scope, client.scopes)
    if not is_valid:
        logger.warning(
            "[oauth.authorize] invalid scope client_id=%r requested_scope=%r allowed_scopes=%r",
            client_id,
            scope,
            client.scopes,
        )
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_scope",
                error_description="Requested scopes not allowed for this client",
            ).model_dump(),
        )

    # Check if user is logged in via session cookie
    session_id = request.cookies.get("session_id")
    session = get_session(session_id) if session_id else None

    if not session:
        # User not logged in – redirect to login page
        original_url = settings.prefix + "/oauth/authorize?" + urlencode({
            "client_id": client_id,
            "response_type": response_type,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            **({"nonce": nonce} if nonce else {}),
            **({"code_challenge": code_challenge} if code_challenge else {}),
            **({"code_challenge_method": code_challenge_method} if code_challenge_method else {}),
        })
        login_url = settings.prefix + "/login?" + urlencode({"redirect_to": original_url})
        logger.info(
            "[oauth.authorize] no session redirect login client_id=%r login_url=%r",
            client_id,
            login_url,
        )
        return RedirectResponse(url=login_url, status_code=302)

    # User is logged in – auto-approve and generate authorization code
    user_id = session["user_id"]

    # Enforce onboarding before issuing an authorization code: users who are not
    # registered or have not accepted the Terms of Use must complete the consent
    # flow first (accept ToU, confirm AI training, reset password if needed).
    user = get_user_by_id(db, user_id)
    if user and (not user.registered or not user.accepted_tou):
        original_url = settings.prefix + "/oauth/authorize?" + urlencode({
            "client_id": client_id,
            "response_type": response_type,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            **({"nonce": nonce} if nonce else {}),
            **({"code_challenge": code_challenge} if code_challenge else {}),
            **({"code_challenge_method": code_challenge_method} if code_challenge_method else {}),
        })
        consent_url = settings.prefix + "/consent?" + urlencode({"next": original_url})
        logger.info(
            "[oauth.authorize] onboarding required redirect consent user_id=%r consent_url=%r",
            user_id,
            consent_url,
        )
        return RedirectResponse(
            url=consent_url,
            status_code=302,
        )

    # Record consent for the user
    record_user_consent(
        db,
        user_id,
        client_id,
        scope_to_string(granted_scopes),
    )

    # Create authorization code
    code = create_authorization_code(
        db,
        client_id,
        user_id,
        redirect_uri,
        scope_to_string(granted_scopes),
        code_challenge,
        code_challenge_method,
        nonce,
    )

    # Redirect to callback URI with authorization code and state
    callback_url = f"{redirect_uri}?code={code}&state={state}"
    logger.info(
        "[oauth.authorize] issue code redirect callback user_id=%r client_id=%r callback_url=%r",
        user_id,
        client_id,
        callback_url,
    )
    return RedirectResponse(url=callback_url, status_code=302)


@router.post("/token")
async def token_endpoint(
    request: Request,
    grant_type: str | None = Form(None),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    code_verifier: str | None = Form(None),
    refresh_token: str | None = Form(None),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Handle token endpoint POST request.

    Accepts form-encoded OAuth 2.0 token request per RFC 6749.
    Exchanges authorization codes for access/ID/refresh tokens.
    Also handles refresh token exchanges.
    """
    # Handle Basic Auth header (RFC 6749 Section 2.3.1)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Basic "):
        import base64
        try:
            encoded_credentials = auth_header[6:]
            decoded = base64.b64decode(encoded_credentials).decode("utf-8")
            if ":" in decoded:
                header_client_id, header_client_secret = decoded.split(":", 1)
                client_id = client_id or header_client_id
                client_secret = client_secret or header_client_secret
        except Exception as e:
            print(f"[oauth.token] Failed to decode Basic Auth header: {e}")

    # Reconstruct TokenRequest object from form fields and header
    request_body = TokenRequest(
        grant_type=grant_type or "",
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id or "",
        client_secret=client_secret,
        code_verifier=code_verifier,
        refresh_token=refresh_token,
    )

    if grant_type == "authorization_code":
        return _handle_authorization_code_grant(request_body, db)
    elif grant_type == "refresh_token":
        return _handle_refresh_token_grant(request_body, db)
    else:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="unsupported_grant_type",
                error_description=f"Grant type '{grant_type}' not supported",
            ).model_dump(),
        )


def _handle_authorization_code_grant(
    request: TokenRequest,
    db: Session,
) -> TokenResponse:
    """Handle authorization_code grant type.

    Args:
        request: Token request.
        db: Database session.

    Returns:
        TokenResponse.

    Raises:
        HTTPException: If validation fails.
    """
    # Validate required fields
    if not request.code or not request.redirect_uri or not request.client_id:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_request",
                error_description="Missing required parameters",
            ).model_dump(),
        )

    # Fetch and validate OAuth client
    client = get_oauth_client(db, request.client_id)
    if not client:
        raise HTTPException(
            status_code=401,
            detail=ErrorResponse(
                error="invalid_client",
                error_description="Client authentication failed",
            ).model_dump(),
        )

    # For confidential clients, validate client_secret
    if client.client_secret:
        if not request.client_secret or request.client_secret != client.client_secret:
            raise HTTPException(
                status_code=401,
                detail=ErrorResponse(
                    error="invalid_client",
                    error_description="Client authentication failed",
                ).model_dump(),
            )

    # Fetch authorization code
    auth_code = get_authorization_code(db, request.code)
    if not auth_code:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_grant",
                error_description="Authorization code not found or expired",
            ).model_dump(),
        )

    # Verify authorization code belongs to this client and redirect_uri
    if auth_code.client_id != client.id:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_grant",
                error_description="Code not issued to this client",
            ).model_dump(),
        )

    if auth_code.redirect_uri != request.redirect_uri:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_grant",
                error_description="redirect_uri does not match",
            ).model_dump(),
        )

    # Validate PKCE if present
    if auth_code.code_challenge:
        if not request.code_verifier:
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error="invalid_request",
                    error_description="code_verifier required",
                ).model_dump(),
            )

        if not verify_pkce(
            request.code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method or "plain",
        ):
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error="invalid_grant",
                    error_description="PKCE verification failed",
                ).model_dump(),
            )

    # Mark authorization code as used
    mark_authorization_code_used(db, auth_code)

    # Create tokens
    id_token, access_token, refresh_token = create_tokens(
        db,
        auth_code.user_id,
        request.client_id,
        auth_code.scope,
        auth_code.nonce,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=settings.access_token_expire_seconds,
        refresh_token=refresh_token,
        id_token=id_token,
        scope=auth_code.scope,
    )


def _handle_refresh_token_grant(
    request: TokenRequest,
    db: Session,
) -> TokenResponse:
    """Handle refresh_token grant type.

    Args:
        request: Token request.
        db: Database session.

    Returns:
        TokenResponse.

    Raises:
        HTTPException: If validation fails.
    """
    if not request.refresh_token or not request.client_id:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_request",
                error_description="Missing required parameters",
            ).model_dump(),
        )

    # Fetch and validate OAuth client
    client = get_oauth_client(db, request.client_id)
    if not client:
        raise HTTPException(
            status_code=401,
            detail=ErrorResponse(
                error="invalid_client",
                error_description="Client authentication failed",
            ).model_dump(),
        )

    # For confidential clients, validate client_secret
    if client.client_secret:
        if not request.client_secret or request.client_secret != client.client_secret:
            raise HTTPException(
                status_code=401,
                detail=ErrorResponse(
                    error="invalid_client",
                    error_description="Client authentication failed",
                ).model_dump(),
            )

    # Exchange refresh token for new tokens
    result = refresh_access_token(db, request.refresh_token)
    if not result:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                error="invalid_grant",
                error_description="Refresh token not found or expired",
            ).model_dump(),
        )

    new_access_token, new_refresh_token = result

    return TokenResponse(
        access_token=new_access_token,
        token_type="Bearer",
        expires_in=settings.access_token_expire_seconds,
        refresh_token=new_refresh_token,
        scope="openid profile email",
    )


@router.get("/userinfo", response_model=UserInfoResponse)
async def userinfo_endpoint(
    request: Request,
    db: Session = Depends(get_db),
) -> UserInfoResponse:
    """Handle UserInfo endpoint request.

    Returns claims about the authenticated user.

    Authorization header format: "Bearer <access_token>"

    Args:
        request: FastAPI Request object.
        db: Database session.

    Returns:
        UserInfoResponse with user claims.

    Raises:
        HTTPException: If token is missing or invalid.
    """
    # Extract access token from Authorization header
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail=ErrorResponse(
                error="invalid_token",
                error_description="Missing or invalid Authorization header",
            ).model_dump(),
        )

    access_token = auth_header[7:]

    # Validate token in database
    oauth_token = get_oauth_token(db, access_token)
    if not oauth_token:
        raise HTTPException(
            status_code=401,
            detail=ErrorResponse(
                error="invalid_token",
                error_description="Token not found or revoked",
            ).model_dump(),
        )

    # Fetch user
    user = get_user_by_id(db, oauth_token.user_id)
    if not user:
        raise HTTPException(
            status_code=401,
            detail=ErrorResponse(
                error="invalid_token",
                error_description="User not found",
            ).model_dump(),
        )

    # Return user info
    return build_userinfo_response(user)
