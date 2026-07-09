# Authentication Flow

## Simplified Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Browser
    participant Frontend as RHAI_SE Front End
    participant AuthProvider as Auth Provider
    participant DB as Database

    Browser->>Frontend: Open protected page
    Frontend-->>Browser: Redirect to Auth Provider authorize endpoint
    Browser->>AuthProvider: GET /oauth/authorize
    AuthProvider->>DB: Read OAuth client + session
    DB-->>AuthProvider: Client valid / session missing
    AuthProvider-->>Browser: Redirect to login

    Browser->>AuthProvider: Submit login form
    AuthProvider->>DB: Read user + create session
    DB-->>AuthProvider: User valid + session stored
    AuthProvider-->>Browser: Set session cookie + redirect to authorize

    Browser->>AuthProvider: Retry /oauth/authorize with session cookie
    AuthProvider->>DB: Update session, store consent, create auth code
    DB-->>AuthProvider: Auth code stored
    AuthProvider-->>Browser: Redirect to Front End callback with code
    Browser->>Frontend: Return with authorization code

    Frontend->>AuthProvider: POST /oauth/token with code
    AuthProvider->>DB: Validate code, mark used, store tokens
    DB-->>AuthProvider: Tokens persisted
    AuthProvider-->>Frontend: Return access token, ID token, refresh token
```

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser
    participant Client as OAuth Client App
    participant IdP as RhAI Inno OAuth Provider
    participant Auth as Auth Service
    participant Session as Session Store
    participant OIDC as OIDC Service
    participant DB as PostgreSQL

    User->>Browser: Open client app and start sign-in
    Browser->>Client: Request protected page
    Client-->>Browser: Redirect to /oauth/authorize with client_id, redirect_uri, scope, state, PKCE
    Browser->>IdP: GET /oauth/authorize
    IdP->>OIDC: get_oauth_client(client_id)
    OIDC->>DB: SELECT oauth_clients row
    DB-->>OIDC: client config + allowed redirect URIs/scopes
    OIDC-->>IdP: client validated
    IdP->>Session: get_session(session_id cookie)
    Session->>DB: SELECT user_sessions row
    DB-->>Session: session row or none

    alt No valid provider session
        Session-->>IdP: No session
        IdP-->>Browser: 302 redirect to /login?redirect_to=/oauth/authorize...
        Browser->>IdP: GET /login
        IdP-->>Browser: HTML login form
        User->>Browser: Enter email + password
        Browser->>IdP: POST /login
        IdP->>Auth: authenticate_user(username, password)
        Auth->>DB: SELECT users WHERE username=email
        DB-->>Auth: user row + password_hash
        Auth->>Auth: verify_password(password, stored hash)

        alt Invalid credentials
            Auth-->>IdP: authentication failed
            IdP-->>Browser: 302 redirect back to /login?error=Invalid+credentials
        else Valid credentials
            Auth-->>IdP: authenticated user
            IdP->>Session: create_session(user.id)
            Session->>DB: INSERT INTO user_sessions
            DB-->>Session: session persisted
            Session-->>IdP: session_id
            IdP-->>Browser: Set session_id cookie + 302 redirect to original /oauth/authorize
            Browser->>IdP: GET /oauth/authorize with session cookie
            IdP->>Session: get_session(session_id)
            Session->>DB: SELECT user_sessions row
            DB-->>Session: active session
            Session->>DB: UPDATE user_sessions SET last_seen_at=NOW()
        end
    else Valid provider session
        Session-->>IdP: user_id from session
        Session->>DB: UPDATE user_sessions SET last_seen_at=NOW()
    end

    opt User must accept platform Terms of Use and AI training first
        Browser->>IdP: GET /consent?next=/oauth/authorize...
        IdP->>Session: get_session(session_id)
        Session->>DB: SELECT user_sessions row
        DB-->>Session: active session
        User->>Browser: Accept training + Terms of Use
        Browser->>IdP: POST /consent
        IdP->>Auth: accept_user_consent(user_id)
        Auth->>DB: UPDATE users SET registered=true, accepted_tou=true
        DB-->>Auth: user updated
        IdP-->>Browser: 302 redirect to original /oauth/authorize
    end

    IdP->>OIDC: record_user_consent(user_id, client_id, scope)
    OIDC->>DB: SELECT/UPSERT user_consent
    DB-->>OIDC: consent stored
    IdP->>OIDC: create_authorization_code(..., redirect_uri, scope, PKCE, nonce)
    OIDC->>DB: INSERT INTO oauth_authorization_codes
    DB-->>OIDC: authorization code persisted
    OIDC-->>IdP: authorization code
    IdP-->>Browser: 302 redirect to client redirect_uri?code=...&state=...
    Browser->>Client: Deliver authorization code + state

    Client->>IdP: POST /oauth/token with code, redirect_uri, client_id, code_verifier
    IdP->>OIDC: get_oauth_client(client_id)
    OIDC->>DB: SELECT oauth_clients row
    DB-->>OIDC: client row
    IdP->>OIDC: get_authorization_code(code)
    OIDC->>DB: SELECT oauth_authorization_codes row
    DB-->>OIDC: code row
    IdP->>OIDC: verify client, redirect_uri, expiry, used flag, PKCE
    IdP->>OIDC: mark_authorization_code_used(code)
    OIDC->>DB: UPDATE oauth_authorization_codes SET used=true
    DB-->>OIDC: code consumed
    IdP->>OIDC: create_tokens(user_id, client_id, scope, nonce)
    OIDC->>DB: SELECT users row
    DB-->>OIDC: user row
    OIDC->>DB: SELECT oauth_clients row
    DB-->>OIDC: client row
    OIDC->>OIDC: Sign ID token JWT + access token JWT + generate refresh token
    OIDC->>DB: INSERT INTO oauth_tokens
    DB-->>OIDC: tokens persisted
    OIDC-->>IdP: id_token + access_token + refresh_token
    IdP-->>Client: JSON token response

    opt Refresh token grant
        Client->>IdP: POST /oauth/token with grant_type=refresh_token
        IdP->>OIDC: refresh_access_token(refresh_token)
        OIDC->>DB: SELECT oauth_tokens row by refresh_token
        DB-->>OIDC: token row
        OIDC->>DB: SELECT oauth_clients row
        DB-->>OIDC: client row
        OIDC->>OIDC: Sign new access token JWT + generate new refresh token
        OIDC->>DB: UPDATE oauth_tokens with rotated tokens + new expiries
        DB-->>OIDC: rotated token row saved
        OIDC-->>IdP: new access_token + new refresh_token
        IdP-->>Client: JSON token response
    end
```

Notes:

- Browser session state lives in `session_id` cookie, backed by `user_sessions`.
- Credential lookup and Terms of Use acceptance update `users`.
- Client metadata comes from `oauth_clients`.
- Authorization codes live in `oauth_authorization_codes` and are single-use.
- Access and refresh tokens are stored in `oauth_tokens` for validation, rotation, and revocation.
- OAuth scope consent is stored in `user_consent`; separate platform Terms of Use consent updates `users.accepted_tou`.
*** End Patch