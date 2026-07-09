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
Notes:

- Browser session state lives in `session_id` cookie, backed by `user_sessions`.
- Credential lookup and Terms of Use acceptance update `users`.
- Client metadata comes from `oauth_clients`.
- Authorization codes live in `oauth_authorization_codes` and are single-use.
- Access and refresh tokens are stored in `oauth_tokens` for validation, rotation, and revocation.
- OAuth scope consent is stored in `user_consent`; separate platform Terms of Use consent updates `users.accepted_tou`.
*** End Patch