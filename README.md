# Identity Provider

OpenID Connect (OIDC) compatible Identity Provider with OAuth2 support.

## Features

- **OpenID Connect Discovery** – Auto-configuration for OIDC clients
- **JWKS Endpoint** – Public key distribution for JWT verification
- **Authorization Code Flow** – Standard OAuth2 flow with PKCE support
- **Refresh Tokens** – Long-lived refresh token support
- **ID Tokens** – OIDC ID tokens with user claims
- **UserInfo Endpoint** – Retrieve authenticated user information
- **Session Management** – Secure cookie-based sessions

## Project Structure

```
innovationcloud_authprovider/
├── app/
│   ├── api/              # Endpoint definitions
│   ├── auth/             # Authentication logic
│   ├── config/           # Configuration
│   ├── db/               # Database layer
│   ├── models/           # SQLAlchemy ORM & Pydantic schemas
│   ├── oidc/             # OIDC-specific functionality
│   ├── security/         # JWT, PKCE, password hashing
│   ├── main.py           # FastAPI app factory
│   └── templates/        # HTML templates
├── scripts/
│   └── generate_keys.py  # RSA key pair generation
├── tests/                # Pytest test suite
├── Dockerfile            # Container image
├── podman-compose.yml    # Podman Compose configuration
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## Setup

### Generate RSA Keys

Required for JWT signing. Generate once and reuse:

```bash
python scripts/generate_keys.py
```

Creates:
- `private_key.pem` – Private key (keep secret)
- `public_key.pem` – Public key (distributed via JWKS)

### Environment Variables

Copy `.env.example` to `.env` and populate:

```bash
cp .env.example .env
```

Key variables:
- `JWT_PRIVATE_KEY` – Private RSA key (PEM format)
- `JWT_PUBLIC_KEY` – Public RSA key (PEM format)
- `OIDC_ISSUER` – Issuer URL (must match clients' expectations)
- `POSTGRES_*` – Database credentials

### Database Setup

PostgreSQL with the following existing tables:
- `users` – User accounts
- `oauth_clients` – OAuth2 clients
- `oauth_authorization_codes` – Auth codes
- `oauth_tokens` – Tokens
- `user_consent` – Consent records

Create tables:

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    roles JSONB DEFAULT '[]',
    registered BOOLEAN DEFAULT FALSE,
    accepted_tou BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE oauth_clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR UNIQUE NOT NULL,
    client_secret VARCHAR,
    redirect_uris JSONB DEFAULT '[]',
    grant_types JSONB DEFAULT '[]',
    response_types JSONB DEFAULT '[]',
    scopes JSONB DEFAULT '[]'
);

CREATE TABLE oauth_authorization_codes (
    id SERIAL PRIMARY KEY,
    code VARCHAR UNIQUE NOT NULL,
    client_id VARCHAR NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    redirect_uri VARCHAR NOT NULL,
    scope VARCHAR NOT NULL,
    code_challenge VARCHAR,
    code_challenge_method VARCHAR,
    nonce VARCHAR,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP
);

CREATE TABLE oauth_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    client_id VARCHAR NOT NULL,
    access_token VARCHAR UNIQUE NOT NULL,
    refresh_token VARCHAR UNIQUE,
    token_type VARCHAR DEFAULT 'Bearer',
    scope VARCHAR NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP
);

CREATE TABLE user_consent (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    client_id VARCHAR NOT NULL,
    scope VARCHAR NOT NULL,
    granted_at TIMESTAMP
);
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Locally

```bash
export JWT_PRIVATE_KEY=$(cat private_key.pem)
export JWT_PUBLIC_KEY=$(cat public_key.pem)

uvicorn app.main:app --reload
```

Server runs at `http://localhost:8000`

OpenAPI docs: `http://localhost:8000/docs`

## Endpoints

### Discovery

- `GET /.well-known/openid-configuration` – OIDC metadata
- `GET /.well-known/jwks.json` – Public keys

### Authentication

- `GET /login` – Login form
- `POST /login` – Handle login

### OAuth2 / OIDC

- `GET /oauth/authorize` – Authorization endpoint
- `POST /oauth/token` – Token endpoint
- `GET /oauth/userinfo` – UserInfo endpoint

### Health

- `GET /health` – Health check

## Testing

Run test suite:

```bash
pytest
```

With coverage:

```bash
pytest --cov=app tests/
```

Tests include:
- Login flow
- Authorization code flow
- Token exchange
- PKCE validation
- UserInfo retrieval
- Refresh token flow
- Security validation

## Docker / Podman

Build and run with Podman Compose:

```bash
podman compose up
```

Services:
- **postgres** – PostgreSQL database (port 5432)
- **authprovider** – Identity Provider (port 8080)
- **authclient** – Test client (port 3000)

Access:
- Provider API: `http://localhost:8080`
- Provider Docs: `http://localhost:8080/docs`
- Test Client: `http://localhost:3000`

## Integration Testing

The `authclient` application provides a simple UI for manual testing:

1. Navigate to `http://localhost:3000`
2. Click "Login with OIDC"
3. You'll be redirected to the provider's login
4. After authentication, tokens are displayed on the client

## Security Considerations

- Passwords are hashed with bcrypt (work factor 12)
- Authorization codes expire after 5 minutes
- Access tokens expire after 1 hour
- Refresh tokens expire after 30 days
- All tokens are stored in the database for revocation
- PKCE is supported for public clients
- Session cookies are HTTP-only
- Redirect URIs are validated against registered list

## OIDC Claims

ID tokens include:

```json
{
  "sub": "123",                          // User ID
  "preferred_username": "user@example.com",
  "email": "user@example.com",
  "email_verified": true,
  "roles": ["analysis", "bid_manager"],
  "iss": "http://localhost:8080",
  "aud": "client-id",
  "exp": 1234567890,
  "iat": 1234564290,
  "auth_time": 1234564290
}
```

## Development

### Code Structure

Follows **Separation of Concerns**:

- `app/api/` – Only endpoint definitions (routing, validation)
- `app/services/` – Business logic (never called directly from endpoints)
- `app/db/` – Database access (queries, transactions)
- `app/oidc/` – OIDC-specific logic (claims, token generation)
- `app/auth/` – Authentication logic (user lookup, session management)
- `app/security/` – Cryptographic utilities (JWT, PKCE, password hashing)

### Adding Endpoints

1. Create handler in `app/api/`
2. Call service functions from `app/services/` or `app/oidc/`
3. Services interact with database via `app/db/`
4. Always use Pydantic models for request/response

### Running Locally for Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Generate keys
python scripts/generate_keys.py

# Run with reload


# Run tests
pytest --watch
```

## Deployment

For production deployment:

1. Generate new RSA keys
2. Use strong `SESSION_SECRET_KEY`
3. Set `OIDC_ISSUER` to public URL
4. Use external PostgreSQL (not local)
5. Enable HTTPS
6. Set appropriate token lifetimes
7. Configure CORS as needed
8. Use secrets management for environment variables

## License

MIT

## Support

For issues or questions, refer to tests for usage examples.
