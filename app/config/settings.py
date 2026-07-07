"""Application settings loaded from config.yaml and environment variables.

Configuration is loaded from config.yaml if available, with environment
variables taking precedence for deployment flexibility.
"""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _load_config_yaml() -> dict[str, Any]:
    """Load configuration from config.yaml in project root.
    
    Returns:
        Dictionary of configuration values, empty if file not found.
    """
    config_path = Path(__file__).parent.parent.parent / "config.yaml"
    
    if not config_path.exists():
        return {}
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config or {}
    except Exception:
        # If YAML parsing fails, fall back to environment variables
        return {}


def _load_env_file() -> dict[str, str]:
    """Load environment variables from .env files.
    
    Returns:
        Dictionary of environment variables from .env.local or .env
    """
    from dotenv import dotenv_values
    
    env_local = Path(__file__).parent.parent.parent / ".env.local"
    env_file = Path(__file__).parent.parent.parent / ".env"
    
    # .env.local takes precedence over .env
    if env_local.exists():
        return dict(dotenv_values(env_local))
    elif env_file.exists():
        return dict(dotenv_values(env_file))
    
    return {}


class Settings(BaseSettings):
    """Identity Provider configuration.

    Loads configuration from config.yaml (if present) and environment variables.
    Environment variables take precedence over config.yaml values.

    Attributes:
        postgres_host: PostgreSQL host address (from config.yaml DB_HOST or env).
        postgres_port: PostgreSQL port (from config.yaml DB_PORT or env).
        postgres_db: PostgreSQL database name (from config.yaml IAM_DB_NAME or env).
        postgres_user: PostgreSQL username (from config.yaml DB_USER or env).
        postgres_password: PostgreSQL password (from config.yaml DB_PASSWORD or env).
        oidc_issuer: OIDC issuer URL. Must match exactly what clients expect.
        jwt_private_key: PEM-encoded RSA private key for signing JWTs.
            Newlines may be escaped as \\n in the environment variable.
        jwt_public_key: PEM-encoded RSA public key for verifying JWTs.
            Newlines may be escaped as \\n in the environment variable.
        jwt_key_id: Key ID (kid) used in JWKS and JWT headers.
        session_secret_key: Secret for signing session cookies. Change in production.
        access_token_expire_seconds: Access token lifetime in seconds.
        refresh_token_expire_seconds: Refresh token lifetime in seconds.
        auth_code_expire_seconds: Authorization code lifetime in seconds.
    """

    _project_root = Path(__file__).parent.parent.parent

    model_config = SettingsConfigDict(
        env_file=[_project_root / ".env.local", _project_root / ".env"],
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database - read from config.yaml or environment
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "identity_and_access"
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"

    # OIDC
    oidc_issuer: str = "http://localhost:8080"

    # JWT signing keys (PEM-encoded RSA key pair).
    # Use scripts/generate_keys.py to generate these for development.
    jwt_private_key: str = ""
    jwt_public_key: str = ""
    jwt_key_id: str = "key-1"

    # Session cookie signing secret
    session_secret_key: str = "change-this-secret-in-production"

    # Token lifetimes
    access_token_expire_seconds: int = 3600         # 1 hour
    refresh_token_expire_seconds: int = 2_592_000   # 30 days
    auth_code_expire_seconds: int = 300             # 5 minutes

    def __init__(self, **data: Any) -> None:
        """Initialize settings, loading from env files first.
        
        Note: Env file loading happens AFTER __init__, so we don't override
        values in __init__. Use model_validator(mode='after') instead.
        """
        # Load JWT keys from file paths if not set via environment or .env files
        yaml_config = _load_config_yaml()
        
        if not os.getenv("JWT_PRIVATE_KEY") and not data.get("jwt_private_key"):
            key_path = yaml_config.get("JWT_PRIVATE_KEY_FILE") or str(
                Path(__file__).parent.parent.parent / "private_key.pem"
            )
            pem_path = Path(key_path)
            if pem_path.exists():
                data.setdefault("jwt_private_key", pem_path.read_text())

        if not os.getenv("JWT_PUBLIC_KEY") and not data.get("jwt_public_key"):
            key_path = yaml_config.get("JWT_PUBLIC_KEY_FILE") or str(
                Path(__file__).parent.parent.parent / "public_key.pem"
            )
            pem_path = Path(key_path)
            if pem_path.exists():
                data.setdefault("jwt_public_key", pem_path.read_text())

        super().__init__(**data)

    @model_validator(mode="after")
    def apply_yaml_defaults(self) -> "Settings":
        """Apply yaml config as fallback for unset fields.
        
        This runs AFTER pydantic loads all fields (including from .env files),
        so yaml config only applies if the field was not set by env vars/files.
        
        Precedence (highest to lowest):
        1. Shell environment variables (os.getenv)
        2. .env files (.env.local, .env)
        3. config.yaml
        4. Field defaults
        """
        yaml_config = _load_config_yaml()
        env_file_vars = _load_env_file()
        
        # Only use yaml config if:
        # 1. The shell environment variable is NOT set
        # 2. The value is NOT in the .env file
        # Then use yaml (or keep default if yaml doesn't have it)
        
        # POSTGRES_HOST
        if (not os.getenv("POSTGRES_HOST") and 
            "POSTGRES_HOST" not in env_file_vars and
            "DB_HOST" in yaml_config):
            self.postgres_host = yaml_config["DB_HOST"]
        
        # POSTGRES_PORT
        if (not os.getenv("POSTGRES_PORT") and 
            "POSTGRES_PORT" not in env_file_vars and
            "DB_PORT" in yaml_config):
            self.postgres_port = yaml_config["DB_PORT"]
        
        # POSTGRES_DB
        if (not os.getenv("POSTGRES_DB") and 
            "POSTGRES_DB" not in env_file_vars and
            "IAM_DB_NAME" in yaml_config):
            self.postgres_db = yaml_config["IAM_DB_NAME"]
        
        # POSTGRES_USER
        if (not os.getenv("POSTGRES_USER") and 
            "POSTGRES_USER" not in env_file_vars and
            "DB_USER" in yaml_config):
            self.postgres_user = yaml_config["DB_USER"]
        
        # POSTGRES_PASSWORD
        if (not os.getenv("POSTGRES_PASSWORD") and 
            "POSTGRES_PASSWORD" not in env_file_vars and
            "DB_PASSWORD" in yaml_config):
            self.postgres_password = yaml_config["DB_PASSWORD"]
        
        return self

    @property
    def database_url(self) -> str:
        """Build synchronous PostgreSQL database URL for psycopg2."""
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


# Module-level singleton – loaded once at startup and shared across the app.
settings = Settings()
