#!/usr/bin/env python3
"""Test creating Settings the exact same way as our code."""

import sys
import os
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

# Clear any existing POSTGRES vars
for key in list(os.environ.keys()):
    if "POSTGRES" in key:
        del os.environ[key]

# Import everything like the real Settings does
import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

def _load_config_yaml() -> dict:
    config_path = Path(__file__).parent.parent / "config.yaml"
    if not config_path.exists():
        return {}
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config or {}
    except Exception:
        return {}

class TestSettingsSimple(BaseSettings):
    """No custom __init__, just like our class structure."""
    
    model_config = SettingsConfigDict(
        env_file=[".env.local", ".env"],
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "identity_and_access"
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"

# Try creating it
print("TestSettingsSimple (no custom __init__):")
test1 = TestSettingsSimple()
print(f"  postgres_port: {test1.postgres_port}")
print(f"  postgres_user: {test1.postgres_user}")

# Now with custom __init__ but no config.yaml logic
class TestSettingsWithInit(BaseSettings):
    """With custom __init__ like our class."""
    
    model_config = SettingsConfigDict(
        env_file=[".env.local", ".env"],
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "identity_and_access"
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    
    def __init__(self, **data: Any) -> None:
        print(f"  In __init__, data: {data}")
        print(f"  In __init__, POSTGRES_PORT in env: {'POSTGRES_PORT' in os.environ}")
        super().__init__(**data)

print("\nTestSettingsWithInit (with custom __init__, no yaml logic):")
test2 = TestSettingsWithInit()
print(f"  postgres_port: {test2.postgres_port}")
print(f"  postgres_user: {test2.postgres_user}")

# Now with config.yaml logic
class TestSettingsWithYaml(BaseSettings):
    """With custom __init__ and yaml logic like our real class."""
    
    model_config = SettingsConfigDict(
        env_file=[".env.local", ".env"],
        env_file_encoding="utf-8",
        extra="ignore",
    )
    
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "identity_and_access"
    postgres_user: str = "postgres"
    postgres_password: str = "postgres"
    
    def __init__(self, **data: Any) -> None:
        yaml_config = _load_config_yaml()
        print(f"  In __init__, data: {data}")
        print(f"  In __init__, yaml_config: {yaml_config}")
        
        # Apply yaml config if not already set (like our real code)
        if "postgres_port" not in data and not os.getenv("POSTGRES_PORT") and "DB_PORT" in yaml_config:
            data["postgres_port"] = yaml_config["DB_PORT"]
        
        if "postgres_user" not in data and not os.getenv("POSTGRES_USER") and "DB_USER" in yaml_config:
            data["postgres_user"] = yaml_config["DB_USER"]
        
        print(f"  After yaml override, data: {data}")
        super().__init__(**data)

print("\nTestSettingsWithYaml (with yaml override):")
test3 = TestSettingsWithYaml()
print(f"  postgres_port: {test3.postgres_port}")
print(f"  postgres_user: {test3.postgres_user}")
