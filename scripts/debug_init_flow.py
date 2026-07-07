#!/usr/bin/env python3
"""Debug to understand pydantic __init__ flow with env files."""

import sys
import os
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

# Clear any existing POSTGRES vars
for key in list(os.environ.keys()):
    if "POSTGRES" in key:
        del os.environ[key]

print("Initial state:")
print(f"  POSTGRES_PORT in env: {'POSTGRES_PORT' in os.environ}")
print()

# Create a test settings class with debugging
from pydantic_settings import BaseSettings, SettingsConfigDict

class DebugSettings(BaseSettings):
    postgres_port: int = 5432
    
    model_config = SettingsConfigDict(
        env_file=[".env.local", ".env"],
        extra="ignore",
    )
    
    def __init__(self, **data: Any) -> None:
        print("Inside __init__:")
        print(f"  data dict: {data}")
        print(f"  POSTGRES_PORT in os.environ: {'POSTGRES_PORT' in os.environ}")
        if "POSTGRES_PORT" in os.environ:
            print(f"  os.environ['POSTGRES_PORT']: {os.environ['POSTGRES_PORT']}")
        super().__init__(**data)

test = DebugSettings()
print(f"\nResult:")
print(f"  postgres_port: {test.postgres_port}")
print(f"  POSTGRES_PORT in env after: {'POSTGRES_PORT' in os.environ}")
