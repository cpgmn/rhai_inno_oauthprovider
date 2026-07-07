#!/usr/bin/env python3
"""Check pydantic-settings configuration."""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Check if pydantic-settings can find the file
env_local_path = Path(".env.local").resolve()
print(f"Working directory: {os.getcwd()}")
print(f"Looking for: {env_local_path}")
print(f"File exists: {env_local_path.exists()}")

# Try to import and check the model config
from app.config.settings import Settings
print(f"\nSettings model_config:")
print(f"  env_file: {Settings.model_config.get('env_file')}")
print(f"  env_file_encoding: {Settings.model_config.get('env_file_encoding')}")

# Try to manually load .env.local to see if it works
print(f"\nManual env_file loading test:")
from dotenv import load_dotenv
load_result = load_dotenv(".env.local", override=True)
print(f"  load_dotenv result: {load_result}")
print(f"  POSTGRES_PORT after load_dotenv: {os.getenv('POSTGRES_PORT')}")

# Now try creating settings after manual load
from pydantic_settings import BaseSettings, SettingsConfigDict

class TestSettings(BaseSettings):
    postgres_port: int = 5432
    
    model_config = SettingsConfigDict(
        env_file=".env.local",
        extra="ignore",
    )

test = TestSettings()
print(f"\nTestSettings.postgres_port: {test.postgres_port}")
