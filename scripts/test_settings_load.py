#!/usr/bin/env python3
"""Test that settings load .env.local correctly."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Force reload to pick up new config
import importlib
import app.config.settings
importlib.reload(app.config.settings)

from app.config.settings import Settings

# Create fresh settings instance
fresh_settings = Settings()

print("Settings loaded from .env.local and config.yaml:")
print(f"  Host: {fresh_settings.postgres_host}")
print(f"  Port: {fresh_settings.postgres_port}")
print(f"  DB: {fresh_settings.postgres_db}")
print(f"  User: {fresh_settings.postgres_user}")
print(f"\nExpected from .env.local:")
print(f"  Host: localhost")
print(f"  Port: 5050")
print(f"  DB: identity_and_access")
print(f"  User: postgres")

if fresh_settings.postgres_port == 5050:
    print("\n✓ SUCCESS: .env.local is being loaded correctly!")
else:
    print(f"\n✗ FAIL: Port is {fresh_settings.postgres_port}, expected 5050")
    print("  This means config.yaml is still taking precedence")
