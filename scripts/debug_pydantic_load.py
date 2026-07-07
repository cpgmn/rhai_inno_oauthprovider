#!/usr/bin/env python3
"""Debug what pydantic is loading from .env.local."""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Check what's in .env.local
print("=" * 70)
print(".env.local contents:")
print("=" * 70)
with open(".env.local") as f:
    print(f.read())

# Check environment variables
print("\n" + "=" * 70)
print("Current shell environment (POSTGRES_*):")
print("=" * 70)
for key, val in os.environ.items():
    if "POSTGRES" in key:
        print(f"{key}={val}")
if not any("POSTGRES" in key for key in os.environ):
    print("(none)")

# Now import settings and check what pydantic loaded
print("\n" + "=" * 70)
print("Pydantic-settings loading:")
print("=" * 70)

# Patch __init__ to debug
from app.config import settings as settings_module

original_init = settings_module.Settings.__init__

def debug_init(self, **data):
    print(f"\nData dict passed to __init__:")
    for key in ["postgres_host", "postgres_port", "postgres_db", "postgres_user", "postgres_password"]:
        if key in data:
            print(f"  {key}: {data[key]}")
        else:
            print(f"  {key}: (not in data)")
    original_init(self, **data)

settings_module.Settings.__init__ = debug_init

# Now create a fresh instance
fresh = settings_module.Settings()
print(f"\nResult after __init__:")
print(f"  postgres_port: {fresh.postgres_port}")
print(f"  postgres_user: {fresh.postgres_user}")
