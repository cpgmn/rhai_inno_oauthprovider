#!/usr/bin/env python3
"""Generate RSA keypair for JWT signing.

This script generates a new 2048-bit RSA public/private key pair
for use with the Identity Provider.

Keys are saved to:
- private_key.pem
- public_key.pem

Usage:
    python scripts/generate_keys.py

These files should be loaded via environment variables:
    JWT_PRIVATE_KEY=$(cat private_key.pem)
    JWT_PUBLIC_KEY=$(cat public_key.pem)
"""

import sys
from pathlib import Path

# Add parent directory to path so we can import app module
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.security.jwt import generate_rsa_keypair


def main() -> None:
    """Generate and save RSA keypair."""
    print("Generating RSA keypair...")
    private_key, public_key = generate_rsa_keypair()

    # Get script directory
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent

    private_path = project_dir / "private_key.pem"
    public_path = project_dir / "public_key.pem"

    # Save private key
    private_path.write_text(private_key)
    print(f"✓ Private key saved to {private_path}")

    # Save public key
    public_path.write_text(public_key)
    print(f"✓ Public key saved to {public_path}")

    print("\nTo use these keys with the Identity Provider:")
    print(f"export JWT_PRIVATE_KEY=$(cat {private_path})")
    print(f"export JWT_PUBLIC_KEY=$(cat {public_path})")


if __name__ == "__main__":
    main()
