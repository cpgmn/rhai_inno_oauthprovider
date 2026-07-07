#!/usr/bin/env python3
"""Register a new user in database using app password hashing.

Usage examples:
    python scripts/register_user.py --username user@example.com --password secret123
    python scripts/register_user.py --username admin@example.com --password secret123 --roles analysis,bid_manager --registered --accepted-tou
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db.session import SessionLocal
from app.models.orm import User
from app.security.password import hash_password


def parse_roles(roles_arg: str | None) -> list[str]:
    """Parse comma-separated roles into list."""
    if not roles_arg:
        return []

    return [role.strip() for role in roles_arg.split(",") if role.strip()]


def register_user(
    username: str,
    password: str,
    roles: list[str],
    registered: bool,
    accepted_tou: bool,
) -> int:
    """Create user if username is not already present.

    Returns:
        Exit code (0 success, 1 error)
    """
    db = SessionLocal()

    try:
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"Error: user already exists: {username}")
            return 1

        user = User(
            username=username,
            password_hash=hash_password(password),
            roles=roles,
            registered=registered,
            accepted_tou=accepted_tou,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        print("User created successfully")
        print(f"  id: {user.id}")
        print(f"  username: {user.username}")
        print(f"  roles: {user.roles}")
        print(f"  registered: {user.registered}")
        print(f"  accepted_tou: {user.accepted_tou}")
        return 0

    except Exception as exc:
        db.rollback()
        print(f"Error creating user: {exc}")
        return 1
    finally:
        db.close()


def build_arg_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Register a new user in identity provider database"
    )
    parser.add_argument("--username", required=True, help="Username/email")
    parser.add_argument("--password", required=True, help="Plain text password")
    parser.add_argument(
        "--roles",
        default="",
        help="Comma-separated roles, e.g. analysis,bid_manager",
    )
    parser.add_argument(
        "--registered",
        action="store_true",
        help="Set registered=true",
    )
    parser.add_argument(
        "--accepted-tou",
        action="store_true",
        help="Set accepted_tou=true",
    )
    return parser


def main() -> int:
    """CLI entrypoint."""
    parser = build_arg_parser()
    args = parser.parse_args()

    roles = parse_roles(args.roles)

    return register_user(
        username=args.username,
        password=args.password,
        roles=roles,
        registered=args.registered,
        accepted_tou=args.accepted_tou,
    )


if __name__ == "__main__":
    raise SystemExit(main())
