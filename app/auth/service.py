"""User authentication service.

Handles user lookup and password verification.
"""

from sqlalchemy.orm import Session

from app.models.orm import User
from app.security.password import verify_password




def authenticate_user(db: Session, username: str, password: str) -> User | None:
    """Authenticate a user by username and password.

    Args:
        db: Database session.
        username: Email address.
        password: Plain-text password.

    Returns:
        User object if credentials are valid, None otherwise.
    """

    
    # Look up user by username (email)
    user = db.query(User).filter(User.username == username).first()

    if not user:
        return None

    # Verify password against stored hash
    if not verify_password(password, user.password_hash):
        return None

    return user


def get_user_by_id(db: Session, user_id: int) -> User | None:
    """Fetch a user by ID.

    Args:
        db: Database session.
        user_id: Numeric user ID.

    Returns:
        User object or None if not found.
    """

    return db.query(User).filter(User.id == user_id).first()


def register_user_request(db: Session, email: str) -> tuple[bool, str]:
    """Create a pending registration entry for the given email.

    The user is created with empty password hash and flags set to False.
    An admin must later approve and assign a password before the user can log in.

    Args:
        db: Database session.
        email: Corporate email address.

    Returns:
        (success, reason) where reason is 'created', 'already_exists', or 'error'.
    """
    email = email.strip().lower()
    existing = db.query(User).filter(User.username == email).first()
    if existing:
        return False, "already_exists"

    user = User(username=email, password_hash="")
    db.add(user)
    try:
        db.commit()
        return True, "created"
    except Exception:
        db.rollback()
        return False, "error"


def accept_user_consent(db: Session, user_id: int) -> bool:
    """Set registered=True and accepted_tou=True for a user (consent accepted).

    Args:
        db: Database session.
        user_id: Numeric user ID.

    Returns:
        True on success, False if user not found or DB error.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False
    user.registered = True
    user.accepted_tou = True
    try:
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
