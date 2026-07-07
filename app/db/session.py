"""Database session management using SQLAlchemy.

Provides a single engine and session factory for the entire application.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config.settings import settings
from app.models.orm import Base

# Create synchronous engine
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,  # Verify connections are alive before using
    echo=False,  # Set to True for SQL debugging
)

# Session factory
SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    expire_on_commit=False,
)


def get_db() -> Session:
    """Dependency for FastAPI endpoints to inject database sessions.

    Yields:
        A database session that will be closed automatically by FastAPI.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize the database schema.

    This function is called at application startup.
    It will create any tables that don't exist, but will not
    modify or drop existing tables.
    """
    Base.metadata.create_all(bind=engine)
