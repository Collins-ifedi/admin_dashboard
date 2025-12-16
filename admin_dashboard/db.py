# db.py
# Production-grade database layer with automatic schema initialization

from contextlib import contextmanager
from typing import Iterator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session # Added Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import QueuePool
import logging # Added logging

from config import settings
from models import Base

# Configure logging (important for production environment)
logger = logging.getLogger(__name__)

# ---------- ENGINE ----------

engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    poolclass=QueuePool,
    # Production-tuned pool settings
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True, # Ensures connections are alive before being used
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    future=True,
)

# ---------- AUTO MIGRATION / INIT ----------

def init_db() -> None:
    """
    Automatically creates all tables if they do not exist.
    Acts as zero-touch migration for schema additions.
    Logs errors if connection/creation fails.
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialized successfully.")
    except SQLAlchemyError as e:
        logger.error(f"Database initialization failed: {e}")
        # Reraise as a fatal error for calling code (e.g., bot.py) to catch and stop
        raise RuntimeError(f"Database initialization failed: {e}") from e

# ---------- SESSION HANDLING ----------

def get_db_session() -> Session:
    """
    Returns a fresh, non-context-managed DB session.
    Used by Telegram handlers to acquire a session.
    The caller (e.g., a Telegram handler) is responsible for calling db.close()
    if the session is acquired outside of the get_db context manager.
    """
    return SessionLocal()


@contextmanager
def get_db() -> Iterator[Session]:
    """
    Provides a safe, transactional DB session context manager.
    Handles commit on success, rollback on exception, and ensures close().
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"DB transaction rolled back due to error: {e}")
        raise
    finally:
        db.close()

# ---------- HEALTH CHECK ----------

def db_healthcheck() -> bool:
    """
    Verifies DB connectivity by executing a simple query.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError as e:
        logger.error(f"DB health check failed: {e}")
        return False

# ---------- TEST SCRIPT ----------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        print("Initializing database...")
        init_db()
        print("DB initialized ✔")

        print("Running health check...")
        if db_healthcheck():
            print("DB connection OK ✔")
        else:
            print("DB connection FAILED ✖")
            exit(1)

    except RuntimeError as e:
        print(f"FATAL ERROR during DB setup: {e}")
        exit(1)