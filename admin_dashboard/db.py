# db.py
"""
Production-grade async database layer.
Handles connection creation, SSL contexts for cloud deployment (Render/Heroku),
and session management.

UPDATED: 
- Removed dependency on 'config.py'.
- Loads credentials directly from Environment Variables (Priority) or config.yaml.
"""

import logging
import ssl
import os
import yaml  # Requires PyYAML: pip install PyYAML
from typing import AsyncGenerator, Any
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# Configure logging
logger = logging.getLogger(__name__)

# ==============================================================================
# CONFIGURATION LOADING
# ==============================================================================

def load_config_value(key: str, default: Any = None) -> Any:
    """
    Retrieves configuration values with the following priority:
    1. Environment Variable (Production/Render)
    2. config.yaml file (Local Development)
    3. Default value
    """
    # 1. Check Environment Variable
    env_val = os.getenv(key)
    if env_val is not None:
        return env_val

    # 2. Check config.yaml
    config_path = "config.yaml"
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f) or {}
                # YAML keys might be case-sensitive, assuming config.yaml uses exact keys
                if key in config_data:
                    return config_data[key]
        except Exception as e:
            # Log warning but don't crash, allowing fallback to default
            logger.warning(f"Attempted to read '{key}' from config.yaml but failed: {e}")

    # 3. Return Default
    return default

# Load Database Settings
DATABASE_URL = load_config_value("DATABASE_URL")

# Safe parsing for Boolean and Integer settings
_db_echo_val = load_config_value("DB_ECHO", "False")
DB_ECHO = str(_db_echo_val).lower() in ("true", "1", "yes", "on")

DB_POOL_SIZE = int(load_config_value("DB_POOL_SIZE", 20))
DB_MAX_OVERFLOW = int(load_config_value("DB_MAX_OVERFLOW", 10))


# ==============================================================================
# DATABASE URL HANDLING
# ==============================================================================

if not DATABASE_URL:
    # Critical error if no DB URL is found in Env or YAML
    raise ValueError(
        "DATABASE_URL not found. Please set it in Environment Variables or config.yaml."
    )

# Render/Heroku provide URLs starting with 'postgres://', but SQLAlchemy requires 'postgresql://'
# For async, we specifically need 'postgresql+asyncpg://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# ==============================================================================
# SSL CONTEXT (CRITICAL FOR CLOUD DEPLOYMENT)
# ==============================================================================

connect_args = {}

# Check if we are using PostgreSQL (implies production/cloud deployment like Render)
if "postgresql" in DATABASE_URL:
    # Render requires SSL. asyncpg requires an SSLContext object, not just a boolean.
    # We create a context that uses encryption but skips certificate verification (common for managed DBs).
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        connect_args["ssl"] = ctx
        logger.info("SSL Context enabled for PostgreSQL connection.")
    except Exception as e:
        logger.warning(f"Failed to create SSL context: {e}. Attempting connection without SSL.")

# ==============================================================================
# ASYNC ENGINE & SESSION FACTORY
# ==============================================================================

engine = create_async_engine(
    DATABASE_URL,
    echo=DB_ECHO,
    pool_pre_ping=True,       # Vital for recovering from dropped connections in cloud environments
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    connect_args=connect_args # Pass the SSL context here
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,  # Important for async (avoids implicit IO on attribute access)
)


# ==============================================================================
# SESSION DEPENDENCIES
# ==============================================================================

async def get_db_session() -> AsyncSession:
    """
    Returns a fresh async DB session instance.
    Useful for manual session management if needed outside of a context manager.
    """
    return AsyncSessionLocal()


@asynccontextmanager
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provides a safe, transactional async DB session context manager.
    Handles commit on success, rollback on exception, and ensures close().
    
    Usage:
        async with get_db() as db:
            result = await db.execute(...)
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"DB transaction rolled back due to error: {e}")
            raise
        finally:
            await session.close()

# ==============================================================================
# HEALTH CHECK
# ==============================================================================

async def db_healthcheck() -> bool:
    """
    Verifies DB connectivity by executing a lightweight async query.
    Returns True if successful, False otherwise.
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError as e:
        logger.error(f"DB health check failed: {e}")
        return False